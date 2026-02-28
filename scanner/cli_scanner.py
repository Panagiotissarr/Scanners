import os
import json
import subprocess
import asyncio
import re
import datetime
import socket
import struct
import time
import sys
import threading
import collections

# --- Configuration ---
# You NEED to update these for masscan to work correctly.
# See GEMINI.md for more details on how to find these.
ADAPTER_IP = "192.168.1.100"  # Replace with your machine's IP
ROUTER_MAC = "74-24-9f-a6-b4-ad"  # Replace with your router's MAC
MASSCAN_PATH = os.path.join(os.getcwd(), "scanner\Mas-scan.exe") # Assumes Mas-scan.exe is in the current directory

# --- Minecraft Protocol Functions (from minecraft_scanner_bot.py) ---
def mc_varint(value):
    out = b""
    while True:
        temp = value & 0x7F
        value >>= 7
        if value != 0:
            temp |= 0x80
        out += struct.pack("B", temp)
        if value == 0:
            break
    return out

def mc_string(string):
    encoded = string.encode("utf-8")
    return mc_varint(len(encoded)) + encoded

def mc_varint_from_socket(sock):
    num = 0
    for i in range(5):
        byte = sock.recv(1)
        if not byte:
            return 0
        val = byte[0]
        num |= (val & 0x7F) << (7 * i)
        if not (val & 0x80):
            break
    return num

def build_handshake_packet(host, port):
    protocol_version = mc_varint(47)
    server_address = mc_string(host)
    server_port = struct.pack(">H", port)
    next_state = mc_varint(1)
    data = protocol_version + server_address + server_port + next_state
    return mc_varint(len(data) + 1) + b"\x00" + data

def build_status_request():
    return mc_varint(1) + b"\x00"

def build_login_start(name="ScannerBot"):
    name_bytes = name.encode("utf-8")
    packet_id = b"\x00"
    packet = packet_id + mc_varint(len(name_bytes)) + name_bytes
    return mc_varint(len(packet)) + packet

def detect_whitelist(ip, port=25565, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        protocol_version = mc_varint(47)
        server_address = mc_string(ip)
        server_port = struct.pack(">H", port)
        next_state = mc_varint(2)
        data = protocol_version + server_address + server_port + next_state
        handshake = mc_varint(len(data) + 1) + b"\x00" + data
        sock.send(handshake)

        sock.send(build_login_start())

        mc_varint_from_socket(sock)
        mc_varint_from_socket(sock)
        msg_len = mc_varint_from_socket(sock)
        msg = sock.recv(msg_len).decode("utf-8").lower()

        sock.close()

        if "whitelist" in msg or "not whitelisted" in msg:
            return True
        return False

    except Exception:
        return False

def ping_server(ip, port=25565, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        sock.send(build_handshake_packet(ip, port))
        sock.send(build_status_request())

        mc_varint_from_socket(sock)
        mc_varint_from_socket(sock)
        json_length = mc_varint_from_socket(sock)

        data = sock.recv(json_length).decode("utf-8")
        sock.close()

        return json.loads(data)

    except Exception:
        return None

def get_motd_text(motd_raw):
    if isinstance(motd_raw, dict):
        text = motd_raw.get('text', '')
        if 'extra' in motd_raw and isinstance(motd_raw['extra'], list):
            for part in motd_raw['extra']:
                if isinstance(part, dict) and 'text' in part:
                    text += part['text']
        return re.sub(r'§[0-9a-fk-or]', '', text).strip()
    elif isinstance(motd_raw, str):
        return re.sub(r'§[0-9a-fk-or]', '', motd_raw).strip()
    return str(motd_raw).strip()

# --- Asynchronous Wrappers (from minecraft_scanner_bot.py) ---
async def async_ping_server(ip, port):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, ping_server, ip, port)

async def async_detect_whitelist(ip, port):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, detect_whitelist, ip, port)

async def scan_server(ip, port):
    # print(f"[DEBUG] Calling scan_server for {ip}:{port}")
    data = await async_ping_server(ip, port)
    # print(f"[DEBUG] scan_server for {ip}:{port} returned: {data is not None}")
    return data

async def process_single_masscan_result(masscan_entry):
    if 'ip' in masscan_entry and 'ports' in masscan_entry and masscan_entry['ports']:
        ip = masscan_entry['ip']
        port = masscan_entry['ports'][0]['port']
        
        # print(f"[DEBUG] Processing masscan entry for {ip}:{port}")
        mc_data = await scan_server(ip, port)
        
        if mc_data:
            version = mc_data.get('version', {}).get('name', 'N/A')
            players_online = mc_data.get('players', {}).get('online', 'N/A')
            players_max = mc_data.get('players', {}).get('max', 'N/A')
            motd_raw = mc_data.get('description', 'N/A')
            motd = get_motd_text(motd_raw)

            print(
                f"\n--- Minecraft Server Found ---\n"
                f"IP: {ip}:{port}\n"
                f"Description: {motd}\n"
                f"Version: {version}\n"
                f"Players: {players_online}/{players_max}\n"
                f"------------------------------"
            )
        # else:
            # print(f"[DEBUG] No Minecraft data for {ip}:{port}.")

async def monitor_masscan_output_file(output_filepath, masscan_process, max_servers_limit=None, processed_count_proxy=None):
    last_position = 0

    if processed_count_proxy is None:
        processed_count_proxy = collections.Counter() # Use Counter for atomic updates in a threaded context

    # print(f"[DEBUG] Starting monitor for {output_filepath} with limit {max_servers_limit}")

    while masscan_process.returncode is None or True:
        if max_servers_limit is not None and processed_count_proxy['count'] >= max_servers_limit:
            # print(f"[DEBUG] Reached max_servers_limit ({max_servers_limit}). Terminating masscan process.")
            masscan_process.terminate()
            print(f"Scan stopped: {max_servers_limit} servers found for this limited scan.")
            break

        try:
            if not os.path.exists(output_filepath):
                # print(f"[DEBUG] File {output_filepath} not found yet. Waiting...")
                await asyncio.sleep(0.5)
                if masscan_process.returncode is not None:
                    # print(f"[DEBUG] Masscan finished and file {output_filepath} not found. Breaking monitor loop.")
                    break
                continue

            with open(output_filepath, 'r') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                current_file_size = f.tell()
                last_position = current_file_size

                if not new_lines and masscan_process.returncode is not None and current_file_size == last_position:
                    # print(f"[DEBUG] No new lines, masscan finished, and file fully read. Breaking monitor loop.")
                    break

                for line in new_lines:
                    # print(f"[DEBUG] Read line from masscan output: {line.strip()}")
                    try:
                        masscan_entry = json.loads(line.strip())
                        if 'ip' in masscan_entry and 'ports' in masscan_entry and masscan_entry['ports']:

                            if max_servers_limit is None or processed_count_proxy['count'] < max_servers_limit:
                                # print(f"[DEBUG] New IP {masscan_entry['ip']} found. Scheduling processing.")
                                asyncio.create_task(process_single_masscan_result(masscan_entry))
                                processed_count_proxy['count'] += 1
                            # else:
                                # print(f"[DEBUG] IP {masscan_entry['ip']} found but limit reached. Not processing.")
                        # else:
                            # print(f"[DEBUG] Line is not a valid masscan entry with ports: {masscan_entry}")
                    except json.JSONDecodeError:
                        # print(f"[DEBUG] Line is not valid JSON: {line.strip()}")
                        pass
                    except Exception as e:
                        print(f"[ERROR] Error parsing/processing masscan output line: {e} - Line: {line.strip()}")
            
            await asyncio.sleep(0.5)

        except asyncio.CancelledError:
            print("Masscan file monitor task cancelled.")
            break
        except Exception as e:
            print(f"[ERROR] Error in monitor_masscan_output_file: {e}")
            await asyncio.sleep(5)

    # print(f"[DEBUG] Monitor for {output_filepath} finished. Processed {processed_count_proxy['count']} servers.")
    return processed_count_proxy['count']

async def run_masscan_and_monitor(target, port, rate, max_servers_limit=None):
    current_time = datetime.datetime.now()
    date_str = current_time.strftime("%Y-%m-%d")
    time_str = current_time.strftime("%H-%M-%S")
    
    results_dir = os.path.join("results", date_str)
    os.makedirs(results_dir, exist_ok=True)

    output_json_filename = f"{time_str}.json"
    output_filepath = os.path.join(results_dir, output_json_filename)
    
    command = [
        MASSCAN_PATH,
        target,
        f"-p {port}",
        f"--rate {rate}",
        "--exclude 255.255.255.255",
        f"-oJ {output_filepath}",
        f"--adapter-ip {ADAPTER_IP}",
        f"--router-mac {ROUTER_MAC}"
    ]
    command_str = " ".join(command)

    print(f"Initiating masscan for `{target}` on port `{port}` with rate `{rate}`...")
    print(f"Command: {command_str}")

    masscan_process = None
    monitor_task = None
    processed_count_proxy = collections.Counter()
    
    try:
        masscan_process = await asyncio.create_subprocess_shell(
            command_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        monitor_task = asyncio.create_task(monitor_masscan_output_file(output_filepath, masscan_process, max_servers_limit, processed_count_proxy))

        masscan_stdout, masscan_stderr = await masscan_process.communicate()

        if masscan_stdout:
            print(f"Masscan stdout (full run):\n```\n{masscan_stdout.decode().strip()}\n```")
        if masscan_stderr:
            print(f"Masscan stderr (full run):\n```\n{masscan_stderr.decode().strip()}\n```")

        if masscan_process.returncode == 0:
            print(f"Masscan finished successfully! Full raw results saved to `{output_filepath}`. Total servers found: {processed_count_proxy['count']}.")
        else:
            print(f"Masscan exited with error code {masscan_process.returncode}.")

    except FileNotFoundError:
        print("Error: `Mas-scan.exe` not found. Please ensure it's in the same directory as the script or in your system's PATH.")
    except Exception as e:
        print(f"An unexpected error occurred while running masscan: \n{e}")
    finally:
        if monitor_task:
            await asyncio.sleep(3) # Give some time for remaining results to be processed
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
        
        # Clean up empty output file if no servers were found (optional)
        if processed_count_proxy['count'] == 0 and os.path.exists(output_filepath) and os.path.getsize(output_filepath) == 0:
            os.remove(output_filepath)

# --- CLI Implementation ---

class CLIScanner:
    def __init__(self):
        self.continuous_scan_task = None
        self.running = True

    def display_help(self):
        help_message = """
Available commands:
  scan <target> [port] [rate]    - Scans 10 servers using masscan.
                                   Example: scan 0.0.0.0/0 25565 1000
  247 <target> [port] [rate] [interval_minutes] - Starts a continuous scan.
                                   Example: 247 0.0.0.0/0 25565 1000 5
  stop                             - Stops any active 24/7 scan.
  help                             - Displays this help message.
  clear                            - Clears the terminal screen.
  exit                             - Closes the application.

Configuration (edit cli_scanner.py):
  ADAPTER_IP: Your machine's network adapter IP.
  ROUTER_MAC: Your router's MAC address.
  MASSCAN_PATH: Path to Mas-scan.exe (defaults to current directory).
"""
        print(help_message)

    async def start_continuous_scan(self, target, port, rate, interval_minutes):
        if self.continuous_scan_task and not self.continuous_scan_task.done():
            print("24/7 scan is already running.")
            return

        interval_seconds = interval_minutes * 60
        print(f"Starting continuous masscan (24/7) for `{target}` on port `{port}` with rate `{rate}`. Scans will repeat every {interval_minutes} minutes.")
        
        async def continuous_scanner_loop():
            while True:
                try:
                    print("\n--- Initiating a new scan cycle (24/7 mode) ---")
                    await run_masscan_and_monitor(target, port, rate, max_servers_limit=None)
                    print(f"--- Scan cycle complete. Waiting {interval_minutes} minutes before next scan ---")
                    await asyncio.sleep(interval_seconds)
                except asyncio.CancelledError:
                    print("24/7 continuous scan stopped.")
                    break
                except Exception as e:
                    print(f"[ERROR] Error in continuous scan cycle: {e}. Retrying in {interval_minutes} minutes.")
                    await asyncio.sleep(interval_seconds)

        self.continuous_scan_task = asyncio.create_task(continuous_scanner_loop())

    async def stop_continuous_scan(self):
        if self.continuous_scan_task and not self.continuous_scan_task.done():
            print("Attempting to stop continuous scan...")
            self.continuous_scan_task.cancel()
            try:
                await self.continuous_scan_task
            except asyncio.CancelledError:
                pass
            self.continuous_scan_task = None
            print("Continuous scan successfully stopped.")
        else:
            print("No continuous scan is currently running.")

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    async def run(self):
        self.display_help()
        while self.running:
            try:
                command_line = await asyncio.to_thread(input, "> ")
                parts = command_line.strip().split()
                if not parts:
                    continue

                command = parts[0].lower()
                args = parts[1:]

                if command == "help":
                    self.display_help()
                elif command == "exit":
                    self.running = False
                    await self.stop_continuous_scan()
                    print("Exiting application.")
                elif command == "clear":
                    self.clear_screen()
                elif command == "scan":
                    target = args[0] if len(args) > 0 else "0.0.0.0/0"
                    port = int(args[1]) if len(args) > 1 else 25565
                    rate = int(args[2]) if len(args) > 2 else 1000
                    await run_masscan_and_monitor(target, port, rate, max_servers_limit=10)
                elif command == "247":
                    target = args[0] if len(args) > 0 else "0.0.0.0/0"
                    port = int(args[1]) if len(args) > 1 else 25565
                    rate = int(args[2]) if len(args) > 2 else 1000
                    interval_minutes = int(args[3]) if len(args) > 3 else 5
                    await self.start_continuous_scan(target, port, rate, interval_minutes)
                elif command == "stop":
                    await self.stop_continuous_scan()
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
            except EOFError: # Handles Ctrl-Z on Windows or Ctrl-D on Unix
                self.running = False
                await self.stop_continuous_scan()
                print("\nExiting application.")
            except Exception as e:
                print(f"An error occurred: {e}")

if __name__ == "__main__":
    scanner = CLIScanner()
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt detected. Exiting application.")
        if scanner.continuous_scan_task:
            asyncio.run(scanner.stop_continuous_scan())
