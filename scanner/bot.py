import discord
from discord.ext import commands
import os
import json
import subprocess
import asyncio
import re
import datetime
import socket
import struct
import time
import logging

TOKEN = os.getenv("DISCORD_BOT_TOKEN", ".")
if TOKEN == "YOUR_BOT_TOKEN":
    print("WARNING: DISCORD_BOT_TOKEN not set. Please set 'YOUR_BOT_TOKEN' in the script.")

intents = discord.Intents.default()
intents.message_content = True

# Configure logging for discord.py to suppress INFO messages
discord_logger = logging.getLogger('discord')
discord_logger.setLevel(logging.WARNING)

bot = commands.Bot(command_prefix='!', intents=intents)

_continuous_scan_tasks = {}

@bot.event
async def on_ready():
    print(f'{bot.user.name} has connected to Discord!')
    print(f'Bot ID: {bot.user.id}')
    print(f'Listening for commands with prefix: {bot.command_prefix}')

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

def ping_server(ip, port=25565, timeout=0.5):
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

async def async_ping_server(ip, port):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, ping_server, ip, port)

async def async_detect_whitelist(ip, port):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, detect_whitelist, ip, port)

async def scan_server(ip, port):
    
    print(f"[DEBUG] Calling scan_server for {ip}:{port}")
    data = await async_ping_server(ip, port)
    if data is not None:
        print(f"[DEBUG] scan_server for {ip}:{port} returned: {data is not None}")
    return data

async def process_server_and_queue(queue, masscan_entry, semaphore):
    
    async with semaphore:
        if 'ip' in masscan_entry and 'ports' in masscan_entry and masscan_entry['ports']:
            ip = masscan_entry['ip']
            port = masscan_entry['ports'][0]['port']
            
            print(f"[DEBUG] Pinging {ip}:{port}")
            mc_data = await scan_server(ip, port)
            
            if mc_data:
                version = mc_data.get('version', {}).get('name', 'N/A')
                players_online = mc_data.get('players', {}).get('online', 'N/A')
                players_max = mc_data.get('players', {}).get('max', 'N/A')
                motd_raw = mc_data.get('description', 'N/A')
                motd = get_motd_text(motd_raw)

                masscan_entry['minecraft_version'] = version
                masscan_entry['minecraft_motd'] = motd
                masscan_entry['minecraft_players_online'] = players_online
                masscan_entry['minecraft_players_max'] = players_max
                
                
                await queue.put(masscan_entry)
            else:
                
                masscan_entry['minecraft_version'] = None
                masscan_entry['minecraft_motd'] = None
                masscan_entry['minecraft_players_online'] = None
                masscan_entry['minecraft_players_max'] = None

async def send_batched_messages(ctx, queue, batch_size=5, batch_interval=0.5):
    
    while True:
        batch = []
        try:
            
            first_item = await queue.get()
            if first_item is None: 
                break
            batch.append(first_item)
            queue.task_done()

            
            while len(batch) < batch_size:
                try:
                    item = queue.get_nowait()
                    if item is None: 
                        
                        queue.put_nowait(None)
                        break
                    batch.append(item)
                    queue.task_done()
                except asyncio.QueueEmpty:
                    break 

            
            message_parts = []
            for entry in batch:
                part = (
                    f"IP: {entry.get('ip')}:{entry.get('ports', [{}])[0].get('port')}\n"
                    f"Version: {entry.get('minecraft_version')}\n"
                    f"Players: {entry.get('minecraft_players_online')}/{entry.get('minecraft_players_max')}\n"
                    f"MOTD: {entry.get('minecraft_motd')}"
                )
                message_parts.append(part)

            final_message = "```\n" + "\n--------------------\n".join(message_parts) + "\n```"

            
            if len(final_message) > 1990: 
                print("[DEBUG] Message too long, sending items individually.")
                for part in message_parts:
                     try:
                        await ctx.send(f"```\n{part}\n```")
                        await asyncio.sleep(0.25) 
                     except discord.HTTPException as e:
                        print(f"[ERROR] Discord HTTP Exception (individual): {e}")
            else:
                try:
                    await ctx.send(final_message)
                except discord.HTTPException as e:
                    print(f"[ERROR] Discord HTTP Exception (batch): {e}")

            
            await asyncio.sleep(batch_interval)

        except asyncio.CancelledError:
            break

async def monitor_and_process_masscan_stream(ctx, queue, masscan_process, max_servers_limit, processed_count_proxy, all_results, semaphore):
    
    while True:
        if masscan_process.stdout is None:
            break
        try:
            line_bytes = await masscan_process.stdout.readline()
        except (IOError, BrokenPipeError):
            print("[DEBUG] Masscan stdout pipe closed unexpectedly.")
            break

        if not line_bytes:
            break

        line = line_bytes.decode('utf-8', errors='ignore').strip()

        
        if not line or line == "[" or line == "]":
            continue

        
        if line.endswith(','):
            line = line[:-1]

        if line.startswith('{') and line.endswith('}'):
            try:
                masscan_entry = json.loads(line)
                all_results.append(masscan_entry)

                if 'ip' in masscan_entry and 'ports' in masscan_entry and masscan_entry['ports']:
                    
                    if max_servers_limit is not None and processed_count_proxy['count'] >= max_servers_limit:
                        print(f"[DEBUG] Reached max_servers_limit ({max_servers_limit}). Terminating masscan.")
                        await ctx.send(f"Scan limit of {max_servers_limit} servers reached. Stopping scan.")
                        try:
                            masscan_process.terminate()
                        except ProcessLookupError:
                            print("[DEBUG] Masscan process already terminated.")
                        return 
                    
                    print(f"[DEBUG] New IP {masscan_entry['ip']} found. Scheduling processing.")
                    asyncio.create_task(process_server_and_queue(queue, masscan_entry, semaphore))
                    processed_count_proxy['count'] += 1

            except json.JSONDecodeError:
                print(f"[DEBUG] Line is not valid JSON: {line}")
            except Exception as e:
                print(f"[ERROR] Error processing masscan stream line: {e} - Line: {line}")

async def read_stderr(stderr_stream, ctx):
    
    stderr_lines = []
    while True:
        try:
            line_bytes = await stderr_stream.readline()
        except (IOError, BrokenPipeError):
            print("[DEBUG] Masscan stderr pipe closed unexpectedly.")
            break
        if not line_bytes:
            break
        line = line_bytes.decode(errors='ignore').strip()
        stderr_lines.append(line)
        print(f"[MASSCAN_STDERR] {line}")
    
    full_stderr = "\n".join(stderr_lines)
    if full_stderr and "rate-limiting" not in full_stderr and "TCP-SYN" not in full_stderr:
        try:
            await ctx.send(f"Masscan stderr:\n```\n{full_stderr}\n```")
        except discord.HTTPException as e:
            print(f"[ERROR] Failed to send stderr to Discord: {e}")

async def _run_masscan_and_monitor(ctx, target, port, rate, max_servers_limit=None):
    
    current_time = datetime.datetime.now()
    date_str = current_time.strftime("%Y-%m-%d")
    time_str = current_time.strftime("%H-%M-%S")
    
    results_dir = os.path.join("results", date_str)
    os.makedirs(results_dir, exist_ok=True)

    output_json_filename = f"{time_str}.json"
    output_filepath = os.path.join(results_dir, output_json_filename)

    command = [
        "Mas-scan.exe",
        target,
        f"-p{port}",
        "--rate", str(rate),
        "--exclude", "255.255.255.255",
        "-oJ", "-" 
    ]

    await ctx.send(f"Initiating masscan for `{target}` on port `{port}` with rate `{rate}`...")
    print(f"Executing command: {' '.join(command)}")

    masscan_process = None
    processed_count_proxy = {'count': 0}
    all_results = []
    
    ping_semaphore = asyncio.Semaphore(200)
    results_queue = asyncio.Queue()
    batcher_task = asyncio.create_task(send_batched_messages(ctx, results_queue))
    
    try:
        masscan_process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout_task = asyncio.create_task(
            monitor_and_process_masscan_stream(ctx, results_queue, masscan_process, max_servers_limit, processed_count_proxy, all_results, ping_semaphore)
        )
        stderr_task = asyncio.create_task(
            read_stderr(masscan_process.stderr, ctx)
        )
        
        await asyncio.gather(stdout_task, stderr_task)
        
        
        await masscan_process.wait()

        
        if all_results:
            try:
                with open(output_filepath, 'w') as f:
                    json.dump(all_results, f, indent=4)
                print(f"Results saved to {output_filepath}")
            except Exception as e:
                print(f"[ERROR] Failed to save results to file: {e}")

        
        final_status_message = f"Scan complete! Full raw results saved to `{output_filepath}`. Total servers processed: {processed_count_proxy['count']}."
        if max_servers_limit is None and masscan_process.returncode == 0:
            await ctx.send(final_status_message)
        elif max_servers_limit is not None:
             # For limited scans, we send a message if it completes without being terminated by the limit watcher.
             # If it was terminated, a message was already sent from the monitor.
             if processed_count_proxy['count'] < max_servers_limit:
                 await ctx.send(final_status_message)
        elif masscan_process.returncode != 0 and masscan_process.returncode != -1: 
            # Catch other exit codes, but ignore -1 which can be from forceful termination.
            await ctx.send(f"Masscan exited with code {masscan_process.returncode}.")


    except FileNotFoundError:
        await ctx.send("Error: `Mas-scan.exe` not found. Please ensure it's in the bot's directory.")
    except Exception as e:
        await ctx.send(f"An unexpected error occurred while running masscan: ```\n{e}\n```")
        import traceback
        print(f"[ERROR] Masscan execution failed: {traceback.format_exc()}")
    finally:
        
        await results_queue.put(None)
        await batcher_task

        if masscan_process and masscan_process.returncode is None:
            try:
                masscan_process.kill()
                await masscan_process.wait()
            except ProcessLookupError:
                pass 
            except Exception as e:
                print(f"[ERROR] Failed to kill masscan process: {e}")

@bot.command(name='check')
async def check_command(ctx, ip: str, port: int = 25565):
    
    await ctx.send(f"Checking Minecraft server at `{ip}:{port}`...")

    data = await scan_server(ip, port)

    if not data:
        await ctx.send(f"No response from `{ip}:{port}`. It might be offline or not a Minecraft server.")
        return

    try:
        version = data.get('version', {}).get('name', 'N/A')
        players_online = data.get('players', {}).get('online', 'N/A')
        players_max = data.get('players', {}).get('max', 'N/A')
        motd_raw = data.get('description', 'N/A')
        motd = get_motd_text(motd_raw).replace("`", "")
        
        is_whitelisted = await async_detect_whitelist(ip, port)
        player_sample = data.get('players', {}).get('sample', [])
        
        embed = discord.Embed(
            title=f"Minecraft Server Status: {ip}:{port}",
            color=discord.Color.green()
        )
        embed.add_field(name="Version", value=version, inline=True)
        embed.add_field(name="Players", value=f"{players_online}/{players_max}", inline=True)
        embed.add_field(name="Whitelist", value="Yes" if is_whitelisted else "No", inline=True)
        embed.add_field(name="MOTD", value=f"```\n{motd}\n```", inline=False)

        if player_sample:
            player_names = [p['name'] for p in player_sample]
            if player_names:
                embed.add_field(name="Player Sample", value="```\n" + "\n".join(player_names) + "\n```", inline=False)

        if 'favicon' in data:
            embed.set_thumbnail(url=data['favicon'])

        await ctx.send(embed=embed)
    except (KeyError, TypeError) as e:
        await ctx.send(f"Server at `{ip}:{port}` responded with unexpected data or an error occurred: {e}")

@bot.command(name='masscan')
async def masscan_command(ctx, target: str = "0.0.0.0/0", port: int = 25565, rate: int = 1000):
    
    await _run_masscan_and_monitor(ctx, target, port, rate, max_servers_limit=10)

@bot.command(name='scan')
async def scan_command(ctx, target: str = "0.0.0.0/0", port: int = 25565, rate: int = 1000):
    
    await _run_masscan_and_monitor(ctx, target, port, rate, max_servers_limit=10)

@bot.command(name='247')
async def start_247_scan(ctx, target: str = "0.0.0.0/0", port: int = 25565, rate: int = 1000, interval_minutes: int = 5):
    

    channel_id = ctx.channel.id
    if channel_id in _continuous_scan_tasks and not _continuous_scan_tasks[channel_id].done():
        await ctx.send("Continuous scan is already running in this channel. Use `!stop` to stop it.")
        return

    interval_seconds = interval_minutes * 60
    await ctx.send(f"Starting continuous masscan (24/7) for `{target}` on port `{port}` with rate `{rate}`. Scans will repeat every {interval_minutes} minutes.")
    
    async def continuous_scanner():
        while True:
            try:
                await ctx.send(f"---"" Initiating a new scan cycle (24/7 mode) ---")

                await _run_masscan_and_monitor(ctx, target, port, rate, max_servers_limit=None) 
                await ctx.send(f"---"" Scan cycle complete. Waiting {interval_minutes} minutes before next scan ---")
                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                await ctx.send("Continuous scan stopped.")
                break
            except Exception as e:
                await ctx.send(f"Error in continuous scan cycle: {e}. Retrying in {interval_minutes} minutes.")

                import traceback
                print(f"[ERROR] Continuous scan error: {traceback.format_exc()}")
                await asyncio.sleep(interval_seconds)

    _continuous_scan_tasks[channel_id] = asyncio.create_task(continuous_scanner())

@bot.command(name='stop')
async def stop_247_scan(ctx):
    
    channel_id = ctx.channel.id
    if channel_id in _continuous_scan_tasks and not _continuous_scan_tasks[channel_id].done():
        await ctx.send("Attempting to stop continuous scan in this channel...")
        task = _continuous_scan_tasks.pop(channel_id)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await ctx.send("Continuous scan successfully stopped in this channel.")
    else:
        await ctx.send("No continuous scan is currently running in this channel.")

try:
    bot.run(TOKEN)
except KeyboardInterrupt:
    print("Goodbye!")