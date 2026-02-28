import socket
import json
import struct
import time
import threading
from flask import Flask, jsonify, render_template_string

found_servers = []

# -----------------------------
#  VARINT HELPERS
# -----------------------------

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

# -----------------------------
#  PACKETS
# -----------------------------

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

# -----------------------------
#  WHITELIST DETECTION
# -----------------------------

def detect_whitelist(ip, port=25565, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # handshake for login state
        protocol_version = mc_varint(47)
        server_address = mc_string(ip)
        server_port = struct.pack(">H", port)
        next_state = mc_varint(2)  # LOGIN state
        data = protocol_version + server_address + server_port + next_state
        handshake = mc_varint(len(data) + 1) + b"\x00" + data
        sock.send(handshake)

        # send fake login start
        sock.send(build_login_start())

        # read disconnect reason
        mc_varint_from_socket(sock)  # length
        mc_varint_from_socket(sock)  # packet id
        msg_len = mc_varint_from_socket(sock)
        msg = sock.recv(msg_len).decode("utf-8").lower()

        sock.close()

        if "whitelist" in msg or "not whitelisted" in msg:
            return True
        return False

    except:
        return False

# -----------------------------
#  STATUS PING
# -----------------------------

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

# -----------------------------
#  LOAD MASSCAN RESULTS
# -----------------------------

def load_masscan_results(file_path):
    ips = []
    try:
        with open(file_path) as f:
            for line in f:
                if line.startswith("open"):
                    ips.append(line.split()[3])
    except:
        pass
    return ips

# -----------------------------
#  SCANNER LOOP
# -----------------------------

def scanner_loop():
    print("Scanner running...")

    while True:
        ips = load_masscan_results("results.txt")

        for ip in ips:
            result = ping_server(ip)

            if result:
                version = result["version"]["name"]
                online = result["players"]["online"]
                max_players = result["players"]["max"]

                # Player names
                if "sample" in result["players"]:
                    names = [p["name"] for p in result["players"]["sample"]]
                    names_str = " , ".join(names)
                else:
                    names_str = ""

                # Whitelist detection
                wl = detect_whitelist(ip)

                found_servers.append({
                    "ip": ip,
                    "version": version,
                    "players": f"{online}/{max_players}",
                    "online": online,
                    "names": names_str,
                    "whitelist": wl
                })

                print(f"[{'WL' if wl else 'OK'}] {ip} | {version} | {online}/{max_players} | {names_str}")

        time.sleep(1)

# -----------------------------
#  CATPPUCCIN MOCHA UI
# -----------------------------

app = Flask(__name__)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Minecraft Scanner Dashboard</title>
    <style>
        body { background: #1e1e2e; color: #cdd6f4; font-family: Arial; padding: 20px; }
        h1 { color: #b4befe; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; background: #313244; border-radius: 8px; overflow: hidden; }
        th { background: #45475a; padding: 12px; text-align: left; color: #89b4fa; }
        td { padding: 12px; border-bottom: 1px solid #6c7086; }
        tr:hover { background: #45475a; }
        .wl { color: #f38ba8; font-weight: bold; margin-right: 6px; }
    </style>
    <script>
        async function loadData() {
            const res = await fetch("/servers");
            const data = await res.json();
            const table = document.getElementById("table-body");
            table.innerHTML = "";

            data.forEach(s => {
                const badge = s.whitelist ? "<span class='wl'>[WL]</span>" : "";
                table.innerHTML += `
                    <tr>
                        <td>${badge}${s.ip}</td>
                        <td>${s.version}</td>
                        <td>${s.names || s.players}</td>
                    </tr>
                `;
            });
        }

        setInterval(loadData, 3000);
        window.onload = loadData;
    </script>
</head>
<body>
    <h1>Minecraft Scanner Dashboard</h1>

    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Version</th>
                <th>Players</th>
            </tr>
        </thead>
        <tbody id="table-body"></tbody>
    </table>
</body>
</html>
"""

@app.get("/")
def home():
    return render_template_string(HTML_PAGE)

@app.get("/servers")
def get_servers():
    return jsonify(sorted(found_servers, key=lambda x: x["online"], reverse=True))

# -----------------------------
#  MAIN
# -----------------------------

if __name__ == "__main__":
    t = threading.Thread(target=scanner_loop)
    t.daemon = True
    t.start()
    app.run(host="0.0.0.0", port=5000)
