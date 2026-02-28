# Minecraft Server Scanner Discord Bot

A Discord bot for discovering and monitoring Minecraft servers. This bot uses `masscan` to quickly find open servers across specified IP ranges and then pings them to retrieve detailed Minecraft server information.

## Features

- **Mass Scanning**: Utilizes `masscan` to scan large IP ranges for Minecraft servers with high speed.
- **Live Monitoring**: Discovered servers are reported to your Discord channel in real-time batches.
- **Detailed Server Info**: For each found server, the bot provides version, MOTD (Message of the Day), and player counts.
- **Continuous Scanning**: Run scans automatically at set intervals with the `!247` command.
- **Individual Server Check**: Use the `!check` command to get a detailed status report for a single server.
- **Data Archival**: All scan results, including detailed Minecraft data, are saved to local JSON files for later analysis.

## Prerequisites

- Python 3.8+
- A Discord Bot Token with the "Message Content Intent" enabled.
- `masscan` executable (`Mas-scan.exe` on Windows) placed in the same directory as the bot.

## Setup & Installation

1.  **Clone the project or download the files.**

2.  **Install Dependencies**: It is highly recommended to use a virtual environment.
    ```bash
    # Create and activate a virtual environment
    python -m venv .venv
    # Windows
    .venv\Scripts\activate
    # macOS/Linux
    source .venv/bin/activate

    # Install required Python packages
    pip install -r requirements.txt
    ```

3.  **Configure Bot Token**:
    Open `minecraft_scanner_bot.py` and replace `"YOUR_BOT_TOKEN_HERE"` with your actual Discord bot token.
    ```python
    TOKEN = os.getenv("DISCORD_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
    ```

4.  **Run the Bot**:
    You may need to run with administrator/root privileges for `masscan` to function correctly.
    ```bash
    python minecraft_scanner_bot.py
    ```

## Commands

-   `!check <ip> [port]`
    Checks a single Minecraft server and provides a detailed status embed.
    -   `ip`: The IP address of the server.
    -   `port` (optional): The server's port (defaults to `25565`).

-   `!scan <target> [port] [rate]`
    Initiates a scan for a maximum of 10 servers. Results are streamed to Discord.
    -   `target`: The IP range to scan (e.g., `192.168.1.0/24`, `0.0.0.0/0`).
    -   `port` (optional): The port to scan (defaults to `25565`).
    -   `rate` (optional): The packet rate for `masscan` (defaults to `1000`).

-   `!masscan <target> [port] [rate]`
    An alias for the `!scan` command.

-   `!247 <target> [port] [rate] [interval_minutes]`
    Starts a continuous, repeating scan with no server limit per cycle.
    -   `target`, `port`, `rate`: Same as `!scan`.
    -   `interval_minutes` (optional): Minutes between each scan cycle (defaults to `5`).

-   `!stop`
    Stops a continuous `!247` scan running in the current channel.
