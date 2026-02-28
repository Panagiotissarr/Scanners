import discord
from discord.ext import commands
import asyncio
import subprocess
import json
import os
from datetime import datetime
from mcstatus import JavaServer

# --- CONFIGURATION ---
TOKEN = 'YOUR_BOT_TOKEN'
MASSCAN_PATH = r'YOUR_MASSCAN_PATH'
TARGET_RANGE = "0.0.0.0/0"  # Change this to your target IP range
RESULTS_FOLDER = "results"

# --- BOT SETUP ---
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Global flag
is_scanning = False

# Ensure results folder exists
if not os.path.exists(RESULTS_FOLDER):
    os.makedirs(RESULTS_FOLDER)

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user} (ID: {bot.user.id})')
    print('------')

@bot.command()
async def scan(ctx):
    global is_scanning
    if is_scanning:
        await ctx.send("Scanner is already running! 😎")
        return

    is_scanning = True
    await ctx.send("🚀 **Masscan started!** Saving to daily logs and sending info here...")
    bot.loop.create_task(run_scanner_loop(ctx.channel))

@bot.command()
async def stop(ctx):
    global is_scanning
    if not is_scanning:
        await ctx.send("Scanner isn't running right now.")
        return

    is_scanning = False
    await ctx.send("🛑 **Stopping scanner...**")

async def run_scanner_loop(channel):
    global is_scanning
    
    while is_scanning:
        print("Starting a new scan batch...")
        
        # Run Masscan and output to JSON
        # Note: --rate 1000 is aggressive. Lower it if your internet lags.
        command = [
            MASSCAN_PATH,
            "-p25565",
            TARGET_RANGE,
            "--rate", "1000",
            "-oJ", "results.json"
        ]

        # Run masscan in a separate thread
        await asyncio.to_thread(subprocess.run, command, capture_output=True, text=True)
        
        if not is_scanning:
            break

        # Parse the JSON results
        try:
            with open("results.json", "r") as f:
                data = json.load(f)
                
            for entry in data:
                if not is_scanning: 
                    break
                
                ip = entry.get('ip')
                if ip:
                    await check_mc_server(ip, channel)

        except (FileNotFoundError, json.JSONDecodeError):
            print("No results found in this batch.")
        
        # Wait 10 seconds before the next loop
        await asyncio.sleep(10)

async def check_mc_server(ip, channel):
    try:
        # 1. Get Server Details
        server = await asyncio.to_thread(JavaServer.lookup, ip)
        status = await asyncio.to_thread(server.status)

        # Clean up MOTD (Description)
        motd = status.description
        if isinstance(motd, dict):
            motd = motd.get('text', 'Unknown')
        motd = str(motd).strip()

        version = status.version.name
        players = f"{status.players.online}/{status.players.max}"

        # 2. Save to File (Daily Log)
        today = datetime.now().strftime('%Y-%m-%d')
        filename = f"{RESULTS_FOLDER}/{today}.txt"
        
        log_entry = (
            f"----------------------------------------\n"
            f"Time: {datetime.now().strftime('%H:%M:%S')}\n"
            f"IP: {ip}\n"
            f"Version: {version}\n"
            f"Players: {players}\n"
            f"MOTD: {motd}\n"
        )

        # Append to file
        with open(filename, "a", encoding="utf-8") as f:
            f.write(log_entry)

        # 3. Send to Discord
        embed = discord.Embed(title="Minecraft Server Found!", color=0x00ff00)
        embed.add_field(name="Description (MOTD)", value=f"```{motd}```", inline=False)
        embed.add_field(name="Version", value=version, inline=True)
        embed.add_field(name="Server IP", value=f"`{ip}`", inline=True)
        embed.add_field(name="Players", value=players, inline=True)
        
        await channel.send(embed=embed)
        print(f"✅ Saved & Sent: {ip}")

    except Exception as e:
        # Server was open port but not valid Minecraft, or timed out
        pass

bot.run(TOKEN)