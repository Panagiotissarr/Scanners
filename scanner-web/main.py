import discord
from discord.ext import commands, tasks
import asyncio
import subprocess
import json
from mcstatus import JavaServer

# --- CONFIGURATION ---
TOKEN = 'YOUR_BOT_TOKEN'
MASSCAN_PATH = r'C:\\Users\\sarris\\scanner\\Mas-scan.exe'
CHANNEL_ID = 1467160324477288632  # Replace with the ID of the channel you want messages in

# Define the IP range you want to scan.
# 0.0.0.0/0 scans the WHOLE internet (Not recommended for home WiFi).
# Try smaller ranges or specific subnets.
TARGET_RANGE = "0.0.0.0/0" 

# --- BOT SETUP ---
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Global flag to control scanning
is_scanning = False

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
    await ctx.send("🚀 **Masscan started!** Scanning for Minecraft servers 24/7...")
    
    # Start the background task
    bot.loop.create_task(run_scanner_loop(ctx.channel))

@bot.command()
async def stop(ctx):
    global is_scanning
    if not is_scanning:
        await ctx.send("Scanner isn't running right now.")
        return

    is_scanning = False
    await ctx.send("🛑 **Stopping scanner...** (It may take a moment to finish the current batch)")

async def run_scanner_loop(channel):
    global is_scanning
    
    while is_scanning:
        print("Starting a new scan batch...")
        
        # 1. Run Masscan
        # We output to JSON (-oJ) so Python can read it easily.
        # --rate 1000 is the packet rate. Adjust based on your internet speed.
        command = [
            MASSCAN_PATH,
            "-p25565",
            TARGET_RANGE,
            "--rate", "1000", 
            "-oJ", "results.json"
        ]

        # Run masscan in a thread so it doesn't freeze the bot
        process = await asyncio.to_thread(subprocess.run, command, capture_output=True, text=True)
        
        if not is_scanning:
            break

        # 2. Parse the results
        try:
            # Masscan sometimes outputs weird JSON structures, we read the file directly
            with open("results.json", "r") as f:
                data = json.load(f)
                
            for entry in data:
                if not is_scanning: 
                    break
                
                ip = entry['ip']
                # Masscan found the port, now let's get the MC details
                await check_mc_server(ip, channel)

        except (FileNotFoundError, json.JSONDecodeError):
            print("No results found or file error.")
        
        # Wait a bit before restarting the loop to be safe
        await asyncio.sleep(10)

async def check_mc_server(ip, channel):
    try:
        # Connect to the server to get details
        server = await asyncio.to_thread(JavaServer.lookup, ip)
        status = await asyncio.to_thread(server.status)

        # Format the description (MOTD) - sometimes it's complex JSON, strictly grabbing text here
        motd = status.description
        if isinstance(motd, dict):
            motd = motd.get('text', 'Unknown')

        # Send to Discord
        embed = discord.Embed(title="Minecraft Server Found!", color=0x00ff00)
        embed.add_field(name="Description (MOTD)", value=f"```{motd}```", inline=False)
        embed.add_field(name="Version", value=status.version.name, inline=True)
        embed.add_field(name="Server IP", value=f"`{ip}`", inline=True)
        embed.add_field(name="Players", value=f"{status.players.online}/{status.players.max}", inline=True)
        
        await channel.send(embed=embed)
        print(f"Reported server: {ip}")

    except Exception as e:
        # Often a server is open but not actually a Minecraft server, or it times out
        # We pass silently so we don't spam the console
        pass

bot.run(TOKEN)