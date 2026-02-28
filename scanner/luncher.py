import ctypes
import sys
import subprocess
import time

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        f'"{__file__}"',
        None,
        1
    )
    sys.exit(0)

# =========================
# ADMIN INSTANCE
# =========================

print("✅ Admin granted, starting bot...")

subprocess.Popen(
    [
        r"C:\Python314\python.exe",
        r"c:\Users\sarris\projects\scanner\bot.py"
    ],
    shell=False
)

# Keep launcher alive (optional but useful)
while True:
    time.sleep(60)
