import subprocess

from rich import print
from pyfiglet import figlet_format

from scanner import scan_networks

print(f"[bold green]{figlet_format('SCAN')}[/bold green]")

DEFAULT_INTERFACE = "wlan0"
MONITOR_INTERFACE = "wlan0mon"


# ===================== INTERFACE CHECK FUNCTIONS START =====================
# These functions help us read iwconfig and check if monitor mode is active.

def get_iwconfig_output():
    result = subprocess.run(
        ["iwconfig"],
        capture_output=True,
        text=True
    )
    return result.stdout + result.stderr


def find_monitor_interface(iwconfig_output):
    current_interface = None

    for line in iwconfig_output.splitlines():
        if line and not line.startswith(" "):
            current_interface = line.split()[0]

        if "Mode:Monitor" in line and current_interface:
            return current_interface

    return None

# ====================== INTERFACE CHECK FUNCTIONS END ======================


# ===================== MONITOR MODE CHECK START =====================
# This shows iwconfig result first.
# Then it checks if monitor mode is already active.
# If monitor mode is off, it asks whether to start it on wlan0.

print("\n[cyan]Checking wireless interface status...[/cyan]\n")

iwconfig_output = get_iwconfig_output()

print("[bold yellow]iwconfig result:[/bold yellow]\n")
print(iwconfig_output)

monitor_interface = find_monitor_interface(iwconfig_output)

if monitor_interface:
    print(f"[green]Monitor mode is already active on:[/green] {monitor_interface}")
    interface = monitor_interface
else:
    print("[yellow]Monitor mode is currently off.[/yellow]")

    start_monitor = input("Start monitor mode on wlan0? (y/n): ").strip().lower()

    if start_monitor in ["y", "yes"]:
        print("\n[cyan]Starting monitor mode on wlan0...[/cyan]\n")

        subprocess.run(
            ["sudo", "airmon-ng", "start", DEFAULT_INTERFACE],
            check=True
        )

        interface = MONITOR_INTERFACE
    else:
        print("[red]Monitor mode is required for scanning.[/red]")
        exit()

# ====================== MONITOR MODE CHECK END ======================


# ===================== SCAN CONFIRMATION START =====================
# This asks only after iwconfig and monitor status are shown.

start_scan = input("\nStart scanning for networks? (y/n): ").strip().lower()

if start_scan not in ["y", "yes"]:
    print("[yellow]Scanning cancelled.[/yellow]")
    exit()

# ====================== SCAN CONFIRMATION END ======================


# ===================== NETWORK SCAN START =====================
# scanner.py shows the live network list.
# After you press ENTER there, this returns the networks list to main.py.

networks = scan_networks(interface)

if len(networks) == 0:
    print("[red]No networks detected.[/red]")
    exit()

# ====================== NETWORK SCAN END ======================


# ===================== TARGET SELECTION START =====================
# Use the target number from the live scan list shown by scanner.py.

choice = int(input("\nSelect Target Number from the list above: ")) - 1

if choice < 0 or choice >= len(networks):
    print("[red]Invalid target number.[/red]")
    exit()

target = networks[choice]

print(f"\n[green]Selected:[/green] {target['ssid']}")

# ====================== TARGET SELECTION END ======================


# ===================== CAPTURE LAUNCH START =====================
# Sends target details automatically to capture.py:
# BSSID, channel, interface, and SSID.

subprocess.run([
    "python3",
    "capture.py",
    target["bssid"],
    target["channel"],
    interface,
    target["ssid"]
])

# ====================== CAPTURE LAUNCH END ======================
