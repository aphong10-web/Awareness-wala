import subprocess
import time
import csv
import os
import signal
import threading

from rich import print
from rich.console import Console
from rich.table import Table

console = Console()


def read_networks_from_csv(csv_file):
    networks = []

    if not os.path.exists(csv_file):
        return networks

    with open(csv_file, newline='', encoding='utf-8', errors='ignore') as file:
        reader = csv.reader(file)

        for row in reader:
            try:
                if len(row) == 0:
                    continue

                # Stop reading when airodump reaches client/station section
                if row[0].strip() == "Station MAC":
                    break

                if len(row) > 13 and row[0].strip() != "BSSID":
                    bssid = row[0].strip()
                    channel = row[3].strip()
                    encryption = row[5].strip()
                    power = row[8].strip()
                    ssid = row[13].strip()

                    if ssid != "":
                        networks.append({
                            "bssid": bssid,
                            "channel": channel,
                            "power": power,
                            "encryption": encryption,
                            "ssid": ssid
                        })

            except:
                pass

    # Remove duplicate networks by BSSID
    unique_networks = {}

    for network in networks:
        unique_networks[network["bssid"]] = network

    return list(unique_networks.values())


def show_live_table(networks):
    table = Table(title="Nearby Wi-Fi Networks")

    table.add_column("No.", style="cyan", justify="right")
    table.add_column("SSID", style="green")
    table.add_column("BSSID", style="yellow")
    table.add_column("CH", style="cyan")
    table.add_column("ENC", style="magenta")
    table.add_column("PWR", style="red")

    for i, net in enumerate(networks):
        table.add_row(
            str(i + 1),
            net["ssid"],
            net["bssid"],
            net["channel"],
            net["encryption"],
            net["power"]
        )

    console.clear()
    console.print(table)
    console.print("\n[bold cyan]Press ENTER to stop scanning...[/bold cyan]")


def scan_networks(interface):
    print("\n[cyan]Scanning for nearby Wi-Fi networks...[/cyan]")
    print("[yellow]Live results refresh every 1 second.[/yellow]\n")

    scan_folder = os.path.join("scans", f"scan_{int(time.time())}")

    os.makedirs(scan_folder, exist_ok=True)

    scan_name = os.path.join(scan_folder, "scan")
    csv_file = os.path.join(scan_folder, "scan-01.csv")
    error_file = os.path.join(scan_folder, "error.log")

    subprocess.run(["sudo", "-v"], check=True)

    error_output = open(error_file, "w")

    scan_process = subprocess.Popen(
        [
            "sudo",
            "-n",
            "airodump-ng",
            "--write",
            scan_name,
            "--output-format",
            "csv",
            interface
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=error_output,
        preexec_fn=os.setsid
    )

    stop_scanning = False

    # ===================== ADDED LIVE ENTER CHECK START =====================
    # This runs input() in the background.
    # The main loop can keep refreshing results every 1 second.

    def wait_for_enter():
        nonlocal stop_scanning
        input()
        stop_scanning = True

    input_thread = threading.Thread(target=wait_for_enter, daemon=True)
    input_thread.start()

    # ====================== ADDED LIVE ENTER CHECK END ======================

    latest_networks = []

    # ===================== ADDED LIVE SCAN DISPLAY START =====================
    # While the user has not pressed ENTER:
    # 1. Read the CSV file
    # 2. Show networks in a table
    # 3. Wait 1 second
    # 4. Repeat

    while not stop_scanning:
        latest_networks = read_networks_from_csv(csv_file)
        show_live_table(latest_networks)
        time.sleep(1)

    # ====================== ADDED LIVE SCAN DISPLAY END ======================

    print("\n[cyan]Stopping scan...[/cyan]\n")

    try:
        os.killpg(os.getpgid(scan_process.pid), signal.SIGINT)
        scan_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        scan_process.terminate()
        scan_process.wait()

    error_output.close()

    print("[green]Scan complete![/green]\n")

    # Read one final time after stopping scan
    latest_networks = read_networks_from_csv(csv_file)

    if len(latest_networks) == 0:
        print("[red]No networks detected.[/red]")
        print(f"[yellow]Scan files saved in:[/yellow] {scan_folder}")

    return latest_networks
