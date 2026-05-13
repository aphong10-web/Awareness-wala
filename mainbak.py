# better ui ver1
import subprocess
import sys
import shutil
from pathlib import Path

from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pyfiglet import figlet_format

from scanner import scan_networks

# === ADDED: import attack modules directly so we get return values back ===
from pmkid import run_pmkid_attack
from capture import run_capture
# === END ADDED ===


console = Console()

DEFAULT_INTERFACE = "wlan0"
MONITOR_INTERFACE = "wlan0mon"

PROJECT_ROOT = Path(__file__).resolve().parent


# ===================== UI FUNCTIONS START =====================

def show_banner():
    console.print(f"[bold green]{figlet_format('SCAN')}[/bold green]")
    console.print(
        Panel(
            "[bold cyan]Python Wi-Fi Scanner[/bold cyan]\n"
            "[white]Authorized lab network testing tool[/white]",
            border_style="green", width=60
        )
    )


def show_status_table(interface_status, active_interface):
    table = Table(title="Interface Status", show_header=True, header_style="bold cyan")
    table.add_column("Item", style="yellow")
    table.add_column("Value", style="white")
    table.add_row("Monitor Mode", interface_status)
    table.add_row("Active Interface", active_interface)
    console.print(table)


def ask_yes_no(question):
    answer = input(f"\n{question} (y/n): ").strip().lower()
    return answer in ["y", "yes"]

# ====================== UI FUNCTIONS END ======================


# ===================== INTERFACE CHECK FUNCTIONS START =====================

def get_iwconfig_output():
    result = subprocess.run(["iwconfig"], capture_output=True, text=True)
    return result.stdout + result.stderr


def find_monitor_interface(iwconfig_output):
    current_interface = None

    for line in iwconfig_output.splitlines():
        if line and not line.startswith(" "):
            current_interface = line.split()[0]

        if "Mode:Monitor" in line and current_interface:
            return current_interface

    return None


def interface_exists(iwconfig_output, interface_name):
    for line in iwconfig_output.splitlines():
        if line.startswith(interface_name + " "):
            return True
    return False

# ====================== INTERFACE CHECK FUNCTIONS END ======================


# ===================== TARGET SELECTION START =====================

def select_target(networks):
    while True:
        try:
            choice = int(input("\nSelect Target Number from the live scan list: ")) - 1

            if 0 <= choice < len(networks):
                return networks[choice]

            print("[red]Invalid target number. Try again.[/red]")

        except ValueError:
            print("[red]Please enter a valid number.[/red]")

# ====================== TARGET SELECTION END ======================


# === ADDED: check which attacks are available for the selected target ===
def get_available_attacks(target):
    """
    Looks at the target's encryption and returns a list of supported attack names.
    WPA / WPA2  -> both attacks available
    Anything else -> empty list
    """
    encryption = target.get("encryption", "").upper()

    if "WPA" in encryption and "WPA3" not in encryption:
        return [
            "WPA Handshake Capture",
            "PMKID Attack"
        ]

    return []
# === END ADDED ===


# === ADDED: print numbered attack menu and return user's choice ===
def choose_attack(attacks):
    """Prints the attack menu and returns the chosen attack name."""
    console.print(
        Panel("[bold cyan]Available Attacks[/bold cyan]", border_style="cyan", width=60)
    )

    for i, attack_name in enumerate(attacks, start=1):
        console.print(f"  [yellow]{i}.[/yellow] {attack_name}")

    while True:
        try:
            choice = int(input("\nChoose attack type: ")) - 1

            if 0 <= choice < len(attacks):
                return attacks[choice]

            print("[red]Invalid choice. Try again.[/red]")

        except ValueError:
            print("[red]Please enter a valid number.[/red]")
# === END ADDED ===


# === ADDED: after a failed attack, ask user to retry or exit ===
def offer_retry(remaining_attacks):
    """
    Called when an attack fails.
    Shows which attacks are still untried and asks the user what to do next.
    """
    console.print(
        Panel(
            "[red]Attack did not succeed.[/red]\n"
            "[yellow]Would you like to try another attack or exit?[/yellow]",
            border_style="red", width=60
        )
    )

    if not remaining_attacks:
        console.print("[red]No other attacks available for this target.[/red]")
        return None

    console.print("\n[cyan]Remaining options:[/cyan]")

    options = remaining_attacks + ["Exit"]

    for i, option in enumerate(options, start=1):
        color = "red" if option == "Exit" else "yellow"
        console.print(f"  [{color}]{i}.[/{color}] {option}")

    while True:
        try:
            choice = int(input("\nYour choice: ")) - 1

            if 0 <= choice < len(options):
                selected = options[choice]

                if selected == "Exit":
                    return None

                return selected

            print("[red]Invalid choice. Try again.[/red]")

        except ValueError:
            print("[red]Please enter a valid number.[/red]")
# === END ADDED ===


# === ADDED: run an attack by name and return True/False result ===
def launch_attack(attack_name, target, interface):
    """
    Runs the correct module for the chosen attack.
    Returns True if the attack succeeded, False if it failed.
    """
    if attack_name == "WPA Handshake Capture":
        return run_capture(
            target_bssid=target["bssid"],
            channel=target["channel"],
            interface=interface,
            target_name=target["ssid"]
        )

    elif attack_name == "PMKID Attack":
        return run_pmkid_attack(
            bssid=target["bssid"],
            channel=target["channel"],
            iface=interface,
            ssid=target["ssid"]
        )

    else:
        print(f"[red]Unknown attack: {attack_name}[/red]")
        return False
# === END ADDED ===


# === ADDED: cleanup saved scan/capture folders ===
def ask_cleanup_saved_folders():
    """
    At the end of the program, asks whether to keep generated folders.
    This does NOT delete wordlist/, because that folder may contain rockyou.txt.
    """
    folders_to_clean = [
        "scans",
        "captures",
        "pmkid_captures",
        "hashes"
    ]

    existing_folders = []

    for folder_name in folders_to_clean:
        folder_path = PROJECT_ROOT / folder_name

        if folder_path.exists() and folder_path.is_dir():
            existing_folders.append(folder_path)

    if not existing_folders:
        return

    console.print(
        Panel(
            "[bold cyan]Saved Output Folders[/bold cyan]\n\n"
            "The following generated folders were found:\n"
            + "\n".join(f"[yellow]- {folder.name}/[/yellow]" for folder in existing_folders)
            + "\n\n[white]wordlist/ will not be deleted.[/white]",
            border_style="cyan",
            width=60
        )
    )

    choice = input("\nDo you want to keep these saved folders? (y/n): ").strip().lower()

    if choice in ["y", "yes"]:
        print("[green]Saved folders kept.[/green]")
        return

    if choice in ["n", "no"]:
        for folder in existing_folders:
            try:
                shutil.rmtree(folder)
                print(f"[green]Deleted:[/green] {folder.name}/")
            except OSError as error:
                print(f"[red]Could not delete {folder.name}/:[/red] {error}")

        print("[green]Cleanup complete.[/green]")
        return

    print("[yellow]Invalid choice. Saved folders were kept for safety.[/yellow]")
# === END ADDED ===


# ===================== MAIN PROGRAM START =====================

def main():
    show_banner()

    print("\n[cyan]Checking wireless interface status...[/cyan]\n")

    iwconfig_output = get_iwconfig_output()

    console.print(
        Panel(
            iwconfig_output.strip(),
            title="iwconfig Result",
            border_style="cyan", width=60
        )
    )

    monitor_interface = find_monitor_interface(iwconfig_output)

    if monitor_interface:
        interface = monitor_interface
        show_status_table(
            interface_status="[green]Active[/green]",
            active_interface=interface
        )

    else:
        if not interface_exists(iwconfig_output, DEFAULT_INTERFACE):
            show_status_table(
                interface_status="[red]Adapter Not Found[/red]",
                active_interface=DEFAULT_INTERFACE
            )
            print(f"[red]{DEFAULT_INTERFACE} was not found.[/red]")
            print("[yellow]Please plug in your external Wi-Fi adapter and run the program again.[/yellow]")
            sys.exit()

        show_status_table(
            interface_status="[yellow]Off[/yellow]",
            active_interface=DEFAULT_INTERFACE
        )

        if ask_yes_no("Start monitor mode on wlan0"):
            print("\n[cyan]Starting monitor mode on wlan0...[/cyan]\n")

            try:
                subprocess.run(["sudo", "airmon-ng", "start", DEFAULT_INTERFACE], check=True)
                interface = MONITOR_INTERFACE
                print(f"[green]Monitor mode started on:[/green] {interface}")

            except subprocess.CalledProcessError:
                print(f"[red]Failed to start monitor mode on {DEFAULT_INTERFACE}.[/red]")
                print("[yellow]Check if the Wi-Fi adapter is plugged in and supports monitor mode.[/yellow]")
                sys.exit()

        else:
            print("[red]Monitor mode is required for scanning.[/red]")
            sys.exit()

    if not ask_yes_no("Start scanning for networks"):
        print("[yellow]Scanning cancelled.[/yellow]")
        sys.exit()

    networks = scan_networks(interface)

    if len(networks) == 0:
        print("[red]No networks detected.[/red]")
        sys.exit()

    target = select_target(networks)

    console.print(
        Panel(
            f"[bold green]Selected Target[/bold green]\n\n"
            f"[yellow]SSID:[/yellow]       {target['ssid']}\n"
            f"[yellow]BSSID:[/yellow]      {target['bssid']}\n"
            f"[yellow]Channel:[/yellow]    {target['channel']}\n"
            f"[yellow]Encryption:[/yellow] {target['encryption']}\n"
            f"[yellow]Power:[/yellow]      {target['power']}",
            border_style="green", width=60
        )
    )

    # === ADDED: attack menu + retry loop ===

    available_attacks = get_available_attacks(target)

    if not available_attacks:
        console.print(
            Panel(
                f"[red]No supported attacks available for this target.[/red]\n"
                f"[yellow]Encryption '[white]{target['encryption']}[/white]' is not supported yet.[/yellow]",
                border_style="red", width=60
            )
        )
        sys.exit()

    chosen_attack = choose_attack(available_attacks)

    remaining_attacks = [a for a in available_attacks if a != chosen_attack]

    while True:
        console.print(f"\n[cyan]Launching:[/cyan] [bold white]{chosen_attack}[/bold white]\n")

        success = launch_attack(chosen_attack, target, interface)

        if success:
            console.print(
                Panel("[bold green]Attack completed successfully.[/bold green]", border_style="green", width=60)
            )
            break

        next_attack = offer_retry(remaining_attacks)

        if next_attack is None:
            console.print("[yellow]Exiting. Goodbye.[/yellow]")
            sys.exit()

        remaining_attacks = [a for a in remaining_attacks if a != next_attack]
        chosen_attack = next_attack

    # === END ADDED ===


# === ADDED: always ask cleanup question when program ends ===
if __name__ == "__main__":
    try:
        main()
    finally:
        ask_cleanup_saved_folders()

# ====================== MAIN PROGRAM END ======================
