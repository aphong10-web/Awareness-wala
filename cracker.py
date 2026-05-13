import subprocess
import sys
import os
import gzip
import shutil
import time
import re
import select

from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from pyfiglet import figlet_format

console = Console()

print(f"[bold green]{figlet_format('CRACK')}[/bold green]")

WORDLIST_FOLDER = "wordlist"
WORDLIST_TXT = os.path.join(WORDLIST_FOLDER, "rockyou.txt")
WORDLIST_GZ = os.path.join(WORDLIST_FOLDER, "rockyou.txt.gz")

MAX_CRACK_SECONDS = 180


def prepare_wordlist():
    if os.path.exists(WORDLIST_TXT):
        return WORDLIST_TXT

    if not os.path.exists(WORDLIST_GZ):
        print("[red]Wordlist not found.[/red]")
        print(f"[yellow]Expected:[/yellow] {WORDLIST_GZ}")
        return None

    print("[cyan]Extracting rockyou.txt.gz...[/cyan]")

    with gzip.open(WORDLIST_GZ, "rb") as compressed_file:
        with open(WORDLIST_TXT, "wb") as extracted_file:
            shutil.copyfileobj(compressed_file, extracted_file)

    print(f"[green]Wordlist ready:[/green] {WORDLIST_TXT}")
    return WORDLIST_TXT


def format_time(seconds):
    seconds = int(seconds)
    minutes = seconds // 60
    remaining_seconds = seconds % 60

    if minutes == 0:
        return f"{remaining_seconds} seconds"

    return f"{minutes} minutes {remaining_seconds} seconds"


def get_progress(output):
    matches = re.findall(r"(\d+)\s*/\s*(\d+)\s+keys tested", output)

    if not matches:
        return None, None, None

    tested, total = matches[-1]
    tested = int(tested)
    total = int(total)
    percent = (tested / total) * 100

    return tested, total, percent


def make_progress_panel(tested, total, percent, elapsed_time):
    table = Table.grid(padding=(0, 2))

    table.add_column(style="yellow")
    table.add_column(style="white")

    table.add_row("No. of keys tried:", f"{tested}/{total}")
    table.add_row("Wordlist checked:", f"{percent:.4f}%")
    table.add_row("Time elapsed:", format_time(elapsed_time))
    table.add_row("Max time:", f"{MAX_CRACK_SECONDS} seconds")

    # === FIXED: added width=60 so the panel doesn't stretch across the whole terminal ===
    return Panel(
        table,
        title="Cracking Progress",
        border_style="cyan",
        width=60
    )
    # === END FIXED ===


def show_crack_summary(output, elapsed_time):
    key_match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", output)
    tested, total, percent = get_progress(output)

    # === FIXED: summary now prints inside a compact panel instead of plain text ===
    # This keeps it consistent with the progress panel above it.
    summary_lines = []

    if key_match:
        password = key_match.group(1)
        summary_lines.append(f"[green]Password Found:[/green]  {password}")
    else:
        summary_lines.append("[red]Password Found:[/red]  No")

    summary_lines.append(f"[cyan]Time Taken:[/cyan]      {format_time(elapsed_time)}")

    if tested is not None:
        summary_lines.append(f"[cyan]Passwords Tried:[/cyan] {tested:,}")
        summary_lines.append(f"[cyan]Wordlist Size:[/cyan]   {total:,}")
        summary_lines.append(f"[cyan]Checked:[/cyan]         {percent:.4f}%")
    else:
        summary_lines.append("[yellow]Passwords Tried:[/yellow] Could not read from aircrack-ng output.")

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold yellow]Crack Summary[/bold yellow]",
            border_style="yellow",
            width=60
        )
    )
    # === END FIXED ===


def run_aircrack(command):
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    output = ""
    start_time = time.time()

    last_tested = 0
    last_total = "?"
    last_percent = 0
    last_live_update = 0

    with Live(
        make_progress_panel(last_tested, last_total, last_percent, 0),
        refresh_per_second=1,
        console=console
    ) as live:

        while True:
            elapsed_time = time.time() - start_time

            if elapsed_time >= MAX_CRACK_SECONDS:
                process.terminate()

                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

                return output, elapsed_time, True

            ready, _, _ = select.select([process.stdout], [], [], 0.2)

            if ready:
                chunk = process.stdout.read(1)

                if chunk:
                    output += chunk

            tested, total, percent = get_progress(output)

            if tested is not None:
                last_tested = tested
                last_total = total
                last_percent = percent

            if time.time() - last_live_update >= 1:
                live.update(
                    make_progress_panel(
                        last_tested,
                        last_total,
                        last_percent,
                        elapsed_time
                    )
                )
                last_live_update = time.time()

            if process.poll() is not None:
                remaining_output = process.stdout.read()

                if remaining_output:
                    output += remaining_output

                elapsed_time = time.time() - start_time
                return output, elapsed_time, False


if len(sys.argv) >= 4:
    cap_file = sys.argv[1]
    target_bssid = sys.argv[2]
    target_name = sys.argv[3]
else:
    cap_file = input("Capture file path: ").strip()
    target_bssid = input("Target BSSID: ").strip()
    target_name = input("Target Name: ").strip()


print(f"[green]Target Name:[/green] {target_name}")
print(f"[green]Target BSSID:[/green] {target_bssid}")
print(f"[green]Capture File:[/green] {cap_file}")

if not os.path.exists(cap_file):
    print("[red]Capture file not found.[/red]")
    exit()

wordlist = prepare_wordlist()

if wordlist is None:
    exit()


print(f"\n[cyan]Starting password cracking, max time {MAX_CRACK_SECONDS} seconds...[/cyan]\n")

aircrack_command = [
    "aircrack-ng",
    "-a2",
    "-b",
    target_bssid,
    "-w",
    wordlist,
    cap_file
]

output, elapsed_time, timed_out = run_aircrack(aircrack_command)

if timed_out:
    print("\n[red]Cracking stopped.[/red]")
    print("[yellow]No password found within 3 minutes.[/yellow]")
    print("[yellow]This password is probably too hard for this laptop or not in the wordlist.[/yellow]")
else:
    print("\n[green]Cracking process finished.[/green]")

show_crack_summary(output, elapsed_time)
