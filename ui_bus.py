from queue import Queue, Empty
from threading import Lock

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()
ui_events = Queue()
ui_lock = Lock()


def queue_message(message, style="cyan"):
    ui_events.put(("message", message, style))


def queue_panel(message, title=None, border_style="cyan", width=60):
    ui_events.put(("panel", message, title, border_style, width))


def flush_ui_events():
    while True:
        try:
            event = ui_events.get_nowait()
        except Empty:
            break

        with ui_lock:
            if event[0] == "message":
                _, message, style = event
                # markup=True so Rich tags inside message render correctly
                console.print(message, style=style if "[" not in message else None, markup=True)

            elif event[0] == "panel":
                _, message, title, border_style, width = event
                console.print(
                    Panel(
                        message,          # no Align.left() wrapper — causes width explosion
                        title=title,
                        border_style=border_style,
                        width=width,
                        expand=False,
                        padding=(0, 1),
                    )
                )


def safe_print(message, style="cyan"):
    with ui_lock:
        # If message already contains Rich markup tags, print as-is
        # Otherwise wrap in the style tag
        if "[" in message:
            console.print(message, markup=True)
        else:
            console.print(f"[{style}]{message}[/{style}]")


def safe_panel(message, title=None, border_style="cyan", width=60):
    with ui_lock:
        console.print(
            Panel(
                message,              # no Align.left() — it breaks width containment
                title=title,
                border_style=border_style,
                width=width,
                expand=False,
                padding=(0, 1),
            )
        )
