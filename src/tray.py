"""
System-tray launcher for the realtime monitor.

Menu:
    Start Monitoring     - arm the watcher on the configured directory
    Stop Monitoring      - tear it down
    Open Log             - open scan_log.jsonl in the default editor
    Exit                 - quit the tray app entirely

Icon swaps between two states:
    grey  - idle / stopped
    green - actively monitoring
The icon updates immediately on Start/Stop.

Run:
    python -m src.tray --watch <directory>
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading

from PIL import Image, ImageDraw

import pystray
from pystray import Menu, MenuItem

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from monitor import Monitor  # noqa: E402
from quarantine import DEFAULT_LOG_DIR, SCAN_LOG_NAME  # noqa: E402


# ---------- Icons -----------------------------------------------------------

def _make_icon(color_rgb: tuple[int, int, int]) -> Image.Image:
    """Render a 64x64 PNG icon: filled circle + small shield notch."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # outer circle
    d.ellipse((4, 4, 60, 60), fill=color_rgb, outline=(20, 20, 20, 255), width=2)
    # shield-shaped notch
    d.polygon([(32, 14), (50, 22), (50, 36), (32, 50), (14, 36), (14, 22)],
              fill=(255, 255, 255, 220), outline=(40, 40, 40, 255))
    return img


_ICON_IDLE = _make_icon((140, 140, 140))      # grey
_ICON_ACTIVE = _make_icon((60, 190, 80))      # green


# ---------- Tray app --------------------------------------------------------

class TrayApp:
    def __init__(self, watch_dir: str, log_dir: str = DEFAULT_LOG_DIR,
                 preloaded_monitor: Monitor | None = None):
        self.watch_dir = os.path.abspath(watch_dir)
        self.log_dir = os.path.abspath(log_dir)
        # If the launcher already armed a Monitor (because --watch was given),
        # adopt it so the tray reflects the running state from the start.
        self.monitor: Monitor | None = preloaded_monitor
        self._mon_lock = threading.Lock()

        running = self.monitor is not None and self.monitor.is_running
        self.icon = pystray.Icon(
            "AV",
            _ICON_ACTIVE if running else _ICON_IDLE,
            f"Vigil (watching {self.watch_dir})" if running else "Vigil (idle)",
            menu=Menu(
                MenuItem("Start Monitoring", self._on_start,
                         enabled=lambda _: not self._is_running(), default=True),
                MenuItem("Stop Monitoring", self._on_stop,
                         enabled=lambda _: self._is_running()),
                Menu.SEPARATOR,
                MenuItem("Open Log", self._on_open_log),
                Menu.SEPARATOR,
                MenuItem("Exit", self._on_exit),
            ),
        )

    # ---- state ---------------------------------------------------------

    def _is_running(self) -> bool:
        with self._mon_lock:
            return self.monitor is not None and self.monitor.is_running

    def _refresh_icon(self) -> None:
        if self._is_running():
            self.icon.icon = _ICON_ACTIVE
            self.icon.title = f"Vigil (watching {self.watch_dir})"
        else:
            self.icon.icon = _ICON_IDLE
            self.icon.title = "Vigil (idle)"
        # Force menu re-evaluation (enables/disables Start/Stop).
        self.icon.update_menu()

    # ---- menu callbacks ------------------------------------------------

    def _on_start(self, icon, item):
        with self._mon_lock:
            if self.monitor is not None and self.monitor.is_running:
                return
            self.monitor = Monitor(watch_dir=self.watch_dir, log_dir=self.log_dir, verbose=False)
            self.monitor.start()
        self._refresh_icon()
        self.icon.notify("Monitoring started", "Vigil")

    def _on_stop(self, icon, item):
        with self._mon_lock:
            if self.monitor is None or not self.monitor.is_running:
                return
            self.monitor.stop()
            self.monitor = None
        self._refresh_icon()
        self.icon.notify("Monitoring stopped", "Vigil")

    def _on_open_log(self, icon, item):
        log_path = os.path.join(self.log_dir, SCAN_LOG_NAME)
        if not os.path.isfile(log_path):
            os.makedirs(self.log_dir, exist_ok=True)
            open(log_path, "a").close()
        try:
            os.startfile(log_path)  # Windows-native shell open
        except Exception:
            subprocess.Popen(["notepad.exe", log_path])

    def _on_exit(self, icon, item):
        with self._mon_lock:
            if self.monitor is not None and self.monitor.is_running:
                self.monitor.stop()
        self.icon.stop()

    # ---- entry ---------------------------------------------------------

    def run(self):
        self.icon.run()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch", required=True, help="directory to monitor")
    ap.add_argument("--log-dir", default=DEFAULT_LOG_DIR)
    args = ap.parse_args()
    TrayApp(watch_dir=args.watch, log_dir=args.log_dir).run()


if __name__ == "__main__":
    main()
