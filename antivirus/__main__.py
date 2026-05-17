"""
Unified launcher: starts the Flask dashboard in a background thread,
opens the browser, then runs the pystray tray app in the foreground.

  python -m antivirus
  python -m antivirus --watch <dir>      # also enables filesystem monitor
  python -m antivirus --no-browser       # skip the browser auto-open
  python -m antivirus --dashboard-only   # skip the tray (CI / headless)
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import traceback
import webbrowser

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(HERE, "src")
sys.path.insert(0, SRC_DIR)

# These imports must come after sys.path mutation.
import dashboard  # noqa: E402


def _start_dashboard_thread(host: str, port: int) -> threading.Thread:
    def _run():
        # Flask dev server -- fine for localhost-only.
        dashboard.run(host=host, port=port, debug=False)
    t = threading.Thread(target=_run, daemon=True, name="dashboard")
    t.start()
    return t


def _wait_until_listening(host: str, port: int, timeout: float = 5.0) -> bool:
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    ap = argparse.ArgumentParser(prog="python -m antivirus",
                                 description="Tray + dashboard launcher.")
    ap.add_argument("--watch", default=None,
                    help="if set, the tray's filesystem monitor watches this directory")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7331)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--dashboard-only", action="store_true",
                    help="skip the tray; useful for CI or headless smoke tests")
    args = ap.parse_args()

    url = f"http://{args.host}:{args.port}/"
    print(f"[antivirus] starting dashboard on {url}")
    _start_dashboard_thread(args.host, args.port)
    if not _wait_until_listening(args.host, args.port):
        print(f"[antivirus] WARNING: dashboard didn't come up in 5s", file=sys.stderr)

    if not args.no_browser:
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass

    watch_dir = args.watch or os.path.join(HERE, "data", "watched")
    os.makedirs(watch_dir, exist_ok=True)

    # If --watch was supplied, arm the realtime monitor before the tray
    # comes up. Without this the watcher sits idle until the user clicks
    # "Start Monitoring" in the tray menu.
    standalone_monitor = None
    if args.watch:
        try:
            from monitor import Monitor
            standalone_monitor = Monitor(watch_dir=watch_dir, verbose=True)
            standalone_monitor.start()
        except Exception:
            print("[antivirus] ERROR while constructing/starting Monitor:",
                  file=sys.stderr)
            traceback.print_exc()
            standalone_monitor = None

        # Surface a dead watcher thread loudly -- a daemon thread crashing
        # in threading.Thread() is otherwise silent.
        if standalone_monitor is not None:
            w = standalone_monitor.watcher
            alive = bool(w and w._thread and w._thread.is_alive())
            print(f"[antivirus] watcher thread alive={alive}  "
                  f"is_running={standalone_monitor.is_running}  "
                  f"watch_dir={watch_dir}")
            if not alive:
                print("[antivirus] ERROR: watcher thread is NOT alive after start()",
                      file=sys.stderr)

    if args.dashboard_only:
        print("[antivirus] --dashboard-only: not starting tray; Ctrl+C to exit")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("[antivirus] shutting down")
        finally:
            if standalone_monitor is not None:
                try:
                    standalone_monitor.stop()
                except Exception:
                    traceback.print_exc()
        return

    # Lazy-import the tray so the dashboard-only path doesn't need pystray
    # already initialized.
    import tray  # noqa: E402
    print(f"[antivirus] launching tray (watch_dir={watch_dir})")
    try:
        app = tray.TrayApp(watch_dir=watch_dir,
                           preloaded_monitor=standalone_monitor)
    except Exception:
        print("[antivirus] ERROR constructing TrayApp:", file=sys.stderr)
        traceback.print_exc()
        return
    app.run()


if __name__ == "__main__":
    main()
