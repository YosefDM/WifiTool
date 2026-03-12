#!/usr/bin/env python3
"""Root entry point for WifiTool.

Usage
-----
  python main.py          # GUI mode (default)
  python main.py --cli    # terminal / ASCII mode
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))


def main() -> None:
    if "--cli" in sys.argv:
        from wifi_tool.ui.app import run
        run()
        return

    try:
        from wifi_tool.ui.gui import run
        run()
    except ImportError as exc:
        print(f"[!] GUI requires customtkinter:  pip install customtkinter")
        print(f"    Error: {exc}")
        print("[*] Falling back to terminal UI…\n")
        from wifi_tool.ui.app import run
        run()


if __name__ == "__main__":
    main()
