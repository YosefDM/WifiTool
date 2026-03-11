#!/usr/bin/env python3
"""Root entry point for WifiTool."""

import sys
import os

# Allow running as `python main.py` from the repo root
sys.path.insert(0, os.path.dirname(__file__))

from wifi_tool.ui.app import run

if __name__ == "__main__":
    run()
