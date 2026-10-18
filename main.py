#!/usr/bin/env python3
"""Launch the NetCheck GUI (console-friendly entry; Windows uses main.pyw)."""

from pfsense_checker.gui import run_app

if __name__ == "__main__":
    raise SystemExit(run_app())
