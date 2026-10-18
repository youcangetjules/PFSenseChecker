#!/usr/bin/env python3
"""Launch the NetCheck GUI without a console window (Windows .pyw)."""

from pfsense_checker.gui import run_app

if __name__ == "__main__":
    raise SystemExit(run_app())
