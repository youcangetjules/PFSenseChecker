"""A built beacon bundle must import and run on its own (stdlib only)."""

from __future__ import annotations

import subprocess
import sys

from pfsense_checker import beacon_builder as bb


def test_bundle_files_import_and_run_a_cycle(tmp_path) -> None:
    for src, rel in bb._SOURCE_FILES:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(src.read_bytes())
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]);"
        "from pfsense_checker.monitor.beacon import run_cycle;"
        "r = run_cycle({'beacon_id': 'b', 'ping_targets': [], 'dhcp_targets': [],"
        " 'subnets': ['10.0.0.0/24']});"
        "print('ok', r.meta['accessible_subnets'][0]['cidr'])"
    )
    proc = subprocess.run([sys.executable, "-I", "-c", code, str(tmp_path)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok 10.0.0.0/24"
