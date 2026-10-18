"""Config file → topology chassis port population."""

from __future__ import annotations

from pathlib import Path

from pfsense_checker.checker import check_file
from pfsense_checker.topology_site import Device, apply_config_to_device


def test_apply_config_populates_pfsense_ports() -> None:
    sample = Path(__file__).resolve().parents[1] / "samples" / "sample_config.xml"
    result = check_file(sample)
    dev = Device(name="fw-lab", kind="pfsense")
    n = apply_config_to_device(dev, result)
    assert n >= 4
    assert dev.components
    assert any(c.name == "LAN" for c in dev.components)
    lan = next(c for c in dev.components if c.name == "LAN")
    assert lan.address == "192.168.1.1/24"
    assert "bridge0" in lan.media
    assert dev.software_version == "23.1"
