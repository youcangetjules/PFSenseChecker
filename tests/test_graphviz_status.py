"""Graphviz panel on Python Modules: installed / on PATH / test render."""

from __future__ import annotations

import subprocess

from pfsense_checker import graphviz_status as gs


def _fake_run(ok: bool = True):
    def run(cmd, **kwargs):  # noqa: ANN001, ANN003
        if "-V" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "", "dot - graphviz version 9.0.0\n")
        out = "<svg>...</svg>" if ok else ""
        return subprocess.CompletedProcess(cmd, 0 if ok else 1, out, "" if ok else "Error: syntax\n")
    return run


def test_not_installed(monkeypatch) -> None:
    monkeypatch.setattr(gs, "find_dot", lambda: ("", False))
    st = gs.check()
    assert not st.installed and st.summary == "Not installed" and "graphviz.org" in st.notes[0]


def test_installed_not_on_path(monkeypatch) -> None:
    monkeypatch.setattr(gs, "find_dot", lambda: (r"C:\Program Files\Graphviz\bin\dot.exe", False))
    monkeypatch.setattr(gs.winproc, "run", _fake_run())
    monkeypatch.setenv("PATH", r"C:\Windows")
    st = gs.check()
    assert st.works and st.version == "dot - graphviz version 9.0.0"
    assert st.summary == "Installed and working (not on PATH)"
    assert any("to PATH" in n for n in st.notes)


def test_render_failure(monkeypatch) -> None:
    monkeypatch.setattr(gs, "find_dot", lambda: ("/usr/bin/dot", True))
    monkeypatch.setattr(gs.winproc, "run", _fake_run(ok=False))
    st = gs.check()
    assert not st.works and st.error == "Error: syntax"
    assert st.summary == "Installed, but a test render failed"
