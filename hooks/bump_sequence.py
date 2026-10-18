"""Bump versions.SEQUENCE by 1 on commit when the author left it unchanged."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ROOT / "versions.py"
_SEQ_RE = re.compile(r"^SEQUENCE\s*=\s*(\d+)\s*$", re.MULTILINE)


def read_sequence(text: str) -> int:
    match = _SEQ_RE.search(text)
    if match is None:
        raise ValueError("versions.py has no SEQUENCE = <integer> assignment")
    return int(match.group(1))


def decide_sequence(current: int, previous: int | None) -> int | None:
    """Return a new sequence to write, or None to leave the file alone.

    ``previous is None`` means this file is not in HEAD yet (introducing commit).
    An unchanged sequence becomes previous + 1. A sequence already set to
    previous + 1 is left alone. Any other jump is an error.
    """
    if previous is None:
        return None
    if current == previous:
        return previous + 1
    if current == previous + 1:
        return None
    raise ValueError(
        f"SEQUENCE is {current}; expected {previous} (hook will add 1) "
        f"or {previous + 1} (already bumped)"
    )


def _head_sequence() -> int | None:
    proc = subprocess.run(
        ["git", "show", "HEAD:versions.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        return None
    return read_sequence(proc.stdout)


def _write_sequence(text: str, sequence: int) -> str:
    updated, count = _SEQ_RE.subn(f"SEQUENCE = {sequence}", text, count=1)
    if count != 1:
        raise ValueError("failed to rewrite SEQUENCE")
    return updated


def main() -> int:
    text = VERSIONS.read_text(encoding="utf-8")
    current = read_sequence(text)
    try:
        nxt = decide_sequence(current, _head_sequence())
    except ValueError as exc:
        print(f"bump_sequence: {exc}", file=sys.stderr)
        return 1
    if nxt is None:
        return 0
    VERSIONS.write_text(_write_sequence(text, nxt), encoding="utf-8", newline="\n")
    subprocess.run(
        ["git", "add", "--", "versions.py"],
        cwd=ROOT,
        check=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
