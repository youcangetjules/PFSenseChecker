"""Well-known project paths (single saved topology slots, etc.)."""

from __future__ import annotations

from pathlib import Path

# Package lives in <root>/pfsense_checker/ — project root is one level up.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Live topology: shared with Login to Routers (one slot).
SAVED_TOPOLOGY_PATH = PROJECT_ROOT / "data" / "topology.json"

# Experimental topology: sandbox, separate from live/login (one slot).
SAVED_EXPERIMENTAL_TOPOLOGY_PATH = PROJECT_ROOT / "data" / "topology_experimental.json"

# Default directory for application log files (FIFO ring file).
DEFAULT_LOG_DIR = PROJECT_ROOT / "data" / "logs"


def ensure_data_dir() -> Path:
    """Create the data directory if needed; return it."""
    data = PROJECT_ROOT / "data"
    data.mkdir(parents=True, exist_ok=True)
    return data
