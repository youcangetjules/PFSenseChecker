"""Wireshark integration scaffold (Lua API bridge).

NetCheck will drive Wireshark analysis through its embedded Lua API.
Authoritative reference:

  https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html

This module is a framework only — no live Wireshark process is launched yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


WIRESHARK_LUA_API_DOCS = (
    "https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html"
)


class WiresharkCapability(str, Enum):
    """High-level Lua API areas we plan to use (see WSDG Ch. 13)."""

    UTILITY = "utility"  # get_version, preferences, dofile, …
    GUI = "gui"  # ProgDlg, TextWindow
    PROTOCOLS = "protocols"  # Proto, ProtoField, Dissector, Pref
    FIELDS = "fields"  # Field, FieldInfo
    PACKET_INFO = "packet_info"  # Pinfo, Address, NSTime, Conversation
    PACKET_DATA = "packet_data"  # Tvb, TvbRange, ByteArray
    TREE = "tree"  # TreeItem
    LISTENER = "listener"  # post-dissection Listener
    CAPTURE_IO = "capture_io"  # Dumper, FileHandler, FrameInfo
    WTAP = "wtap"  # capture file type helpers


@dataclass(frozen=True)
class LuaModuleNote:
    """One documented Lua API module / chapter section."""

    key: WiresharkCapability
    title: str
    wsdg_anchor: str
    summary: str


# Map to WSDG Chapter 13 sections — keep in sync with the public manual.
LUA_API_MODULES: tuple[LuaModuleNote, ...] = (
    LuaModuleNote(
        WiresharkCapability.UTILITY,
        "Utility Functions",
        "13.1",
        "get_version, preferences, dofile/loadfile, report_failure",
    ),
    LuaModuleNote(
        WiresharkCapability.GUI,
        "GUI Support",
        "13.2",
        "ProgDlg progress dialogs and TextWindow output panes",
    ),
    LuaModuleNote(
        WiresharkCapability.PROTOCOLS,
        "Protocols And Dissectors",
        "13.3",
        "Proto, ProtoField, DissectorTable, Pref / Prefs",
    ),
    LuaModuleNote(
        WiresharkCapability.FIELDS,
        "Obtaining Dissection Data",
        "13.4",
        "Field / FieldInfo accessors for dissected values",
    ),
    LuaModuleNote(
        WiresharkCapability.PACKET_INFO,
        "Packet Information",
        "13.5",
        "Pinfo, Address, Column(s), NSTime, Conversation",
    ),
    LuaModuleNote(
        WiresharkCapability.PACKET_DATA,
        "Packet Data",
        "13.6",
        "Tvb / TvbRange / ByteArray over frame bytes",
    ),
    LuaModuleNote(
        WiresharkCapability.TREE,
        "Dissection Tree",
        "13.7",
        "TreeItem — add protocol tree nodes",
    ),
    LuaModuleNote(
        WiresharkCapability.LISTENER,
        "Post-Dissection Analysis",
        "13.8",
        "Listener taps for after-dissection analysis",
    ),
    LuaModuleNote(
        WiresharkCapability.CAPTURE_IO,
        "Capture File I/O",
        "13.9–13.11",
        "Dumper, FileHandler, FrameInfo, custom file formats",
    ),
    LuaModuleNote(
        WiresharkCapability.WTAP,
        "Wtap / File Types",
        "13.10",
        "Capture file type registration helpers",
    ),
)


@dataclass
class WiresharkBridgeConfig:
    """Where NetCheck expects Wireshark and our Lua plugins to live."""

    wireshark_exe: Path | None = None
    plugins_dir: Path | None = None
    personal_config_dir: Path | None = None
    tshark_exe: Path | None = None
    enabled: bool = False
    notes: str = ""


@dataclass
class WiresharkStatus:
    """Runtime probe result (placeholder until a real launcher exists)."""

    available: bool = False
    version: str = ""
    lua_release: str = ""
    message: str = "Not connected — framework only"
    config: WiresharkBridgeConfig = field(default_factory=WiresharkBridgeConfig)


class WiresharkBridge:
    """Scaffold for talking to Wireshark via Lua scripts / tshark.

    Planned flow (not implemented yet):
      1. Locate wireshark.exe / tshark.exe
      2. Drop NetCheck Lua under the personal plugins dir
      3. Invoke tshark with ``-X lua_script:…`` or open Wireshark with a tap
      4. Collect Listener / Field results back into NetCheck

    See: https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html
    """

    def __init__(self, config: WiresharkBridgeConfig | None = None) -> None:
        self.config = config or WiresharkBridgeConfig()

    def probe(self) -> WiresharkStatus:
        """Best-effort availability check (stub)."""
        exe = self.config.wireshark_exe or self.config.tshark_exe
        if exe is not None and Path(exe).is_file():
            return WiresharkStatus(
                available=True,
                version="(not queried yet)",
                message=f"Binary found at {exe} — Lua bridge not wired",
                config=self.config,
            )
        return WiresharkStatus(
            available=False,
            message=(
                "Wireshark / tshark not configured. "
                "Set paths under this section when the bridge is implemented."
            ),
            config=self.config,
        )

    def list_lua_modules(self) -> tuple[LuaModuleNote, ...]:
        """Documented Lua API surfaces NetCheck intends to use."""
        return LUA_API_MODULES

    def draft_plugin_info(self) -> dict[str, str]:
        """Payload for Lua ``set_plugin_info`` once scripts ship."""
        from pfsense_checker import version as ver

        return {
            "version": ver.__version__,
            "description": f"{ver.APP_NAME} Wireshark Lua bridge",
            "author": "aliniant labs",
            "repository": WIRESHARK_LUA_API_DOCS,
        }

    def render_stub_lua(self) -> str:
        """Example Lua skeleton referencing the public API (not loaded yet)."""
        info = self.draft_plugin_info()
        return (
            "-- NetCheck ↔ Wireshark Lua bridge (stub)\n"
            "-- Docs: "
            f"{WIRESHARK_LUA_API_DOCS}\n\n"
            "local my_info = {\n"
            f'    version = "{info["version"]}",\n'
            f'    description = "{info["description"]}",\n'
            f'    author = "{info["author"]}",\n'
            f'    repository = "{info["repository"]}",\n'
            "}\n"
            "set_plugin_info(my_info)\n\n"
            "-- Example Listener tap (placeholder):\n"
            '-- local tap = Listener.new(nil, "frame")\n'
            "-- function tap.packet(pinfo, tvb, tapdata)\n"
            "--   -- Field / TreeItem / Pinfo usage goes here\n"
            "-- end\n"
        )

    def run_script(self, script: Path, capture: Path | None = None) -> dict[str, Any]:
        """Invoke a Lua script against a capture — not implemented yet."""
        raise NotImplementedError(
            "Wireshark Lua bridge is scaffolded only; "
            f"see {WIRESHARK_LUA_API_DOCS}"
        )
