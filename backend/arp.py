"""Cross-platform ARP-table reader.

Returns a snapshot of the current IP -> MAC mapping from the OS.
Linux reads /proc/net/arp (no subprocess); Windows and macOS run
``arp -a`` via subprocess with a hard timeout.  Results are cached
for 30 seconds so a chatty scanner doesn't trigger repeated reads.
"""

from __future__ import annotations

import logging
import platform
import re
import subprocess
import threading
import time as _time
from typing import Dict, Optional


log = logging.getLogger("sentinelscan.arp")

_CACHE_TTL_SECONDS = 30.0
_PROC_ARP_PATH = "/proc/net/arp"

_lock = threading.Lock()
_cached_table: Dict[str, str] = {}
_cached_at: float = 0.0


def _parse_proc_net_arp(text: str) -> Dict[str, str]:
    """Parse Linux /proc/net/arp content.  Skip header and incomplete rows."""
    table: Dict[str, str] = {}
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4:
            continue
        ip, _hwtype, _flags, mac = cols[:4]
        if mac == "00:00:00:00:00:00" or not mac:
            continue
        table[ip] = mac
    return table


def _parse_arp_output(text: str) -> Dict[str, str]:
    """Parse Windows/macOS ``arp -a`` output."""
    table: Dict[str, str] = {}
    pattern = re.compile(r"\(?([\d.]+)\)?\s+(?:at\s+)?([0-9a-fA-F:-]{17})")
    for line in text.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        ip, mac = m.group(1), m.group(2)
        mac = mac.replace("-", ":").lower()
        if mac == "00:00:00:00:00:00":
            continue
        table[ip] = mac
    return table


def _read_linux() -> Dict[str, str]:
    try:
        with open(_PROC_ARP_PATH, "r") as f:
            return _parse_proc_net_arp(f.read())
    except OSError as exc:
        log.debug("ARP read via /proc/net/arp failed: %s", exc)
        return {}


def _read_via_subprocess() -> Dict[str, str]:
    try:
        result = subprocess.run(
            ["arp", "-an" if platform.system() == "Darwin" else "-a"],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        log.debug("ARP subprocess failed: %s", exc)
        return {}
    return _parse_arp_output(result.stdout or "")


def get_table(force_refresh: bool = False) -> Dict[str, str]:
    """Return the current ARP table as a dict IP -> MAC.  Cached for 30s."""
    global _cached_table, _cached_at
    now = _time.monotonic()
    with _lock:
        if not force_refresh and _cached_table and (now - _cached_at) < _CACHE_TTL_SECONDS:
            return dict(_cached_table)
        if platform.system() == "Linux":
            table = _read_linux()
        else:
            table = _read_via_subprocess()
        _cached_table = table
        _cached_at = now
        return dict(table)


def get_mac(ip: str) -> Optional[str]:
    """Return the MAC address for ``ip`` from the ARP table, or None."""
    if not ip:
        return None
    return get_table().get(ip)


def reset_cache() -> None:
    """Clear the ARP cache.  Intended for tests."""
    global _cached_table, _cached_at
    with _lock:
        _cached_table = {}
        _cached_at = 0.0
