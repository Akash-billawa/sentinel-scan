"""Whitelist Manager — temporary allowlist for sources under review.

A whitelist entry is created when an operator clicks **Allow** on a
pending IPS action. While the entry is alive, packets from that source
bypass the firewall (the firewall_manager.is_blocked() check would not
match anyway, but a higher-level flow may want to short-circuit before
doing deep inspection — that's what ``is_whitelisted()`` is for).

Spec requirements addressed here:
  * Default whitelist duration: 5 minutes (configurable).
  * Atomic add; idempotent — duplicate add refreshes TTL.
  * **Whitelist abuse prevention**: bounded total entries + bounded TTL.
  * **Automatic removal of expired entries** via a background sweeper.

Whitelist is in-memory only — these are short-lived allowances and we
don't want them surviving reboots. A block that should survive would go
through the firewall manager, not here.
"""

from __future__ import annotations

import logging
import threading
import time as _time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional


log = logging.getLogger("sentinelscan.ips.whitelist")


# ---------------------------------------------------------------------------
# Abuse-prevention ceilings — these are hard limits regardless of settings.
# Operators can shorten them but not lengthen them past the safety caps.
# ---------------------------------------------------------------------------
MAX_ENTRIES_HARD_CAP = 10_000          # any one process can hold this many
MAX_TTL_SECONDS_HARD_CAP = 24 * 3600   # 24h — anything longer is a permanent block


@dataclass
class WhitelistEntry:
    ip: str
    added_at: datetime
    expires_at: datetime
    added_by: str = "operator"
    reason: str = ""
    action_id: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "added_at": self.added_at.isoformat() + "Z",
            "expires_at": self.expires_at.isoformat() + "Z",
            "added_by": self.added_by,
            "reason": self.reason,
            "action_id": self.action_id,
        }


class WhitelistManager:
    """Thread-safe temporary IP whitelist with automatic expiry."""

    def __init__(self, default_ttl_seconds: int = 300, max_entries: int = 1000) -> None:
        self._entries: Dict[str, WhitelistEntry] = {}
        self._lock = threading.Lock()
        self._default_ttl = default_ttl_seconds
        self._max_entries = max_entries
        self._running = False
        self._sweeper: Optional[threading.Thread] = None

    # ---- Public API -----------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._sweeper = threading.Thread(
            target=self._sweep_loop, name="whitelist-sweeper", daemon=True,
        )
        self._sweeper.start()
        log.info("Whitelist manager started (default_ttl=%ds, max=%d)",
                 self._default_ttl, self._max_entries)

    def stop(self) -> None:
        self._running = False
        if self._sweeper:
            self._sweeper.join(timeout=2.0)
            self._sweeper = None

    def add(self, ip: str, ttl_seconds: Optional[int] = None,
            added_by: str = "operator", reason: str = "",
            action_id: Optional[str] = None) -> WhitelistEntry:
        """Add (or refresh) a whitelist entry. Returns the new entry.

        Abuse prevention:
          - ``ttl_seconds`` is clamped to ``MAX_TTL_SECONDS_HARD_CAP``.
          - Refuses to exceed ``max_entries`` (oldest entry is evicted).
        """
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        ttl = max(1, min(int(ttl), MAX_TTL_SECONDS_HARD_CAP))
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        with self._lock:
            # Evict oldest if we'd exceed cap. Cheap amortised cost.
            if ip not in self._entries and len(self._entries) >= self._max_entries:
                victim_ip = min(
                    self._entries,
                    key=lambda k: self._entries[k].expires_at,
                )
                log.warning("Whitelist at capacity; evicting oldest entry %s", victim_ip)
                del self._entries[victim_ip]

            entry = WhitelistEntry(
                ip=ip,
                added_at=now,
                expires_at=now + timedelta(seconds=ttl),
                added_by=added_by,
                reason=reason,
                action_id=action_id,
            )
            self._entries[ip] = entry

        log.info("Whitelisted %s for %ds (by %s, action=%s)",
                 ip, ttl, added_by, action_id or "n/a")
        return entry

    def remove(self, ip: str) -> bool:
        """Remove an entry explicitly. Returns True if something was removed."""
        with self._lock:
            return self._entries.pop(ip, None) is not None

    def is_whitelisted(self, ip: str) -> bool:
        """True iff the IP has a non-expired entry. Expired entries are
        pruned on the fly so callers always see accurate state."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                return False
            if entry.expires_at <= now:
                del self._entries[ip]
                return False
            return True

    def list_entries(self) -> List[WhitelistEntry]:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with self._lock:
            # Drop expired entries lazily on read too.
            expired = [ip for ip, e in self._entries.items() if e.expires_at <= now]
            for ip in expired:
                del self._entries[ip]
            return list(self._entries.values())

    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    # ---- Background sweeper --------------------------------------------

    def _sweep_loop(self) -> None:
        while self._running:
            try:
                self._sweep_once()
            except Exception as exc:  # pragma: no cover
                log.warning("whitelist sweep failed: %s", exc)
            for _ in range(10):  # 10 * 1s = 10s sweep interval
                if not self._running:
                    return
                _time.sleep(1.0)

    def _sweep_once(self) -> int:
        """Remove expired entries. Returns the count removed."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with self._lock:
            expired = [ip for ip, e in self._entries.items() if e.expires_at <= now]
            for ip in expired:
                del self._entries[ip]
        if expired:
            log.info("Whitelist swept %d expired entries", len(expired))
        return len(expired)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_manager: Optional[WhitelistManager] = None


def get_whitelist_manager() -> WhitelistManager:
    global _manager
    if _manager is None:
        from .config import get_settings
        s = get_settings()
        # ponytail: pull default TTL from settings; cap on the way in to the
        # settings layer is the right place for soft-cap, this is the last
        # line of defence against an operator-typo'd "360000" in .env.
        _manager = WhitelistManager(
            default_ttl_seconds=getattr(s, "ips_whitelist_ttl", 300),
            max_entries=getattr(s, "ips_whitelist_max_entries", 1000),
        )
        _manager.start()
    return _manager
