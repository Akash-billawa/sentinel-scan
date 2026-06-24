"""Pending rate limiter — caps packets from sources that are currently
under IPS review.

Why: a heavy scan that just triggered a PendingAction would otherwise
keep hammering the detector and pump pending actions on every retry.
This is a soft cap, not a block: the source is still allowed through,
just throttled, so the operator can read the dashboard without the
system being held hostage by one attacker.

Spec requirement #5: "Use temporary rate limiting while decision is
pending. Maintain system stability under heavy scans."

Design:
  * Per-source token bucket.
  * Default refill: 50 tokens / sec.
  * Bucket capacity: 200 tokens.
  * ``note(ip)`` → True if allowed, False if rate-limited (callers decide
    what to do — typically just skip writing the PacketEvent to disk).
  * Background sweeper prunes sources whose action is no longer pending.
"""

from __future__ import annotations

import logging
import threading
import time as _time
from collections import deque
from typing import Dict, Optional, Set


log = logging.getLogger("sentinelscan.ips.ratelimit")


class _Bucket:
    __slots__ = ("tokens", "last_refill")

    def __init__(self, tokens: float, last_refill: float) -> None:
        self.tokens = tokens
        self.last_refill = last_refill


class PendingRateLimiter:
    """Token-bucket rate limiter for sources with a pending IPS decision."""

    def __init__(
        self,
        capacity: int = 200,
        refill_per_sec: float = 50.0,
    ) -> None:
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._capacity = float(capacity)
        self._refill = float(refill_per_sec)
        self._pending_sources: Set[str] = set()
        self._running = False
        self._sweeper: Optional[threading.Thread] = None

    def mark_pending(self, ip: str) -> None:
        """Register a source as currently under review.

        Idempotent. The bucket is allocated lazily on the first packet so
        we don't waste memory on attackers who never reach us.
        """
        with self._lock:
            self._pending_sources.add(ip)

    def unmark_pending(self, ip: str) -> None:
        """Source has been decided (allow or block) — drop from tracking."""
        with self._lock:
            self._pending_sources.discard(ip)
            # Keep the bucket around briefly so an Allow → flood burst
            # can't immediately bypass, but cap its memory by pruning in sweep.

    def note(self, ip: str, cost: float = 1.0) -> bool:
        """Charge ``cost`` tokens from the bucket. Returns False if limited.

        Sources NOT in the pending set bypass the limiter entirely — the
        point is only to cushion the IPS review window, not to throttle
        baseline traffic.
        """
        with self._lock:
            if ip not in self._pending_sources:
                return True
            now = _time.monotonic()
            bucket = self._buckets.get(ip)
            if bucket is None:
                bucket = _Bucket(self._capacity, now)
                self._buckets[ip] = bucket
            else:
                elapsed = now - bucket.last_refill
                if elapsed > 0:
                    bucket.tokens = min(
                        self._capacity,
                        bucket.tokens + elapsed * self._refill,
                    )
                    bucket.last_refill = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True
            return False

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "pending_sources": len(self._pending_sources),
                "tracked_buckets": len(self._buckets),
                "capacity": int(self._capacity),
                "refill_per_sec": int(self._refill),
            }

    # ---- Sweeper ------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._sweeper = threading.Thread(
            target=self._sweep_loop, name="pending-rl-sweeper", daemon=True,
        )
        self._sweeper.start()

    def stop(self) -> None:
        self._running = False
        if self._sweeper:
            self._sweeper.join(timeout=2.0)
            self._sweeper = None

    def _sweep_loop(self) -> None:
        while self._running:
            try:
                self._sweep_once()
            except Exception as exc:  # pragma: no cover
                log.warning("rate-limit sweep failed: %s", exc)
            for _ in range(30):  # every ~30s
                if not self._running:
                    return
                _time.sleep(1.0)

    def _sweep_once(self) -> None:
        with self._lock:
            stale = [ip for ip in self._buckets if ip not in self._pending_sources]
            for ip in stale:
                del self._buckets[ip]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_limiter: Optional[PendingRateLimiter] = None


def get_pending_rate_limiter() -> PendingRateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = PendingRateLimiter()
        _limiter.start()
    return _limiter
