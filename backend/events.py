"""Real-time event broadcasting — Server-Sent Events for the live dashboard.

Architecture::

    DetectionEngine.feed_packet()
        └─→ packet listeners
    DetectionEngine._maybe_evaluate() → Attack
        └─→ attack listeners (alert manager, EventBroadcaster)
                └─→ _EventBroadcaster.push()
                        └─→ subscriber Queue → SSE generator → EventSource (browser)

Each SSE client gets a dedicated ``queue.Queue``; the broadcaster pushes to
every connected queue.  Clients that don't drain their queue fast enough
are silently dropped (``maxsize=32`` prevents memory growth under burst).

Usage in ``app.py``::

    from backend.events import get_broadcaster
    broadcaster = get_broadcaster()
    engine.add_listener(broadcaster.on_attack)
    engine.add_packet_callback(broadcaster.on_packet)
"""

from __future__ import annotations

import json
import logging
import queue as _queue
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from queue import Empty, Queue
from typing import Any, Dict, List, Optional

log = logging.getLogger("sentinelscan.events")

# ponytail: hard cap so a misbehaving client (open /api/events/stream and walk away)
# cannot exhaust memory or serialize the broadcaster lock forever.
MAX_SUBSCRIBERS = 256


@dataclass
class ServerEvent:
    event_type: str  # "attack" | "packet" | "heartbeat" | "error"
    data: Dict[str, Any] = field(default_factory=dict)


class _EventBroadcaster:
    """Pushes detection events to all connected SSE subscribers."""

    def __init__(self, max_queue: int = 32) -> None:
        self._subscribers: List[Queue] = []
        self._lock = threading.Lock()
        self._max_queue = max_queue

    # -- subscriber management -----------------------------------------------

    def subscribe(self) -> Queue:
        q: Queue = Queue(maxsize=self._max_queue)
        with self._lock:
            if len(self._subscribers) >= MAX_SUBSCRIBERS:
                raise RuntimeError(f"max SSE subscribers reached ({MAX_SUBSCRIBERS})")
            self._subscribers.append(q)
        log.debug("SSE subscriber connected (%d total)", len(self._subscribers))
        return q

    def unsubscribe(self, q: Queue) -> None:
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass
        log.debug("SSE subscriber disconnected (%d remaining)", len(self._subscribers))

    # -- event sources -------------------------------------------------------

    def on_attack(self, attack: Any, signals: Optional[Dict] = None) -> None:
        """Listener callback for detection engine attacks."""
        try:
            data = attack.to_dict() if hasattr(attack, "to_dict") else {}
            # ponytail: include signals so dashboard can render "why" alongside the attack
            if signals:
                data["signals"] = signals
            self._push(ServerEvent(event_type="attack", data=data))
        except Exception as exc:
            # ponytail: warning (not debug) — a to_dict() failure is a real event loss
            log.warning("Events: on_attack to_dict() failed: %s (attack=%r)", exc, attack)
            self._push(ServerEvent(event_type="error", data={"reason": "to_dict_failed", "detail": str(exc)}))

    def on_packet(self, packet: Dict) -> None:
        """Callback for incoming packets."""
        try:
            self._push(ServerEvent(event_type="packet", data=packet))
        except Exception as exc:
            log.warning("Events: on_packet error: %s", exc)

    # -- push ----------------------------------------------------------------

    def _push(self, event: ServerEvent) -> None:
        with self._lock:
            dead: List[Queue] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except _queue.Full:
                    # ponytail: slow consumer — only queue.Full means "drop the queue".
                    # Other exceptions (closed queue, etc.) are real bugs — log them.
                    dead.append(q)
                except Exception as exc:
                    log.warning("Events: push failed for subscriber: %s", exc)
                    dead.append(q)
            for q in dead:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass

    # -- SSE generator -------------------------------------------------------

    @staticmethod
    def _sse_format(event: ServerEvent) -> str:
        payload = json.dumps(event.data, default=str)
        return f"event: {event.event_type}\ndata: {payload}\n\n"

    def generate(self, q: Queue) -> Any:
        """Generator for the Flask streaming response.

        Yields SSE-formatted lines.  Sends a heartbeat every 10s to
        keep the connection alive (proxies, browsers).
        Unsubscribes on disconnect so closed tabs don't leak queues.
        """
        import time as _time

        try:
            last_heartbeat = _time.monotonic()
            while True:
                try:
                    event = q.get(timeout=10)
                    yield self._sse_format(event)
                    last_heartbeat = _time.monotonic()
                except Empty:
                    now = _time.monotonic()
                    if now - last_heartbeat >= 10:
                        beat = {"ts": datetime.now(timezone.utc).isoformat()}
                        yield self._sse_format(ServerEvent(event_type="heartbeat", data=beat))
                        last_heartbeat = now
        finally:
            # ponytail: critical — without this, every closed browser tab leaks a Queue
            # that holds a reference to the entire _subscribers list.
            self.unsubscribe(q)


# Module-level singleton.
_broadcaster: Optional[_EventBroadcaster] = None


def get_broadcaster() -> _EventBroadcaster:
    global _broadcaster
    if _broadcaster is None:
        _broadcaster = _EventBroadcaster()
    return _broadcaster


def reset_broadcaster() -> None:
    """Clear the singleton (for tests)."""
    global _broadcaster
    _broadcaster = None
