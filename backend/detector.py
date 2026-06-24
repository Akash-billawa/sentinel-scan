"""Detection engine — the heart of SentinelScan AI.

The engine receives :class:`PacketEvent`-like dictionaries, maintains a
sliding window of activity per source IP, evaluates the window against
the configured thresholds, and — when thresholds are crossed — emits a
fully populated :class:`Attack` object enriched by the classifier,
fingerprinter, profiler, and risk scorer.

Two design choices are worth highlighting:

1. **Engine is the source of truth for *what* was seen.** Capture
   modules only emit per-packet summaries; the engine decides whether
   those packets constitute a scan and how to label it.
2. **Detections are *events*, not state.** The engine keeps a small
   ring of recent packets per source (for the dashboard live feed) but
   the *authoritative* attack records live in the database.  Listeners
   (alert manager, simulator hook) subscribe via ``add_listener``.

The engine is thread-safe: capture threads call ``feed_packet`` from
their own context, the API thread reads summary state, and the
periodic evaluator runs on a timer thread.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Deque, Dict, List, Optional

from . import database as db
from .classifier import classify
from .config import Settings, get_settings
from .explanation import explain_attack
from .fingerprinter import fingerprint_tool
from .profiler import OSGuess, guess_os, profile_source
from .risk import assess
from .threat_intel import check_ip
from .ips_policy import evaluate as ips_evaluate
from .rules import evaluate_rules

log = logging.getLogger("sentinelscan.detector")

# Known CDN / proxy / tunnel provider ASNs.  Traffic from these sources
# that touches very few ports on a single host is almost always
# legitimate tunnel keep-alive (Cloudflare WARP, AWS CloudFront, etc.),
# not reconnaissance.  keyed by the ``asn`` string returned by the
# profiler.
_CDN_ASNS = frozenset({
    "AS13335",   # Cloudflare, Inc.
    "AS15169",   # Google LLC (also Cloudflare WARP exit nodes)
    "AS16509",   # Amazon AWS
    "AS20940",   # Akamai Technologies
    "AS21342",   # Akamai International
    "AS21399",   # Akamai European Network
    "AS16625",   # Akamai Technologies
    "AS32613",   # iWeb Technologies (OVH CDN)
    "AS54113",   # Fastly
    "AS55410",   # Vodafone (some tunnel endpoints)
    "AS14618",   # Amazon AWS CloudFront
    "AS46562",   # Cloudflare Transit
    "AS20473",   # Vultr (some WARP exits)
})


def _now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _flags_set(flags: Dict[str, bool], names: list) -> bool:
    """Return True if every flag in *names* is set to True."""
    return all(flags.get(n) for n in names)

# Maximum number of recent packets retained per source for the live feed.
_RECENT_PACKETS_PER_SOURCE = 200

# Coalesce repeated detections of the same source/scan_type for this many
# seconds — so a long SYN scan becomes *one* attack, not 50 rows.
_DETECTION_COOLDOWN = 30.0


# ---------------------------------------------------------------------------
# Lightweight in-memory packet record
# ---------------------------------------------------------------------------


@dataclass
class PacketRecord:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    flags: Dict[str, bool]
    tcp_window: Optional[int] = None
    ttl: Optional[int] = None
    length: int = 0
    is_fragment: bool = False
    # TCP options parsed from a SYN-only packet.  Bounded dict (≤6 keys):
    #   mss       (int)   — Maximum Segment Size option
    #   wscale    (int)   — Window Scale option
    #   timestamp (bool)  — Timestamp option present
    #   sack_perm (bool)  — SACK-Permitted option present
    #   nop       (int)   — count of NOP pad bytes
    #   eol       (bool)  — End Of Option List present
    # Only set for SYN-only packets to avoid responder-OS contamination —
    # SYN+ACK options reflect the OS of *this* machine, not the scanner.
    tcp_options: Dict[str, object] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Bounded packet buffer
# ---------------------------------------------------------------------------
#
# The previous implementation called ``db.session_scope()`` and INSERTed a
# ``PacketEvent`` row for *every* packet.  On a busy sim burst (1,500
# packets in <1s for a Masscan profile) that's 1,500 short-lived DB
# transactions per second, which overwhelms SQLite's writer lock and
# shows up to the user as "the engine feels stuck".  The PRD promises
# 10,000+ packets/minute, so the hot path has to be cheap.
#
# We fix this by accumulating ``PacketEvent`` objects in a small in-memory
# queue and flushing them in a single ``session_scope()`` whenever the
# queue crosses ``_PACKET_BUFFER_MAX`` records or the periodic flusher
# thread wakes up (``_PACKET_BUFFER_FLUSH_SEC``).  ``DetectionEngine.stop``
# performs a final flush so no events are lost on shutdown.
_PACKET_BUFFER_MAX = 200
_PACKET_BUFFER_FLUSH_SEC = 0.5

# In-memory ring buffer for instant live packet feed (bypasses DB).
_LIVE_PACKETS_MAX = 200


class _PacketBuffer:
    """Bounded, thread-safe accumulator for :class:`db.PacketEvent` rows.

    The detector's hot path calls :meth:`append` (an O(1) operation under
    a short lock); a daemon thread calls :meth:`_flusher_loop` which
    drains the buffer in a single ``session_scope()`` whenever it has
    data.  On a clean stop :meth:`flush` is called synchronously so the
    last batch is never lost.
    """

    def __init__(self) -> None:
        self._queue: List[db.PacketEvent] = []
        self._lock = threading.Lock()
        self._flusher_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._dropped = 0  # packets lost because the buffer blew past its soft cap
        # Per-event requeue counter so a persistently-down DB can't grow the
        # buffer unbounded. After _requeue_threshold attempts we drop the event
        # and increment _permanent_drops (exposed via stats() for /api/status).
        self._requeue_counts: Dict[int, int] = {}
        self._permanent_drops = 0
        self._requeue_threshold = 5  # ponytail: tune up if the DB is briefly slow

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        if self._flusher_thread is not None and self._flusher_thread.is_alive():
            return
        self._stop_event.clear()
        self._flusher_thread = threading.Thread(
            target=self._flusher_loop, name="packet-flusher", daemon=True
        )
        self._flusher_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._flusher_thread is not None:
            self._flusher_thread.join(timeout=2.0)
            self._flusher_thread = None
        # Final drain so no events are lost on shutdown.
        self.flush()

    # -- hot path ---------------------------------------------------------

    def append(self, pkt: PacketRecord) -> None:
        try:
            flags = ",".join(n for n, v in pkt.flags.items() if v) or ""
        except Exception:
            flags = ""
        event = db.PacketEvent(
            timestamp=pkt.timestamp,
            source_ip=pkt.source_ip,
            destination_ip=pkt.destination_ip,
            source_port=pkt.source_port,
            destination_port=pkt.destination_port,
            protocol=pkt.protocol,
            flags=flags,
            length=pkt.length,
            summary=(
                f"{pkt.protocol} {pkt.source_ip}:{pkt.source_port} -> "
                f"{pkt.destination_ip}:{pkt.destination_port}"
            ),
        )
        with self._lock:
            self._queue.append(event)
            # If the queue is growing faster than the flusher can drain
            # (e.g. on a real 10k pps live capture), drop the oldest
            # events rather than letting memory balloon.  The detection
            # logic still runs on the in-memory stream; the dropped
            # events are only forensic records.
            if len(self._queue) > _PACKET_BUFFER_MAX * 4:
                drop = len(self._queue) - _PACKET_BUFFER_MAX * 2
                del self._queue[:drop]
                self._dropped += drop

    # -- flusher ----------------------------------------------------------

    def _flusher_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(_PACKET_BUFFER_FLUSH_SEC)
            try:
                self.flush()
            except Exception as exc:  # pragma: no cover - never block boot
                log.warning("packet flusher error: %s", exc)

    def flush(self) -> None:
        """Drain the buffer in a single transaction.  Safe to call often."""

        with self._lock:
            if not self._queue:
                return
            batch = self._queue
            self._queue = []
            attempts = {id(e): self._requeue_counts.get(id(e), 0) for e in batch}

        try:
            with db.session_scope() as s:
                for event in batch:
                    s.add(event)
            # Successful flush — clear requeue counters for these ids.
            with self._lock:
                for eid in attempts:
                    self._requeue_counts.pop(eid, None)
        except Exception as exc:
            # Re-queue on transient failure so we retry next tick.
            # Append to the END — prepending at [0:0] causes O(n²)
            # growth when the DB is persistently down.
            with self._lock:
                kept = []
                dropped_this_tick = 0
                for event in batch:
                    new_count = attempts.get(id(event), 0) + 1
                    if new_count >= self._requeue_threshold:
                        self._requeue_counts.pop(id(event), None)
                        self._permanent_drops += 1
                        dropped_this_tick += 1
                        continue
                    self._requeue_counts[id(event)] = new_count
                    kept.append(event)
                if kept:
                    self._queue.extend(kept)
            if dropped_this_tick:
                log.error(
                    "packet flusher: %d events dropped after %d requeue attempts "
                    "(DB likely down: %s)",
                    dropped_this_tick, self._requeue_threshold, exc,
                )
            else:
                log.warning("packet flush failed (will retry): %s", exc)

    def stats(self) -> Dict[str, int]:
        """Surface buffer stats for /api/status."""
        with self._lock:
            return {
                "queued": len(self._queue),
                "dropped_overflow": self._dropped,
                "dropped_after_requeue": self._permanent_drops,
                "in_requeue": len(self._requeue_counts),
            }


def _first_syn_options(packets: Deque["PacketRecord"]) -> Dict[str, object]:
    """Return TCP options from the first SYN-only packet that has any.

    Iterates in deque order (which is insertion order for ``deque``), so
    the choice is deterministic and matches the existing OS-guess loop.
    Returns an empty dict if no SYN-only packet had options.
    """
    for p in packets:
        if p.flags.get("SYN") and not p.flags.get("ACK") and p.tcp_options:
            return p.tcp_options
    return {}


# Initial TTLs of common stacks — used to round an observed TTL back to
# the originating stack's default.  Ordered most-specific-first.
_KNOWN_INITIAL_TTLS = (32, 64, 128, 255)


def _initial_ttl(observed: Optional[int]) -> Optional[int]:
    """Round an observed TTL up to the nearest known initial.

    Mirrors the helper in ``backend.profiler``; we keep a local copy to
    avoid an import cycle (``profiler`` doesn't depend on the detector,
    but the detector already imports from ``profiler`` for OS guessing,
    and we want this helper available even if the profiler helper
    changes shape).
    """
    if observed is None or observed < 1 or observed > 255:
        return None
    for k in _KNOWN_INITIAL_TTLS:
        if observed <= k:
            return k
    return 255


def _port_order_continuity(ports: List[int]) -> float:
    """Return 0..1 indicating how sequentially the ports were hit.

    Wide-sweep tools (Masscan, Nmap ``-p-``) probe ports in *numeric
    order*; random/hand-rolled tools don't.  We compute
    ``len(ports) / (max - min + 1)`` on the sorted unique set, which
    approaches 1.0 for a dense run (e.g. ``1..1000``) and 0.0 for a
    sparse set.  This is a cheap stand-in for a more thorough
    longest-run / run-length analysis; the per-tool scorer treats it
    as a soft discriminator, not a hard gate.
    """
    if len(ports) < 2:
        return 0.0
    sorted_ports = sorted(ports)
    span = sorted_ports[-1] - sorted_ports[0] + 1
    if span <= 0:
        return 0.0
    return min(1.0, len(sorted_ports) / span)


def _timing_cv(packets: Deque["PacketRecord"]) -> float:
    """Coefficient of variation (std/mean) of inter-packet deltas.

    Returns 0.0 if there are <2 packets or the mean is zero (instant
    burst).  A low CV (≤ 0.2) is "script-paced" — characteristic of
    Masscan and Nmap at default timing.  A high CV (> 0.5) is
    "human-paced" — characteristic of Zenmap / interactive Nmap.  We
    deliberately do not bound the upper end so the discriminator
    stays meaningful for very jittery traffic.
    """
    if len(packets) < 2:
        return 0.0
    deltas: List[float] = []
    prev = packets[0].timestamp
    for p in list(packets)[1:]:
        delta = (p.timestamp - prev).total_seconds()
        if delta > 0:
            deltas.append(delta)
        prev = p.timestamp
    if not deltas:
        return 0.0
    mean = sum(deltas) / len(deltas)
    if mean <= 0:
        return 0.0
    variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    std = variance ** 0.5
    return std / mean


def _mode_value(values) -> Optional[int]:
    """Return the most common value from an iterable, or None if empty.

    Used to extract the dominant TCP window size or MSS from a burst of
    packets — Suricata rules match on specific values like window:1024
    and tcp.mss:1460.
    """
    counts: Dict[int, int] = {}
    for v in values:
        if v is not None:
            counts[int(v)] = counts.get(int(v), 0) + 1
    if not counts:
        return None
    return max(counts, key=counts.get)


def _count_in_window(packets: Deque[PacketRecord], seconds: int) -> int:
    """Count packets from the tail of the deque within the last N seconds.

    Used for Suricata-style threshold matching: "track by_src, count N,
    seconds T".
    """
    if not packets:
        return 0
    cutoff = packets[-1].timestamp - timedelta(seconds=seconds)
    count = 0
    for p in reversed(packets):
        if p.timestamp < cutoff:
            break
        count += 1
    return count


@dataclass
class SourceState:
    source_ip: str
    packets: Deque[PacketRecord] = field(default_factory=deque)
    first_seen: datetime = field(default_factory=_now_naive)
    last_seen: datetime = field(default_factory=_now_naive)
    last_emit: Dict[str, datetime] = field(default_factory=dict)  # scan_type -> ts
    eval_seq: int = 0

    def purge(self, window_seconds: int) -> None:
        cutoff = _now_naive() - timedelta(seconds=window_seconds * 2)
        while self.packets and self.packets[0].timestamp < cutoff:
            self.packets.popleft()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


DetectionListener = Callable[[db.Attack, Dict], None]


class DetectionEngine:
    """Thread-safe sliding-window scan detector."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self._state: Dict[str, SourceState] = {}
        self._lock = threading.RLock()
        self._listeners: List[DetectionListener] = []
        self._packet_listeners: List[Callable[[Dict], None]] = []
        self._running = False
        self._packet_count = 0
        self._attack_count = 0
        self._session_id: Optional[int] = None
        self._mode: str = "sim"
        self._packet_buffer = _PacketBuffer()
        # In-memory ring buffer for instant live packet feed.
        self._live_packets: Deque[Dict] = deque(maxlen=_LIVE_PACKETS_MAX)

    # -- lifecycle --------------------------------------------------------

    def start(self, mode: str = "sim", session_name: str = "default") -> None:
        with self._lock:
            self._running = True
            self._mode = mode
            self._packet_count = 0
            self._attack_count = 0
            sess = db.get_or_create_session(session_name, mode)
            self._session_id = sess.id
            self._state.clear()
            self._live_packets.clear()
        self._packet_buffer.start()
        log.info("Detection engine started (mode=%s, session=%s)", mode, session_name)

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
            if self._session_id is not None:
                db.end_session(self._session_id, self._packet_count, self._attack_count)
        # Flush any in-flight packet events before we go quiet.
        self._packet_buffer.stop()
        log.info("Detection engine stopped (packets=%d, attacks=%d)", self._packet_count, self._attack_count)

    @property
    def running(self) -> bool:
        return self._running

    @property
    def mode(self) -> str:
        return self._mode

    # -- listeners --------------------------------------------------------

    def add_listener(self, fn: DetectionListener) -> None:
        with self._lock:
            self._listeners.append(fn)

    def remove_listener(self, fn: DetectionListener) -> None:
        with self._lock:
            if fn in self._listeners:
                self._listeners.remove(fn)

    def add_packet_callback(self, fn: Callable[[Dict], None]) -> None:
        with self._lock:
            self._packet_listeners.append(fn)

    def remove_packet_callback(self, fn: Callable[[Dict], None]) -> None:
        with self._lock:
            if fn in self._packet_listeners:
                self._packet_listeners.remove(fn)

    # -- packet ingest ----------------------------------------------------

    def feed_packet(self, pkt: PacketRecord) -> None:
        """Thread-safe entrypoint for capture modules."""

        if not self._running:
            return
        with self._lock:
            self._packet_count += 1
            st = self._state.get(pkt.source_ip)
            if st is None:
                st = SourceState(source_ip=pkt.source_ip)
                self._state[pkt.source_ip] = st
            st.packets.append(pkt)
            st.last_seen = pkt.timestamp
            if len(st.packets) > _RECENT_PACKETS_PER_SOURCE:
                st.packets.popleft()

            # Build packet dict for ring buffer + callbacks.
            try:
                flags_str = ",".join(n for n, v in pkt.flags.items() if v) or ""
            except Exception:
                flags_str = ""
            pkt_dict = {
                "timestamp": pkt.timestamp.isoformat() + "Z",
                "source_ip": pkt.source_ip,
                "destination_ip": pkt.destination_ip,
                "source_port": pkt.source_port,
                "destination_port": pkt.destination_port,
                "protocol": pkt.protocol,
                "flags": flags_str,
                "length": pkt.length,
            }
            self._live_packets.appendleft(pkt_dict)

            # Fire packet callbacks (SSE broadcaster, etc.).
            for cb in list(self._packet_listeners):
                try:
                    cb(pkt_dict)
                except Exception as exc:
                    log.debug("packet callback %r failed: %s", cb, exc)

            # Purge old packets under the lock.
            st.purge(self.settings.window_seconds)

            # Hand the packet to the bounded buffer; the flusher thread
            # persists it in a single ``session_scope()`` every
            # ``_PACKET_BUFFER_FLUSH_SEC`` (or sooner on a full buffer).
            # Rate-limit DB writes for sources under IPS review to avoid
            # flooding the database during heavy scans.
            from .pending_rate_limiter import get_pending_rate_limiter
            if get_pending_rate_limiter().note(pkt.source_ip, cost=1.0):
                self._packet_buffer.append(pkt)

            # Increment sequence and take snapshots.
            st.eval_seq += 1
            my_seq = st.eval_seq
            packets_snapshot = list(st.packets)
            last_emit_snapshot = dict(st.last_emit)

        # Periodically evaluate this source outside the lock.
        self._maybe_evaluate(pkt.source_ip, packets_snapshot, last_emit_snapshot, my_seq)

    # -- evaluation -------------------------------------------------------

    def _maybe_evaluate(
        self,
        source_ip: str,
        packets_snapshot: List[PacketRecord],
        last_emit_snapshot: Dict[str, datetime],
        eval_seq: int
    ) -> None:
        s = self.settings

        if len(packets_snapshot) < 5:  # ignore tiny blips
            return

        unique_ports = {p.destination_port for p in packets_snapshot if p.destination_port}
        unique_targets = {p.destination_ip for p in packets_snapshot if p.destination_ip}
        unique_source_ports = {p.source_port for p in packets_snapshot if p.source_port}
        has_tcp = any(p.protocol == "TCP" for p in packets_snapshot)
        has_udp = any(p.protocol == "UDP" for p in packets_snapshot)
        has_icmp = any(p.protocol == "ICMP" for p in packets_snapshot)
        syn_pkts = sum(1 for p in packets_snapshot if p.flags.get("SYN") and not p.flags.get("ACK"))
        completed = sum(1 for p in packets_snapshot if p.flags.get("SYN") and p.flags.get("ACK"))
        tcp_total = sum(1 for p in packets_snapshot if p.protocol == "TCP")
        syn_ratio = syn_pkts / max(tcp_total, 1)
        completion_ratio = completed / max(syn_pkts, 1) if syn_pkts else 0.0

        flags_seen: Dict[str, bool] = {}
        for p in packets_snapshot:
            for f, v in p.flags.items():
                if v:
                    flags_seen[f] = True
        uses_ecn = any(p.flags.get("ECE") or p.flags.get("CWR") for p in packets_snapshot)

        proto_mix = {
            "TCP": sum(1 for p in packets_snapshot if p.protocol == "TCP"),
            "UDP": sum(1 for p in packets_snapshot if p.protocol == "UDP"),
            "ICMP": sum(1 for p in packets_snapshot if p.protocol == "ICMP"),
        }
        if max(proto_mix.values()) == 0:
            return

        # First SYN-only packet's initial TTL — used by the fingerprinter
        # to bias TTL-128 bursts toward Windows-Nmap and TTL-64 bursts
        # toward Linux-Nmap/Masscan.
        ttl_first_syn: Optional[int] = None
        for p in packets_snapshot:
            if p.flags.get("SYN") and not p.flags.get("ACK"):
                ttl_first_syn = _initial_ttl(p.ttl)
                break

        signals = {
            "has_tcp": has_tcp,
            "has_udp": has_udp,
            "has_icmp": has_icmp,
            "unique_ports": len(unique_ports),
            "unique_targets": len(unique_targets),
            "syn_ratio": syn_ratio,
            "tcp_completion_ratio": completion_ratio,
            "flags_seen": flags_seen,
            "uses_ecn": uses_ecn,
            "proto_mix": proto_mix,
            "packet_count": len(packets_snapshot),
            # Use the real packet time span (not the configured window) so a
            # burst of 800 packets in 1s is reported as 800 pps.
            "rate": len(packets_snapshot) / max(
                (packets_snapshot[-1].timestamp - packets_snapshot[0].timestamp).total_seconds(), 0.5
            ),
            # TCP options sample: the options from the FIRST SYN-only packet
            # in chronological order.
            "tcp_options_sample": _first_syn_options(deque(packets_snapshot)),
            "tcp_options_seen": any(
                p.flags.get("SYN") and not p.flags.get("ACK") and p.tcp_options
                for p in packets_snapshot
            ),
            # --- Suricata-style fingerprint signals ---
            "window_value": _mode_value(p.tcp_window for p in packets_snapshot
                                        if p.protocol == "TCP" and p.tcp_window),
            "mss_value": _mode_value(
                (p.tcp_options or {}).get("mss")
                for p in packets_snapshot
                if p.flags.get("SYN") and not p.flags.get("ACK")
                and (p.tcp_options or {}).get("mss")
            ),
            "source_count_70s": _count_in_window(deque(packets_snapshot), 70),
            "source_count_135s": _count_in_window(deque(packets_snapshot), 135),
            # Unique port list (for rules that check specific port sets).
            "unique_port_list": sorted(unique_ports),
            "ttl_first_syn": ttl_first_syn,
            "source_port_fixed": (
                len(unique_source_ports) == 1 and 0 not in unique_source_ports
            ),
            "port_order_continuity": _port_order_continuity(list(unique_ports)),
            "timing_cv": _timing_cv(deque(packets_snapshot)),
            "fragmented_count": sum(1 for p in packets_snapshot if p.is_fragment),
        }

        # Thresholds: rate, port sweep, host sweep.
        # For TCP, only SYN-only packets are "probes" — ACK, PSH+ACK, SYN+ACK
        # are established traffic, not reconnaissance.  Count probe-only
        # destinations and ports so that browser/cloud false positives
        # (which have zero or one SYN) don't inflate the trip counters.
        rate = signals["rate"]
        syn_probe_targets = {p.destination_ip for p in packets_snapshot
                             if p.flags.get("SYN") and not p.flags.get("ACK")}
        syn_probe_ports = {p.destination_port for p in packets_snapshot
                           if p.flags.get("SYN") and not p.flags.get("ACK")
                           and p.destination_port}
        syn_probe_rate = syn_pkts / max(
            (packets_snapshot[-1].timestamp - packets_snapshot[0].timestamp).total_seconds(), 0.5
        ) if syn_pkts else 0.0
        tripped = []
        # For rate: if TCP is present, use SYN-probe rate (established
        # traffic shouldn't inflate the counter); for pure UDP/ICMP, use
        # the total-packet rate since there's no handshake to distinguish.
        if (has_tcp and syn_probe_rate >= s.rate_threshold
            or not has_tcp and rate >= s.rate_threshold):
            tripped.append("rate")
        # For port sweep: use SYN-probe ports when TCP is active.
        # Pure established TCP (no SYN at all) doesn't trip — that's
        # application data, not a probe.
        if (has_tcp and syn_probe_ports and len(syn_probe_ports) >= s.portsweep_threshold
            or not has_tcp and len(unique_ports) >= s.portsweep_threshold):
            tripped.append("port_sweep")
        # For host sweep: same SYN-probe-based logic as port sweep.
        if (has_tcp and syn_probe_targets and len(syn_probe_targets) >= s.hostsweep_threshold
            or not has_tcp and len(unique_targets) >= s.hostsweep_threshold):
            tripped.append("host_sweep")
        # Special: low-volume but unmistakable signatures still trigger.
        if signals["uses_ecn"] and has_tcp and len(unique_ports) >= 3:
            tripped.append("ecn_probe")

        # Run rules engine: if a Suricata-style scan signature matches, treat it as tripped.
        rule_matches = evaluate_rules(signals)
        if rule_matches:
            tripped.append("rule_match")

        if not tripped:
            return

        # --- Single-port, single-target burst suppression: a high-rate
        #     burst to ONE port on ONE host is application data (WebRTC,
        #     gaming, NAT traversal, VoIP calls), not reconnaissance.
        #     Real scanners always probe multiple ports or hosts. ---
        if len(unique_targets) == 1 and len(unique_ports) == 1:
            log.debug(
                "Suppressed single-target single-port burst from %s: "
                "%d packets to %s:%d at %.1f pkt/sec — app data, not scan",
                source_ip, len(packets_snapshot),
                next(iter(unique_targets)), next(iter(unique_ports)),
                signals["rate"],
            )
            return

        # --- Zero SYN probes suppression: if NO SYN-only packets exist
        #     in a TCP window, every packet is an established connection
        #     (ACK, SYN+ACK, PSH+ACK).  No connection attempts = no scan,
        #     regardless of how many targets or ports are involved.
        #     Catches browsers checking multiple services, Windows
        #     Defender, cloud client heartbeats, etc. ---
        if syn_pkts == 0 and has_tcp and len(packets_snapshot) >= 5:
            log.debug(
                "Suppressed zero-SYN traffic from %s: "
                "%d TCP packets to %d target(s) — all established connections",
                source_ip, len(packets_snapshot), len(unique_targets),
            )
            return

        # --- mDNS / local discovery suppression: traffic to the mDNS
        #     multicast address 224.0.0.251:5353 is Apple Bonjour, Android
        #     device discovery, Chromecast, Smart TV, etc., not scanning.
        #     If the only non-multicast target is a single LAN device and
        #     overall volume is low, it's benign local discovery. ---
        _has_mdns = any(
            p.destination_ip == "224.0.0.251" and p.destination_port == 5353
            for p in packets_snapshot
        )
        if _has_mdns:
            _non_mdns_targets = {
                p.destination_ip for p in packets_snapshot
                if p.destination_ip != "224.0.0.251"
            }
            if len(_non_mdns_targets) <= 2 and len(packets_snapshot) <= 60:
                log.debug(
                    "Suppressed mDNS/local discovery traffic from %s: "
                    "%d target(s) incl. 224.0.0.251, %d packets",
                    source_ip, len(unique_targets), len(packets_snapshot),
                )
                return

        # --- Private-LAN discovery suppression: low-volume traffic
        #     confined to RFC1918 private addresses (optionally plus
        #     multicast) is almost always security/AV software checking
        #     nearby devices, phone discovery, router monitoring, or
        #     other benign LAN activity — not reconnaissance.
        #     Works for both UDP and TCP (SYN,ACK responses to service
        #     discovery probes are not real scans). ---
        if (
            len(packets_snapshot) < 100
            and signals["rate"] < 10
        ):
            _all_private = True
            for p in packets_snapshot:
                try:
                    addr = ipaddress.ip_address(p.destination_ip)
                    if not (addr.is_private or addr.is_multicast):
                        _all_private = False
                        break
                except ValueError:
                    _all_private = False
                    break
            if _all_private:
                proto = "UDP" if not has_tcp else "TCP"
                log.debug(
                    "Suppressed private-LAN discovery traffic from %s: "
                    "%d %s packets to %d port(s) at %.1f pkt/sec",
                    source_ip, len(packets_snapshot), proto,
                    len(unique_ports), signals["rate"],
                )
                return

        # Skip cooldown window for same scan_type (preliminary check).
        classification = classify(signals)
        last = last_emit_snapshot.get(classification.scan_type)
        now = _now_naive()
        if last and (now - last).total_seconds() < _DETECTION_COOLDOWN:
            return

        # Build the Attack row.
        profile = profile_source(source_ip)
        tool_guess = fingerprint_tool(signals)
        explanation = explain_attack({
            "source_ip": source_ip,
            "source_asn": profile.asn,
            "source_tool_guess": tool_guess.tool,
            "scan_type": classification.scan_type,
            "rate": rate,
            "unique_ports": len(unique_ports),
            "unique_targets": len(unique_targets),
            "uses_ecn": signals["uses_ecn"],
            "tcp_completion_ratio": completion_ratio,
            "destination_ports": sorted(unique_ports),
            "unique_port_list": sorted(unique_ports),
        })
        first, last_time = packets_snapshot[0].timestamp, packets_snapshot[-1].timestamp
        duration = (last_time - first).total_seconds() or 1.0

        risk = assess(
            classification.scan_type,
            unique_ports=len(unique_ports),
            rate=rate,
            duration=duration,
            packet_count=len(packets_snapshot),
            unique_targets=len(unique_targets),
        )

        os_guess = "Unknown"
        os_confidence = 0
        os_reasons: list = []
        best: Optional["OSGuess"] = None
        for p in packets_snapshot:
            if not (p.flags.get("SYN") and not p.flags.get("ACK")):
                continue
            g = guess_os(
                {
                    "ttl": p.ttl,
                    "tcp_window": p.tcp_window,
                    "tcp_options": p.tcp_options,
                }
            )
            if best is None or g.confidence > best.confidence:
                best = g
        if best is not None:
            os_guess = best.guess
            os_confidence = best.confidence
            os_reasons = list(best.reasons)

        # Threat-intel enrichment (AbuseIPDB, opt-in).
        threat_intel = None
        if self.settings.threat_intel_enabled:
            try:
                threat_intel = check_ip(source_ip)
            except Exception as exc:
                # ponytail: warning — external dep failure, not a per-attack detail
                log.warning("Threat-intel check failed for %s: %s", source_ip, exc)

        # Boost risk score if threat-intel confirms malicious intent.
        risk_score = risk.score
        risk_level = risk.level
        if threat_intel and threat_intel.abuse_confidence_score >= 50:
            risk_score = min(10.0, risk_score + 1.0)
            if risk_score >= 8.0:
                risk_level = "critical"
            elif risk_score >= 6.0:
                risk_level = "high"

        attack = db.Attack(
            started_at=first,
            ended_at=last_time,
            duration_seconds=duration,
            source_ip=source_ip,
            source_mac=profile.mac,
            source_vendor=profile.vendor,
            source_hostname=profile.hostname,
            source_country=profile.country,
            source_isp=profile.isp,
            source_asn=profile.asn,
            source_os_guess=os_guess,
            source_os_confidence=os_confidence,
            source_tool_guess=tool_guess.tool,
            source_tool_confidence=tool_guess.confidence,
            source_tool_reasons_json=json.dumps(tool_guess.reasons[:50]),
            source_tool_negative_reasons_json=json.dumps(tool_guess.negative_reasons[:50]),
            explanation_name=explanation.name,
            explanation_category=explanation.category,
            explanation_confidence=explanation.confidence,
            explanation_evidence_json=json.dumps(
                [f"[+] {p}" for p in explanation.positive[:6]]
                + [f"[-] {n}" for n in explanation.negative[:6]]
            ),
            explanation_all_reasons_json=json.dumps(explanation.all_reasons),
            scan_type=classification.scan_type,
            scan_confidence=classification.confidence,
            packet_count=len(packets_snapshot),
            unique_ports=len(unique_ports),
            unique_targets=len(unique_targets),
            target_ports_json=json.dumps(sorted(unique_ports)[:200]),
            target_hosts_json=json.dumps(sorted(unique_targets)[:200]),
            risk_score=risk_score,
            risk_level=risk_level,
            threat_intel_json=json.dumps(threat_intel.to_dict()) if threat_intel else None,
            technique_signals_json=json.dumps(
                [f"{classification.scan_type} ({classification.confidence}%)"]
                + [f"signal: {t}" for t in tripped]
                + [f"tool: {tool_guess.tool} ({tool_guess.confidence}%)"]
                + [f"os: {os_guess} ({os_confidence}%)"]
            ),
        )

        # Final verification and emission under lock
        with self._lock:
            st = self._state.get(source_ip)
            if st is None or st.eval_seq != eval_seq:
                # Obsolete evaluation sequence, or the state was cleared.
                return
            
            # Recheck cooldown under lock to prevent race duplicate insertions
            last = st.last_emit.get(classification.scan_type)
            if last and (now - last).total_seconds() < _DETECTION_COOLDOWN:
                return
            st.last_emit[classification.scan_type] = now
            self._attack_count += 1

        # Persist + fire listeners + IPS action under a single guard.
        # Ponytail: don't let a transient DB failure kill listener/IPS too —
        # the attack object exists in memory and can still drive notifications.
        persisted = False
        try:
            with db.session_scope() as s:
                db.insert_attack(s, attack)
                s.flush()
                # Detach for listener use outside the session.
                s.expunge(attack)
            persisted = True
        except Exception as exc:
            log.error(
                "attack persistence FAILED for %s scan=%s risk=%s tool=%s attack_id=%s err=%s",
                attack.source_ip, attack.scan_type, attack.risk_level,
                attack.source_tool_guess, getattr(attack, "id", "?"), exc,
            )

        if persisted:
            log.info(
                "ATTACK #%d from %s — %s (risk=%s, tool=%s)",
                attack.id, attack.source_ip, attack.scan_type, attack.risk_level, attack.source_tool_guess,
            )
        for fn in list(self._listeners):
            try:
                fn(attack, signals)
            except Exception as exc:  # pragma: no cover
                log.warning("listener %r failed: %s", fn, exc)

        # --- IPS integration ---
        # Check IPS policy and create approval request if needed
        # Run even if DB persist failed — we still want to block the live attacker.
        if self.settings.ips_enabled:
            try:
                self._handle_ips_action(attack)
            except Exception:
                log.exception("IPS action failed for attack #%d (%s)", getattr(attack, "id", "?"), attack.source_ip)

    # -- introspection ----------------------------------------------------

    def summary(self) -> Dict:
        with self._lock:
            recent_attacks = []
            now = _now_naive()
            cutoff = now - timedelta(hours=1)
            with db.session_scope() as s:
                from sqlalchemy import select, desc
                rows = list(
                    s.scalars(
                        select(db.Attack)
                        .where(db.Attack.started_at >= cutoff)
                        .order_by(desc(db.Attack.started_at))
                        .limit(5)
                    )
                )
                recent_attacks = [
                    {
                        "id": a.id,
                        "source_ip": a.source_ip,
                        "scan_type": a.scan_type,
                        "risk_level": a.risk_level,
                        "started_at": a.started_at.isoformat() + "Z",
                    }
                    for a in rows
                ]
            return {
                "running": self._running,
                "mode": self._mode,
                "packet_count": self._packet_count,
                "attack_count": self._attack_count,
                "active_sources": len(self._state),
                "recent_attacks": recent_attacks,
            }

    def recent_packets(self, limit: int = 50) -> List[Dict]:
        """Return recent packets from the in-memory ring buffer (instant)."""
        with self._lock:
            packets = list(self._live_packets)[:limit]
        return packets

    def _handle_ips_action(self, attack: db.Attack) -> None:
        """Handle IPS action for a detected attack.

        Evaluates the attack against IPS policy and creates an approval
        request if needed. Auto-blocks critical threats immediately.
        Skips if the IP is already blocked, has a pending action, or was
        recently allowed.
        """
        from .approval_manager import get_approval_manager, ActionStatus
        from .firewall_manager import get_firewall_manager

        src = attack.source_ip

        # --- Skip if IP is already blocked ---
        firewall_mgr = get_firewall_manager()
        if firewall_mgr.is_blocked(src):
            log.debug("IPS: skipping %s — already blocked", src)
            return

        # --- Skip if IP is currently whitelisted (operator allowed) ---
        from .whitelist_manager import get_whitelist_manager
        if get_whitelist_manager().is_whitelisted(src):
            log.debug("IPS: skipping %s — whitelisted", src)
            return

        # --- Skip if IP already has a pending action ---
        approval_mgr = get_approval_manager()
        for pending in approval_mgr.list_pending():
            if pending.source_ip == src:
                log.debug("IPS: skipping %s — already has pending action %s", src, pending.id)
                return

        # --- Skip if IP was recently allowed or denied (within cooldown window) ---
        from datetime import datetime as _dt, timedelta as _td, timezone as _tz
        _now_utc = _dt.now(_tz.utc).replace(tzinfo=None)
        cooldown = _td(seconds=approval_mgr.timeout)
        for action in approval_mgr.list_all(limit=50):
            if (
                action.source_ip == src
                and action.status in (ActionStatus.APPROVED, ActionStatus.EXECUTED, ActionStatus.DENIED)
                and action.decided_at
            ):
                if (_now_utc - action.decided_at) < cooldown:
                    log.debug(
                        "IPS: skipping %s — recently %s by %s",
                        src, action.status.value, action.decided_by,
                    )
                    return

        # Evaluate IPS policy
        _settings = get_settings()
        ips_action = ips_evaluate(
            attack.risk_score,
            attack.scan_type,
            alert_only_max=_settings.ips_approval_threshold,
            auto_block_min=_settings.ips_auto_block_threshold,
        )
        log.info(
            "IPS evaluate: %s risk=%.1f type=%s -> action=%s",
            src, attack.risk_score, attack.scan_type, ips_action.action,
        )

        if ips_action.action == "alert":
            log.debug("IPS: alert only for %s (risk=%.1f)", src, attack.risk_score)
            return

        if ips_action.action == "auto_block":
            log.info(
                "IPS: auto-blocking %s — %s (risk=%.1f)",
                src, attack.scan_type, attack.risk_score,
            )
            firewall_mgr.block_ip(
                src,
                reason=f"Auto-blocked: {attack.scan_type} (risk={attack.risk_score:.1f})",
            )
            return

        if ips_action.action == "approve":
            log.info(
                "IPS: requesting approval for %s — %s (risk=%.1f)",
                src, attack.scan_type, attack.risk_score,
            )
            # Human-in-the-Loop: parse the port list (already a JSON column
            # on Attack) so the operator can see what was touched.
            try:
                import json as _json
                ports = list(_json.loads(attack.target_ports_json or "[]"))
            except Exception:
                ports = []
            try:
                import json as _json
                targets = list(_json.loads(attack.target_hosts_json or "[]"))
            except Exception:
                targets = []
            destination_ip = targets[0] if targets else ""
            action = approval_mgr.create_action(
                attack_id=attack.id,
                source_ip=src,
                destination_ip=destination_ip,
                threat_type=attack.scan_type,
                risk_score=attack.risk_score,
                risk_level=attack.risk_level,
                confidence=attack.scan_confidence,
                ports=ports,
                reason=ips_action.reason,
            )
            # Throttle while the decision is pending — see pending_rate_limiter.
            from .pending_rate_limiter import get_pending_rate_limiter
            get_pending_rate_limiter().mark_pending(src)
            log.info("IPS: created pending action %s for %s", action.id, src)


# ---------------------------------------------------------------------------
# Singleton helper
# ---------------------------------------------------------------------------

_engine: Optional[DetectionEngine] = None


def get_engine() -> DetectionEngine:
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
    return _engine
