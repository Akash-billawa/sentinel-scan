"""Packet capture (live + simulation).

Two implementations live here:

* :class:`LiveCapture` — uses Scapy's ``AsyncSniffer`` to consume a live
  network interface.  Requires Npcap on Windows and root on Linux.  If
  it cannot start, the engine falls back to simulation.

* :class:`SimulatorCapture` — generates realistic reconnaissance traffic
  from a curated catalogue of attacker profiles.  Used for demos,
  testing, and any environment where raw capture isn't possible.

Both implementations expose the same interface (``start()`` / ``stop()``)
and feed :class:`PacketRecord` objects into the detection engine.
"""

from __future__ import annotations

import logging
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .config import Settings, get_settings
from .detector import DetectionEngine, PacketRecord

log = logging.getLogger("sentinelscan.capture")


# ---------------------------------------------------------------------------
# Live capture (Scapy)
# ---------------------------------------------------------------------------


def resolve_scapy_interface(name_or_ip: str):
    """Resolve a human-readable interface name or IP address to a Scapy interface.

    Returns the Scapy interface object if resolved, otherwise None.
    """
    if not name_or_ip:
        return None
    try:
        from scapy.all import conf as scapy_conf
        name_or_ip_str = str(name_or_ip).strip()
        name_or_ip_lower = name_or_ip_str.lower()

        # 1. Match by exact IP address
        for key, iface in scapy_conf.ifaces.items():
            if getattr(iface, "ip", None) == name_or_ip_str:
                return iface

        # 2. Match by exact or substring name / description / network_name / GUID
        for key, iface in scapy_conf.ifaces.items():
            iface_name = (getattr(iface, "name", None) or "").lower()
            iface_desc = (getattr(iface, "description", None) or "").lower()
            iface_net = (getattr(iface, "network_name", None) or "").lower()
            iface_guid = (getattr(iface, "guid", None) or "").lower()
            if (name_or_ip_lower == iface_name or
                name_or_ip_lower == iface_net or
                name_or_ip_lower == iface_guid or
                name_or_ip_lower in iface_desc):
                return iface
    except Exception as exc:
        log.warning("Error resolving Scapy interface '%s': %s", name_or_ip, exc)
    return None


class LiveCapture:
    """Wrap Scapy's AsyncSniffer and feed the engine.

    Imported lazily so that systems without Scapy still work in
    simulation mode.  Supports multiple interfaces — a separate
    sniffer is started for each one (comma-separated in config).
    """

    def __init__(self, engine: DetectionEngine, settings: Optional[Settings] = None) -> None:
        self.engine = engine
        self.settings = settings or get_settings()
        self._sniffers = []  # list of AsyncSniffer instances
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self, interface: str = "") -> bool:
        try:
            from scapy.all import AsyncSniffer, conf as scapy_conf  # noqa: F401
        except Exception as exc:
            log.warning("Scapy not available: %s", exc)
            return False

        if not getattr(scapy_conf, "use_pcap", False):
            log.warning(
                "Live capture unavailable: no libpcap provider (Npcap/WinPcap on "
                "Windows, libpcap on Linux).  Install Npcap from https://npcap.com"
            )
            return False

        raw_iface = interface or self.settings.interface
        if not raw_iface and self.settings.host and self.settings.host not in {"0.0.0.0", "127.0.0.1", "localhost", "::", "::1"}:
            log.info("No interface specified; attempting to auto-resolve using host IP: %s", self.settings.host)
            raw_iface = self.settings.host

        # Support comma-separated interface list (e.g. "Wi-Fi,Ethernet 6").
        if raw_iface:
            interfaces = [i.strip() for i in raw_iface.split(",") if i.strip()]
        else:
            # If no interface is explicitly specified, auto-detect all active interfaces with a valid IP
            try:
                detected_interfaces = []
                for key, iface in scapy_conf.ifaces.items():
                    ip = getattr(iface, "ip", None)
                    desc = (getattr(iface, "description", None) or "").lower()
                    name = (getattr(iface, "name", None) or "").lower()
                    if ip and "miniport" not in desc and "loopback" not in name and ip != "127.0.0.1" and not ip.startswith("169.254."):
                        detected_interfaces.append(iface)
                if detected_interfaces:
                    log.info("No interface specified; auto-detected active interfaces: %s", [getattr(i, 'name', str(i)) for i in detected_interfaces])
                    interfaces = detected_interfaces
                else:
                    interfaces = [""]
            except Exception as exc:
                log.warning("Failed to auto-detect active interfaces: %s. Using default interface.", exc)
                interfaces = [""]

        for iface_name in interfaces:
            iface = None
            if iface_name:
                resolved = resolve_scapy_interface(iface_name)
                if resolved:
                    log.info("Resolved interface: %s -> %s (%s)", iface_name, resolved.name, resolved.network_name)
                    iface = resolved
                else:
                    log.warning("Could not resolve interface '%s' to a Scapy interface. Trying as-is.", iface_name)
                    iface = iface_name

            iface_str = getattr(iface, "name", None) or str(iface) if iface else "default interface"
            try:
                sniffer = AsyncSniffer(
                    iface=iface,
                    prn=self._on_packet,
                    store=False,
                    filter="ip or ip6",
                )
                sniffer.start()
                self._sniffers.append(sniffer)
                log.info("Capture started on interface: %s", iface_str)
            except Exception as exc:
                log.warning(
                    "Capture failed on interface %s: %s — check Npcap installation "
                    "and interface name",
                    iface_str, exc,
                )

        if not self._sniffers:
            return False

        self._running = True

        # Liveness check: sniffer threads can die on first packet if the
        # interface is wrong or the driver refused.
        time.sleep(0.25)
        alive = []
        for s in self._sniffers:
            t = getattr(s, "thread", None)
            if t is not None and t.is_alive():
                alive.append(s)
            else:
                log.warning("Capture sniffer thread died — dropping that interface")
        self._sniffers = alive
        if not self._sniffers:
            log.error("All capture threads died; check Npcap installation")
            self._running = False
            return False
        log.info("Live capture started on %d interface(s)", len(self._sniffers))
        return True

    def stop(self) -> None:
        for s in self._sniffers:
            try:
                s.stop()
            except Exception as exc:  # pragma: no cover
                log.debug("sniffer.stop error: %s", exc)
        self._sniffers.clear()
        self._running = False
        log.info("Live capture stopped")

    # -- callback --------------------------------------------------------

    def _on_packet(self, pkt) -> None:
        try:
            from scapy.all import IP, TCP, UDP, ICMP, IPv6
        except Exception:
            return

        if IP not in pkt:
            return

        ip_layer = pkt[IP]
        proto = "OTHER"
        flags: dict = {}
        sport = 0
        dport = 0
        tcp_window = None
        tcp_options: dict = {}

        if TCP in pkt:
            t = pkt[TCP]
            proto = "TCP"
            sport = int(t.sport)
            dport = int(t.dport)
            tcp_window = int(t.window)
            # Decode flag bits.
            flag_names = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")
            for i, name in enumerate(flag_names):
                if t.flags & (1 << i):
                    flags[name] = True
            # Only extract TCP options from SYN-only packets.  SYN+ACK
            # options reflect the *responder's* OS (us), not the
            # scanner's, so including them would contaminate the
            # fingerprinter with the operator's own OS.  See the
            # "contamination" note in backend/fingerprinter.py.
            if flags.get("SYN") and not flags.get("ACK"):
                tcp_options = _extract_tcp_options(t)
        elif UDP in pkt:
            u = pkt[UDP]
            proto = "UDP"
            sport = int(u.sport)
            dport = int(u.dport)
        elif ICMP in pkt:
            proto = "ICMP"
        else:
            return

        ip_flags = int(getattr(ip_layer, "flags", 0))
        ip_frag = int(getattr(ip_layer, "frag", 0))
        is_fragment = bool(ip_flags & 0x4) or ip_frag > 0

        record = PacketRecord(
            timestamp=_now(),
            source_ip=ip_layer.src,
            destination_ip=ip_layer.dst,
            source_port=sport,
            destination_port=dport,
            protocol=proto,
            flags=flags,
            tcp_window=tcp_window,
            ttl=int(ip_layer.ttl),
            length=int(len(pkt)),
            tcp_options=tcp_options,
            is_fragment=is_fragment,
        )
        self.engine.feed_packet(record)


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------


# Catalogues of fictional attackers the simulator draws from.  Each
# profile mirrors a real-world tool's pacing and TCP flag mix.
_ATTACKER_PROFILES = [
    {
        "name": "nmap-pro",
        "tool": "Nmap",
        "scan_type": "SYN Scan (Stealth)",
        "protocol": "TCP",
        "flags": {"SYN": True},
        "ports": "common",
        "target_count": 1,
        "packet_count": 80,
        "delay_range": (0.01, 0.05),
        "ttl": 64,
        "tcp_window": 29200,
        "tcp_options": {"mss": 1460, "wscale": 7, "timestamp": True,
                        "sack_perm": True, "nop": 2},
    },
    {
        "name": "masscan-pro",
        "tool": "Masscan",
        "scan_type": "Mass Scan",
        "protocol": "TCP",
        "flags": {"SYN": True},
        "ports": "top1000",
        "target_count": 1,
        "packet_count": 1500,
        "delay_range": (0.0001, 0.0006),
        "ttl": 64,
        "tcp_window": 65535,
        "tcp_options": {"mss": 1460},
    },
    {
        "name": "angry-ip",
        "tool": "Angry IP Scanner",
        "scan_type": "Ping Sweep",
        "protocol": "ICMP",
        "flags": {},
        "ports": "none",
        "target_count": 40,
        "packet_count": 60,
        "delay_range": (0.02, 0.08),
        "ttl": 64,
        "tcp_window": 65535,
        "tcp_options": {"mss": 1460, "sack_perm": True, "nop": 1},
    },
    {
        "name": "xmas-pro",
        "tool": "Custom Scanner",
        "scan_type": "Xmas Scan",
        "protocol": "TCP",
        "flags": {"FIN": True, "PSH": True, "URG": True},
        "ports": "common",
        "target_count": 1,
        "packet_count": 40,
        "delay_range": (0.05, 0.2),
        "ttl": 64,
        "tcp_window": 29200,
        "tcp_options": {"mss": 1460, "wscale": 7, "sack_perm": True, "nop": 1},
    },
    {
        "name": "null-pro",
        "tool": "Nmap",
        "scan_type": "NULL Scan",
        "protocol": "TCP",
        "flags": {},
        "ports": "common",
        "target_count": 1,
        "packet_count": 35,
        "delay_range": (0.05, 0.2),
        "ttl": 64,
        "tcp_window": 29200,
        "tcp_options": {"mss": 1460, "wscale": 7, "sack_perm": True, "nop": 1},
    },
    {
        "name": "fin-pro",
        "tool": "Nmap",
        "scan_type": "FIN Scan",
        "protocol": "TCP",
        "flags": {"FIN": True},
        "ports": "common",
        "target_count": 1,
        "packet_count": 30,
        "delay_range": (0.05, 0.2),
        "ttl": 255,
        "tcp_window": 4128,
        "tcp_options": {"mss": 1460},
    },
    {
        "name": "udp-pro",
        "tool": "Nmap",
        "scan_type": "UDP Scan",
        "protocol": "UDP",
        "flags": {},
        "ports": "udp_top",
        "target_count": 1,
        "packet_count": 50,
        "delay_range": (0.05, 0.2),
        "ttl": 64,
        "tcp_window": None,
        "tcp_options": {},
    },
    {
        "name": "serviceenum",
        "tool": "Nmap",
        "scan_type": "Service Enumeration",
        "protocol": "TCP",
        "flags": {"SYN": True, "ACK": True},
        "ports": "top200",
        "target_count": 1,
        "packet_count": 220,
        "delay_range": (0.02, 0.08),
        "ttl": 128,
        "tcp_window": 65535,
        "tcp_options": {"mss": 1460, "wscale": 8, "sack_perm": True, "nop": 2},
    },
    {
        "name": "icmp-sweep",
        "tool": "Angry IP Scanner",
        "scan_type": "Ping Sweep",
        "protocol": "ICMP",
        "flags": {},
        "ports": "none",
        "target_count": 60,
        "packet_count": 70,
        "delay_range": (0.01, 0.04),
        "ttl": 64,
        "tcp_window": None,
        "tcp_options": {},
    },
    {
        "name": "frag-scan",
        "tool": "Nmap",
        "scan_type": "Fragmented Scan",
        "protocol": "TCP",
        "flags": {"SYN": True},
        "ports": "common",
        "target_count": 1,
        "packet_count": 60,
        "delay_range": (0.03, 0.08),
        "ttl": 64,
        "tcp_window": 512,
        "tcp_options": {"mss": 1460, "wscale": 7, "timestamp": True,
                        "sack_perm": True, "nop": 2},
        "fragmented": True,
    },
]


# Validate every profile at module load.  Fail loud, not silent: a
# missing field here would degrade the OS guesser to "Linux/Unix" for
# every scan and the operator would see the dashboard regress without
# an obvious cause.
_REQUIRED_PROFILE_KEYS = ("ttl", "tcp_window", "tcp_options")
for _prof in _ATTACKER_PROFILES:
    _missing = [k for k in _REQUIRED_PROFILE_KEYS if k not in _prof]
    if _missing:
        log.warning(
            "simulator profile %r is missing required key(s) %s — "
            "OS guesser will fall back to TTL-only heuristics for this profile",
            _prof.get("name", "<unnamed>"), _missing,
        )

_FAKE_IPS = [
    "192.168.1.50",  # local attacker
    "10.0.0.137",    # another local attacker
    "103.42.91.18",  # India / Airtel
    "117.247.108.4", # India / Jio
    "185.220.101.7", # Tor exit-ish
    "198.51.100.23", # RFC 5737
    "13.232.45.9",   # AWS
    "8.8.8.8",       # Google (will look suspicious in the dashboard)
]

_LOCAL_TARGETS = ["192.168.1.10", "192.168.1.11", "192.168.1.20"]
_RANDOM_TARGETS = [
    "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9",
    "192.168.1.1", "192.168.1.2", "192.168.1.3",
]


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(tzinfo=None)


def _extract_tcp_options(tcp_layer) -> dict:
    """Pull the SYN-significant TCP options out of a Scapy TCP layer.

    Scapy's ``pkt[TCP].options`` is a list of tuples; for each entry the
    first element is the option name and the second is the value
    (or ``None`` for padding options like NOP / EOL).  We normalise
    the layout to the small dict used by :class:`PacketRecord`:

    * ``mss``        — int  (MSS option)
    * ``wscale``     — int  (Window Scale option)
    * ``timestamp``  — bool (Timestamp option present)
    * ``sack_perm``  — bool (SACK-Permitted option present)
    * ``nop``        — int  (count of NOP pad bytes — useful for layout matching)
    * ``eol``        — bool (End Of Option List)

    Unknown options are ignored silently.  Returning an empty dict is
    fine and means "no options observed".
    """
    out: dict = {}
    try:
        opts = tcp_layer.options or []
    except Exception:
        return out
    for entry in opts:
        if not entry:
            continue
        name = entry[0]
        val = entry[1] if len(entry) > 1 else None
        if name == "MSS":
            try:
                out["mss"] = int(val)
            except (TypeError, ValueError):
                pass
        elif name == "WScale":
            try:
                out["wscale"] = int(val)
            except (TypeError, ValueError):
                pass
        elif name == "Timestamp":
            out["timestamp"] = True
        elif name == "SAckOK":
            out["sack_perm"] = True
        elif name == "NOP":
            out["nop"] = out.get("nop", 0) + 1
        elif name == "EOL":
            out["eol"] = True
        # Other options (SACK block, ECN-related, …) ignored.
    return out


def _ports_for(name: str) -> List[int]:
    if name == "common":
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]
    if name == "top1000":
        return list(range(1, 1001))
    if name == "top200":
        return list(range(1, 201))
    if name == "udp_top":
        return [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 1701, 1900, 4500, 5353]
    return []


class SimulatorCapture:
    """Generate realistic reconnaissance traffic against the engine."""

    def __init__(self, engine: DetectionEngine, settings: Optional[Settings] = None) -> None:
        self.engine = engine
        self.settings = settings or get_settings()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._intensity: float = 1.0  # 0 = quiet, 2 = busy
        self._lock = threading.Lock()

    def start(self) -> bool:
        if self._running:
            return True
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="sim-capture", daemon=True)
        self._thread.start()
        log.info("Simulator capture started")
        return True

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        log.info("Simulator capture stopped")

    def set_intensity(self, value: float) -> None:
        """Scale the traffic rate: 0=quiet, 1=normal, 2=busy."""

        with self._lock:
            self._intensity = max(0.0, min(value, 3.0))

    def _emit_attack(self, profile: dict) -> None:
        src = random.choice(_FAKE_IPS)
        target_count = profile["target_count"]
        targets = (
            random.sample(_LOCAL_TARGETS, min(target_count, len(_LOCAL_TARGETS)))
            if target_count <= len(_LOCAL_TARGETS)
            else random.sample(_RANDOM_TARGETS, min(target_count, len(_RANDOM_TARGETS)))
        )
        ports = _ports_for(profile["ports"])
        pkt_count = profile["packet_count"]
        delays = profile["delay_range"]
        flags = profile["flags"]
        proto = profile["protocol"]
        ttl = profile["ttl"]
        # Per-profile TCP window and option layout.  Profiles that don't
        # set these (e.g. UDP/ICMP) get None/{} which the detector treats
        # as "no signal".  The window is fixed per profile so the OS
        # guesser sees a consistent signature across the burst.
        tcp_window = profile.get("tcp_window")
        tcp_options = dict(profile.get("tcp_options") or {})
        is_fragment = profile.get("fragmented", False)

        if profile["ports"] == "none":
            # ICMP / ping sweep — one packet per host.
            for dst in targets:
                if not self._running:
                    return
                self.engine.feed_packet(
                    PacketRecord(
                        timestamp=_now(),
                        source_ip=src,
                        destination_ip=dst,
                        source_port=random.randint(1024, 65535),
                        destination_port=0,
                        protocol=proto,
                        flags=dict(flags),
                        tcp_window=None,
                        ttl=ttl,
                        length=84,
                        tcp_options={},
                        is_fragment=is_fragment,
                    )
                )
                time.sleep(random.uniform(*delays) / max(self._intensity, 0.1))
            return

        # Distribute packets across targets.
        per_target = max(1, pkt_count // max(len(targets), 1))
        for dst in targets:
            for _ in range(per_target):
                if not self._running:
                    return
                dport = random.choice(ports) if ports else random.randint(1, 1024)
                sport = random.randint(40000, 65535)
                length = random.randint(40, 80)
                # Simulate a small number of TCP completions for connect-scans.
                if proto == "TCP" and profile["scan_type"] == "Service Enumeration" and random.random() < 0.5:
                    pkt_flags = {"SYN": True, "ACK": True}
                elif proto == "TCP" and profile["scan_type"] == "TCP Connect Scan" and random.random() < 0.3:
                    pkt_flags = {"SYN": True, "ACK": True}
                else:
                    pkt_flags = dict(flags)

                self.engine.feed_packet(
                    PacketRecord(
                        timestamp=_now(),
                        source_ip=src,
                        destination_ip=dst,
                        source_port=sport,
                        destination_port=dport,
                        protocol=proto,
                        flags=pkt_flags,
                        tcp_window=tcp_window,
                        ttl=ttl,
                        length=length,
                        # Only SYN-only packets carry options (the
                        # detector uses them for OS / tool
                        # fingerprinting); other packets contribute
                        # nothing to that signal.
                        tcp_options=tcp_options if (
                            pkt_flags.get("SYN") and not pkt_flags.get("ACK")
                        ) else {},
                        is_fragment=is_fragment,
                    )
                )
                time.sleep(random.uniform(*delays) / max(self._intensity, 0.1))

    def _loop(self) -> None:
        # Bootstrap: emit one attack every few seconds, faster when busy.
        while self._running:
            try:
                with self._lock:
                    intensity = self._intensity
                # Choose an attacker profile, weighted slightly.
                profile = random.choice(_ATTACKER_PROFILES)
                self._emit_attack(profile)

                # Small inter-attack pause — shorter when busy.
                pause = random.uniform(0.5, 3.0) / max(intensity, 0.3)
                # Cap to keep the loop responsive to stop() calls.
                pause = min(pause, 4.0)
                slept = 0.0
                while self._running and slept < pause:
                    time.sleep(0.2)
                    slept += 0.2
            except Exception as exc:  # pragma: no cover
                log.exception("simulator loop error: %s", exc)
                time.sleep(1.0)


# ---------------------------------------------------------------------------
# Top-level helper
# ---------------------------------------------------------------------------


def start_capture(
    engine: DetectionEngine,
    mode: str = "auto",
    interface: str = "",
) -> tuple:
    """Start a capture module and return ``(capture, actual_mode)``.

    ``mode`` is one of ``live``, ``sim``, ``auto``.  ``auto`` tries live
    capture first and falls back to simulation on failure.
    """

    if mode == "sim":
        sim = SimulatorCapture(engine)
        sim.start()
        return sim, "sim"

    if mode == "live":
        live = LiveCapture(engine)
        if live.start(interface):
            return live, "live"
        raise RuntimeError("Live capture could not start (Npcap / privileges missing?)")

    # auto
    live = LiveCapture(engine)
    if live.start(interface):
        return live, "live"
    log.info("Falling back to simulation mode")
    sim = SimulatorCapture(engine)
    sim.start()
    return sim, "sim"
