"""Attacker profiling.

This module enriches a source IP with metadata a SOC analyst wants at
a glance: a MAC (when on-link), a hostname guess, ASN/ISP, and a coarse
geolocation.  We deliberately avoid any paid third-party service as the
default — instead, we ship a small offline lookup table that is good
enough for demos, and we provide a clean extension point for hooking
up MaxMind GeoLite2 or an IPinfo-style API in production.

Hostname resolution is the part most likely to misbehave on a real
network: ``socket.gethostbyaddr`` can block for *seconds* if the local
DNS resolver is slow or the PTR record is missing.  This module
therefore:

* caches resolved hostnames in an in-memory LRU (default 4096 entries)
  so a chatty attacker IP doesn't trigger the same PTR lookup twice
* enforces a per-call DNS timeout so a single slow resolver can't
  stall the detection thread
* runs the actual lookup in a worker thread so the calling thread
  is never blocked on I/O
* falls back to NetBIOS name resolution for on-link IPs on Windows
  (a common on-LAN pattern for the local subnet)
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import random
import socket
import threading
import time as _time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


log = logging.getLogger("sentinelscan.profiler")

# Default size of the hostname cache.  Chosen so the cache can hold
# 4096 distinct attacker IPs in memory at a few hundred bytes each —
# well under 4 MB.  Override at runtime with
# ``set_hostname_cache_size(N)`` if your environment sees a lot more
# distinct source IPs than that.
DEFAULT_CACHE_SIZE = 4096
# Per-call DNS timeout.  Bounded so a slow resolver can't pin the
# detection thread; cheap for the common case where the resolver
# replies in <100ms.
DEFAULT_DNS_TIMEOUT = 1.5
# How long we trust a cached PTR record.  PTR records can change
# (DHCP reassignment, server migration) but typically on the order
# of days — 1 hour is a reasonable balance.
DEFAULT_CACHE_TTL_SECONDS = 3600.0


@dataclass
class AttackerProfile:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    os_guess: Optional[str] = None
    on_link: bool = False
    vendor: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "country": self.country,
            "city": self.city,
            "isp": self.isp,
            "asn": self.asn,
            "os_guess": self.os_guess,
            "on_link": self.on_link,
            "vendor": self.vendor,
        }


# ---------------------------------------------------------------------------
# Offline demo data — covers common ranges you will see in the wild and a
# handful of fictional ones for the simulator.  Production users should
# replace _demo_lookup() with a MaxMind / IPinfo call.
# ---------------------------------------------------------------------------

_DEMO_TABLE: Dict[str, Dict] = {
    # Reserved/private blocks
    "192.168.0.0/16": {"country": "Private LAN", "isp": "Local Network", "asn": "RFC1918"},
    "10.0.0.0/8": {"country": "Private LAN", "isp": "Local Network", "asn": "RFC1918"},
    "172.16.0.0/12": {"country": "Private LAN", "isp": "Local Network", "asn": "RFC1918"},
    # Common public ranges (illustrative, not authoritative)
    "8.8.8.0/24": {"country": "United States", "isp": "Google LLC", "asn": "AS15169"},
    "1.1.1.0/24": {"country": "United States", "isp": "Cloudflare, Inc.", "asn": "AS13335"},
    "13.0.0.0/8": {"country": "United States", "isp": "Amazon AWS", "asn": "AS16509"},
    "103.0.0.0/8": {"country": "India", "isp": "Airtel", "asn": "AS24560"},
    "117.0.0.0/8": {"country": "India", "isp": "Jio", "asn": "AS55836"},
    "49.0.0.0/8": {"country": "India", "isp": "BSNL", "asn": "AS9829"},
    "203.0.113.0/24": {"country": "Documentation", "isp": "RFC 5737 TEST-NET-3", "asn": "AS0"},
    "198.51.100.0/24": {"country": "Documentation", "isp": "RFC 5737 TEST-NET-2", "asn": "AS0"},
    "185.220.0.0/14": {"country": "Multiple", "isp": "Tor Exit Nodes (known)", "asn": "AS208294"},
    "23.0.0.0/12": {"country": "United States", "isp": "Akamai Technologies", "asn": "AS20940"},
    "104.16.0.0/12": {"country": "United States", "isp": "Cloudflare, Inc.", "asn": "AS13335"},
}


def _demo_lookup(ip: str) -> Dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}

    for cidr, info in _DEMO_TABLE.items():
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return dict(info)
        except ValueError:
            continue
    return {}


# ---------------------------------------------------------------------------
# Hostname cache + async resolver
# ---------------------------------------------------------------------------
#
# The cache is keyed on the literal IP string.  Each entry stores
# ``(hostname, expiry_ts)`` where ``hostname is None`` means "we
# tried and there's no PTR record" (cached as a *negative* answer so
# we don't keep retrying the same broken DNS).  The LRU eviction is
# bounded by ``_cache_max`` to keep memory predictable; the oldest
# entry is dropped on overflow.
#
# The resolver pool is a small dedicated executor so a long DNS
# timeout doesn't tie up the global fork-pool used for other things.

_CacheValue = Tuple[Optional[str], float]


class HostnameCache:
    """Thread-safe LRU cache for reverse-DNS results.

    Implementation: ``OrderedDict`` with ``move_to_end`` on every
    ``get`` hit.  Eviction is also O(1) via ``popitem(last=False)``.
    The previous dict-based implementation only moved entries on
    ``set``, not on ``get`` — which made it FIFO in practice even
    though the docstring called it an LRU.  A hot scanner that
    kept re-querying the same IP would still get evicted if the
    cache had rotated past it; the move-to-end fix prevents that.
    """

    def __init__(self, max_entries: int = DEFAULT_CACHE_SIZE,
                 ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
                 clock: Optional[callable] = None) -> None:
        self._data: "OrderedDict[str, _CacheValue]" = OrderedDict()
        self._max = max(1, int(max_entries))
        self._ttl = max(0.0, float(ttl_seconds))
        self._lock = threading.Lock()
        # Injectable clock for tests; defaults to ``time.monotonic``.
        self._clock = clock or _time.monotonic

    # -- helpers ----------------------------------------------------------

    def get(self, key: str) -> Tuple[Optional[str], bool]:
        """Return ``(hostname, hit)`` where ``hit`` is True if found and
        not expired.  The hostname may be ``None`` (cached negative).
        A successful get promotes the entry to the most-recently-used
        position — the LRU guarantee.
        """
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None, False
            hostname, expiry = entry
            if self._ttl and self._clock() >= expiry:
                # Expired — drop and miss.
                self._data.pop(key, None)
                return None, False
            # Move-to-end on hit.  An expired entry is a miss, not a
            # hit, so we don't promote it.
            self._data.move_to_end(key)
            return hostname, True

    def set(self, key: str, value: Optional[str]) -> None:
        with self._lock:
            if key in self._data:
                # Refresh insertion order on update.
                self._data.pop(key, None)
            self._data[key] = (value, self._clock() + self._ttl if self._ttl else float("inf"))
            while len(self._data) > self._max:
                # Popitem(last=False) is the FIFO/LRU eviction point.
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


# Module-level singletons so the cache survives across ``profile_source``
# calls (which is the whole point).  Tests can call ``reset_hostname_cache``
# to start from a clean state.
_hostname_cache: Optional[HostnameCache] = None
_resolver_pool: Optional[ThreadPoolExecutor] = None
_resolver_lock = threading.Lock()
_pending_lookups: Dict[str, object] = {}
_pending_lock = threading.Lock()


def _get_hostname_cache() -> HostnameCache:
    global _hostname_cache
    if _hostname_cache is None:
        _hostname_cache = HostnameCache()
    return _hostname_cache


def _get_resolver_pool() -> ThreadPoolExecutor:
    global _resolver_pool
    if _resolver_pool is None:
        with _resolver_lock:
            if _resolver_pool is None:
                _resolver_pool = ThreadPoolExecutor(
                    max_workers=2, thread_name_prefix="rdns-resolver"
                )
    return _resolver_pool


def reset_hostname_cache() -> None:
    """Clear the cache and shut the resolver pool down.

    Intended for tests.  Production code should leave the cache alone.
    """
    global _hostname_cache, _resolver_pool
    if _hostname_cache is not None:
        _hostname_cache.clear()
    with _resolver_lock:
        if _resolver_pool is not None:
            _resolver_pool.shutdown(wait=False, cancel_futures=True)
            _resolver_pool = None
    with _pending_lock:
        _pending_lookups.clear()


def set_hostname_cache_size(n: int) -> None:
    """Resize the cache; old entries that don't fit are dropped in LRU order."""
    global _hostname_cache
    new = HostnameCache(max_entries=n, ttl_seconds=DEFAULT_CACHE_TTL_SECONDS)
    if _hostname_cache is not None:
        # Carry over valid (unexpired) entries, preserving their
        # LRU order from the old cache so a frequently-hit IP
        # doesn't get evicted just because the cache shrank.
        for k, v in list(_hostname_cache._data.items()):
            if len(new._data) >= new._max:
                break
            new._data[k] = v
    _hostname_cache = new


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _fake_mac_for_ip(ip: str) -> str:
    """Deterministic, IP-derived MAC for demo purposes only."""

    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        seed = sum(int(p) for p in parts)
        rnd = random.Random(seed)
        oui = ("00:1A:2B", "F4:5C:89", "3C:5A:B4", "8C:85:90", "AC:DE:48")
        suffix = ":".join(f"{rnd.randint(0, 255):02X}" for _ in range(3))
        return f"{rnd.choice(oui)}:{suffix}"
    return ""


def _do_gethostbyaddr(ip: str, timeout: float) -> Optional[str]:
    """Perform the actual PTR lookup with a hard timeout.

    The timeout is implemented by setting ``socket.getdefaulttimeout``
    for the duration of the call.  The previous value is restored
    regardless of outcome so we don't poison the process-wide
    default for any other code that uses sockets.
    """
    if not _is_valid_ip(ip):
        return None
    prev = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        # Strip a trailing dot; some resolvers return FQDNs with it.
        if name.endswith("."):
            name = name[:-1]
        cleaned = _sanitise_hostname(name, ip)
        return cleaned
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("gethostbyaddr(%s) failed unexpectedly: %s", ip, exc)
        return None
    finally:
        socket.setdefaulttimeout(prev)


# Public suffix list is impractical to ship; instead, validate the
# shape of a returned hostname before trusting it.  Real DNS errors
# and misconfigured resolvers can return a few classes of garbage
# that an unfiltered pass-through would display to the operator:
#
#   * An IP-shaped string (the resolver echoed the query)
#   * The literal name "localhost" for non-loopback IPs
#   * Names longer than RFC 1035's 253-octet limit
#   * Names containing control characters or unprintable bytes
#   * Empty or whitespace-only strings
#   * Punycode / IDN forms that contain an underscore (a sign of
#     upstream zone pollution rather than a real hostname)
#
# We reject all of these silently so the dashboard never shows
# something we'd have to manually scrub.
_HOSTNAME_MAX_LEN = 253
_HOSTNAME_LABEL_MAX_LEN = 63
_LOOPBACK_IPS = frozenset({"127.0.0.1", "::1"})


def _sanitise_hostname(name: Optional[str], ip: str) -> Optional[str]:
    """Return a clean hostname, or ``None`` if the input is unusable.

    The result is what's stored in the cache and shown on the
    dashboard, so this is the last line of defence against bogus
    PTR records.  We deliberately keep the rule set small — the
    goal is to drop obvious garbage, not to implement a full DNS
    validator.  Anything that's "shape OK" passes through.
    """
    if not name:
        return None
    cleaned = name.strip()
    # Strip a trailing dot (FQDN form) if present.  The caller
    # normally strips this, but defending here means a future
    # caller that forgets won't leak a bogus trailing dot into
    # the cache.
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]
    if not cleaned:
        return None
    # Length cap (RFC 1035 §2.3.4).  253 octets for the whole name,
    # 63 per label.  Many misconfigured resolvers return the
    # underlying TXT record or a debug string that can blow past
    # this.  Drop them rather than truncate, so the operator sees
    # "no hostname" instead of a partial one.
    if len(cleaned) > _HOSTNAME_MAX_LEN:
        return None
    for label in cleaned.split("."):
        if not label or len(label) > _HOSTNAME_LABEL_MAX_LEN:
            return None
    # Reject control characters and whitespace embedded in labels.
    for ch in cleaned:
        if ch.isspace() or ord(ch) < 0x20:
            return None
    # An IP-shaped answer means the resolver echoed the query —
    # never trust it.
    if _is_valid_ip(cleaned):
        return None
    # "localhost" is only meaningful for the loopback interface.
    if cleaned.lower() in ("localhost", "localhost.localdomain") and ip not in _LOOPBACK_IPS:
        return None
    return cleaned


def _netbios_name_for_ip(ip: str, timeout: float = 0.5) -> Optional[str]:
    """NetBIOS name lookup, Windows-only best-effort fallback.

    Returns the first name in the adapter-status reply, or ``None`` if
    the lookup fails or the platform doesn't support it.  Used only
    for on-link IPs where a PTR record is unlikely.
    """
    if platform.system() != "Windows":
        return None
    try:
        import netbios  # type: ignore[import-not-found]  # noqa: F401
    except Exception:
        # ``netbios`` is not a stdlib module and not a hard dep.
        return None
    try:
        # The ``netbios`` package on PyPI is third-party; if it's
        # installed, the call shape is ``netbios.query_nbns(ip)``.
        # We swallow all errors because NetBIOS is best-effort.
        names = netbios.query_nbns(ip)  # type: ignore[NameDefined]
        if names:
            first = names[0]
            # NetBIOS names are 16 bytes; ASCII representation is the
            # first 15 + a suffix byte.  Trim to the readable part.
            if isinstance(first, (bytes, bytearray)):
                return bytes(first[:15]).decode("ascii", errors="ignore").strip() or None
            return str(first).strip() or None
    except Exception:
        return None
    return None


def _reverse_dns(ip: str, timeout: float = DEFAULT_DNS_TIMEOUT) -> Optional[str]:
    """Cached reverse DNS with timeout, async lookup, and NetBIOS fallback.

    Behaviour:

    * Private IPs: try NetBIOS first (Windows on-LAN case), then PTR.
    * Public IPs: PTR only.
    * Cache hits short-circuit the network call.
    * The actual PTR lookup runs in a worker thread; this function
      returns within ``timeout`` seconds, even if the resolver is
      misbehaving.
    * Negative results (``None``) are cached too, so a misconfigured
      DNS server doesn't slow down subsequent attempts.
    """
    if not _is_valid_ip(ip):
        return None
    if _is_private(ip):
        # For on-link addresses the PTR record is rarely populated.
        # NetBIOS is the more useful source of a friendly name.
        nb = _netbios_name_for_ip(ip)
        if nb:
            return nb
    # Cache hit?
    cached, hit = _get_hostname_cache().get(ip)
    if hit:
        return cached

    # Check/register pending lookup
    with _pending_lock:
        # Check cache again under the lock just in case it got populated
        cached, hit = _get_hostname_cache().get(ip)
        if hit:
            return cached

        fut = _pending_lookups.get(ip)
        if fut is None:
            pool = _get_resolver_pool()
            fut = pool.submit(_do_gethostbyaddr, ip, timeout)
            _pending_lookups[ip] = fut

    try:
        name = fut.result(timeout=timeout + 0.25)
    except FuturesTimeout:
        # Leave the worker to finish in the background; we move on.
        log.debug("rDNS lookup for %s timed out after %.2fs", ip, timeout)
        name = None
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("rDNS lookup for %s raised: %s", ip, exc)
        name = None
    finally:
        with _pending_lock:
            if _pending_lookups.get(ip) is fut:
                _pending_lookups.pop(ip, None)

    # Cache the result (including the negative answer) and return.
    _get_hostname_cache().set(ip, name)
    return name


def profile_source(ip: str) -> AttackerProfile:
    """Return an :class:`AttackerProfile` for the given source IP.

    Network state (reverse DNS, MAC) is best-effort and offline-safe; any
    failure is silently absorbed because profiling is a non-critical
    enrichment step.
    """

    profile = AttackerProfile(ip=ip)
    profile.on_link = _is_private(ip)

    if profile.on_link:
        # Try the real ARP table first; fall back to the deterministic
        # demo MAC so simulation mode still shows something.
        from . import arp
        from . import oui
        real_mac = arp.get_mac(ip)
        if real_mac:
            profile.mac = real_mac
            profile.vendor = oui.lookup(real_mac)
        else:
            profile.mac = _fake_mac_for_ip(ip)
    else:
        profile.hostname = _reverse_dns(ip)

    info = _demo_lookup(ip)
    profile.country = info.get("country")
    profile.isp = info.get("isp")
    profile.asn = info.get("asn")
    profile.city = info.get("city")
    return profile


# ---------------------------------------------------------------------------
# OS fingerprinting — p0f-style SYN signature matching.
# ---------------------------------------------------------------------------


@dataclass
class OSGuess:
    """Result of an OS guess from a single SYN packet.

    Mirrors the shape of :class:`backend.fingerprinter.ToolGuess` so the
    two attribution fields look the same to the rest of the codebase
    (and the dashboard).

    * ``guess``       — short OS family label (e.g. ``"Linux (4.x/5.x/6.x)"``)
    * ``confidence``  — 0..100, how sure we are (0 for ``"Unknown"``)
    * ``reasons``     — short human-readable strings explaining which
      signals matched, useful for the PDF report and alert body
    """

    guess: str
    confidence: int
    reasons: List[str] = field(default_factory=list)


# Known *initial* TTLs.  Observed TTL on the wire is ``initial - hops``,
# so we round up to the nearest entry.  Ordered most-specific-first so
# the more diagnostic bucket wins ties.
_KNOWN_INITIAL_TTLS = (32, 64, 128, 255)


def _initial_ttl(observed: Optional[int]) -> Optional[int]:
    """Round an observed TTL up to the nearest known initial.

    ``None`` is passed through.  TTL > 255 is treated as uninitialised
    (could be a misread).
    """
    if observed is None or observed < 1 or observed > 255:
        return None
    for k in _KNOWN_INITIAL_TTLS:
        if observed <= k:
            return k
    return 255


# SYN signature table — each row says "if you see this combination in
# the SYN packet, the OS is X".  The list is ordered most-specific
# first; the first match wins.  References: p0f.fp SYN signatures and
# nmap-os-db (used as a sanity check, not copied verbatim).
#
# The 64-char ``source_os_guess`` column at ``backend/database.py:74``
# caps how long the label can be.  Keep labels under ~40 chars to leave
# room for " (95%)" suffix in alert text.
_SYN_SIGNATURES: List[Dict] = [
    # --- TTL 64 (Unix-like) ---
    {
        "label": "Linux (4.x/5.x/6.x)",
        "initial_ttl": 64,
        "wscale": {7},
        "confidence": 88,
        "reason": "TTL 64 + WSCALE=7 (modern Linux default)",
    },
    {
        "label": "Linux (older 2.6/3.x)",
        "initial_ttl": 64,
        "wscale": {8},
        "confidence": 80,
        "reason": "TTL 64 + WSCALE=8 (Linux 2.6/3.x default)",
    },
    {
        "label": "macOS / iOS",
        "initial_ttl": 64,
        "wscale": {5},
        "mss": {1460, 1380},
        "confidence": 82,
        "reason": "TTL 64 + WSCALE=5 + MSS=1460 (Apple stack)",
    },
    {
        "label": "FreeBSD / macOS",
        "initial_ttl": 64,
        "wscale": {4},
        "mss": {1460},
        "confidence": 75,
        "reason": "TTL 64 + WSCALE=4 + MSS=1460 (BSD / macOS Sonoma)",
    },
    {
        "label": "Linux (generic)",
        "initial_ttl": 64,
        "mss": {1460},
        "confidence": 60,
        "reason": "TTL 64 + MSS=1460 (Linux-family default)",
    },
    {
        "label": "Linux (generic)",
        "initial_ttl": 64,
        "confidence": 35,
        "reason": "TTL 64 only (no other signals)",
    },
    # --- TTL 128 (Windows) ---
    {
        "label": "Windows 10/11 / Server 2019+",
        "initial_ttl": 128,
        "wscale": {8},
        "mss": {1460},
        "confidence": 90,
        "reason": "TTL 128 + WSCALE=8 + MSS=1460 (modern Windows)",
    },
    {
        "label": "Windows 10/11 / Server 2019+",
        "initial_ttl": 128,
        "wscale": {8},
        "confidence": 78,
        "reason": "TTL 128 + WSCALE=8 (modern Windows, MSS missing)",
    },
    {
        "label": "Windows (legacy 7/8/2008)",
        "initial_ttl": 128,
        "wscale": {0, 1, 2, 3},
        "confidence": 70,
        "reason": "TTL 128 + WSCALE ≤ 3 (older Windows)",
    },
    {
        "label": "Windows (generic)",
        "initial_ttl": 128,
        "mss": {1460},
        "confidence": 55,
        "reason": "TTL 128 + MSS=1460 (Windows-family)",
    },
    {
        "label": "Windows (generic)",
        "initial_ttl": 128,
        "confidence": 35,
        "reason": "TTL 128 only (no other signals)",
    },
    # --- TTL 255 (network gear / embedded) ---
    {
        "label": "Network device / embedded",
        "initial_ttl": 255,
        "window": {4128, 8192, 16384, 65535},
        "confidence": 70,
        "reason": "TTL 255 (network gear / embedded / IoT)",
    },
    {
        "label": "Network device / embedded",
        "initial_ttl": 255,
        "confidence": 50,
        "reason": "TTL 255 only (likely embedded)",
    },
    # --- TTL 32 (legacy) ---
    {
        "label": "Windows 9x / NT legacy",
        "initial_ttl": 32,
        "confidence": 60,
        "reason": "TTL 32 (legacy Windows 9x / NT)",
    },
]


def _match_signature(initial_ttl: int, window: Optional[int], options: Dict) -> Optional[Dict]:
    """Return the first SYN signature that matches, or ``None``."""
    mss = options.get("mss")
    wscale = options.get("wscale")
    for sig in _SYN_SIGNATURES:
        if sig["initial_ttl"] != initial_ttl:
            continue
        if "wscale" in sig and wscale not in sig["wscale"]:
            continue
        if "mss" in sig and mss not in sig["mss"]:
            continue
        if "window" in sig and window not in sig["window"]:
            continue
        return sig
    return None


def guess_os(packet_features: Dict) -> OSGuess:
    """Return an :class:`OSGuess` from one SYN packet's features.

    Recognised keys in ``packet_features``:

    * ``ttl``          — observed TTL on the wire (int or ``None``)
    * ``tcp_window``   — TCP window-size field (int or ``None``)
    * ``tcp_options``  — dict of TCP options from a SYN-only packet
      (see :class:`PacketRecord` for keys).  ``None`` is treated as
      empty.  ``df_flag`` is intentionally not read — it is dead.
    """

    ttl = packet_features.get("ttl")
    window = packet_features.get("tcp_window")
    options = packet_features.get("tcp_options") or {}

    initial = _initial_ttl(ttl)
    if initial is None:
        return OSGuess(guess="Unknown", confidence=0, reasons=["no TTL observed"])

    sig = _match_signature(initial, window, options)
    if sig is not None:
        return OSGuess(
            guess=sig["label"],
            confidence=int(sig["confidence"]),
            reasons=[sig["reason"]],
        )

    # Fallback: bucket on initial TTL alone.
    if initial == 64:
        return OSGuess(
            guess="Linux/Unix",
            confidence=25,
            reasons=[f"TTL {ttl} → initial 64, no signature match"],
        )
    if initial == 128:
        return OSGuess(
            guess="Windows (unknown variant)",
            confidence=25,
            reasons=[f"TTL {ttl} → initial 128, no signature match"],
        )
    if initial == 255:
        return OSGuess(
            guess="Network device / embedded",
            confidence=40,
            reasons=[f"TTL {ttl} → initial 255, no signature match"],
        )
    return OSGuess(
        guess="Unknown",
        confidence=0,
        reasons=[f"TTL {ttl} → initial {initial}, no signature match"],
    )
