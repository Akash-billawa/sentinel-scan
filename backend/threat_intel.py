"""Threat intelligence feed integration.

Provides offline-safe reputation checks for source IPs via the AbuseIPDB
API.  The module is designed to degrade gracefully:

* No API key configured → returns ``None`` (no data, no error).
* Network error during lookup → logged, returns ``None``.
* Rate-limited (429) → backs off, caches the limiter state.
* Valid response → cached in an in-memory LRU (same pattern as the
  hostname cache in :mod:`backend.profiler`) so repeated lookups of a
  chatty attacker IP don't re-hit the API.

Usage::

    from backend.threat_intel import check_ip
    result = check_ip("45.33.32.156")
    if result:
        print(result.abuse_confidence_score)  # 0-100
        print(result.total_reports)
        print(result.categories)  # list[str]
"""

from __future__ import annotations

import json
import logging
import threading
import time as _time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("sentinelscan.threat_intel")

# Cache TTL — reputation data changes slowly (hours to days).
_CACHE_TTL = 3600.0  # 1 hour
_CACHE_MAX = 2048
# Min delay between API calls to avoid rate-limiting.
_MIN_INTERVAL = 1.2  # seconds


@dataclass
class IntelResult:
    """Reputation data for one IP, as returned by AbuseIPDB (or compatible API)."""

    ip: str
    abuse_confidence_score: int  # 0-100
    total_reports: int = 0
    last_reported_at: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    country_code: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    is_whitelisted: bool = False
    source: str = "abuseipdb"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "abuse_confidence_score": self.abuse_confidence_score,
            "total_reports": self.total_reports,
            "last_reported_at": self.last_reported_at,
            "categories": self.categories,
            "country_code": self.country_code,
            "isp": self.isp,
            "domain": self.domain,
            "is_whitelisted": self.is_whitelisted,
            "source": self.source,
        }


# ---------------------------------------------------------------------------
# LRU cache (mirrors the pattern in profiler.py)
# ---------------------------------------------------------------------------

_CacheValue = tuple[Optional[IntelResult], float]


class _IntelCache:
    def __init__(self, max_entries: int = _CACHE_MAX,
                 ttl_seconds: float = _CACHE_TTL,
                 clock: Optional[callable] = None) -> None:
        self._data: OrderedDict[str, _CacheValue] = OrderedDict()
        self._max = max(1, int(max_entries))
        self._ttl = max(0.0, float(ttl_seconds))
        self._lock = threading.Lock()
        self._clock = clock or _time.monotonic

    def get(self, key: str) -> tuple[Optional[IntelResult], bool]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None, False
            result, expiry = entry
            if self._ttl and self._clock() >= expiry:
                self._data.pop(key, None)
                return None, False
            self._data.move_to_end(key)
            return result, True

    def set(self, key: str, value: Optional[IntelResult]) -> None:
        with self._lock:
            if key in self._data:
                self._data.pop(key, None)
            self._data[key] = (
                value,
                self._clock() + self._ttl if self._ttl else float("inf"),
            )
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------

_intel_cache: Optional[_IntelCache] = None
_last_api_call: float = 0.0
_api_lock = threading.Lock()


def _get_cache() -> _IntelCache:
    global _intel_cache
    if _intel_cache is None:
        _intel_cache = _IntelCache()
    return _intel_cache


# AbuseIPDB category number → human label (v2 API).
_ABUSE_CATEGORIES: Dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def _parse_abuseipdb(data: Dict, ip: str) -> IntelResult:
    """Parse AbuseIPDB check response into an IntelResult."""
    attrs = data.get("data", {}).get("attributes", {})
    raw_cats = attrs.get("categories", [])
    categories = [_ABUSE_CATEGORIES.get(c, f"Category {c}") for c in raw_cats]
    return IntelResult(
        ip=ip,
        abuse_confidence_score=attrs.get("abuseConfidenceScore", 0),
        total_reports=attrs.get("totalReports", 0),
        last_reported_at=attrs.get("lastReportedAt"),
        categories=categories,
        country_code=attrs.get("countryCode"),
        isp=attrs.get("isp"),
        domain=attrs.get("domain"),
        is_whitelisted=attrs.get("isWhitelisted", False),
        source="abuseipdb",
    )


def check_ip(ip: str) -> Optional[IntelResult]:
    """Check an IP against the configured threat-intel provider.

    Returns an :class:`IntelResult` if the API key is configured and the
    lookup succeeds, ``None`` otherwise (no key, network error, or the
    IP is private).
    """
    from .config import get_settings

    settings = get_settings()
    api_key = settings.threat_intel_api_key
    if not api_key:
        return None

    # Skip private / reserved IPs — they are never in threat-intel feeds.
    if _is_private(ip):
        return None

    # Circuit breaker: if the API has been failing repeatedly, short-circuit
    # without hitting the network. Avoids burning 5s timeouts on every packet.
    if _circuit_open():
        return None

    # Cache hit?
    cached, hit = _get_cache().get(ip)
    if hit:
        return cached

    # Rate-limit ourselves. Sleep OUTSIDE the lock so a slow DNS lookup
    # doesn't serialize the entire detection thread.
    global _last_api_call
    with _api_lock:
        last = _last_api_call
    now = _time.monotonic()
    elapsed = now - last
    if elapsed < _MIN_INTERVAL:
        _time.sleep(_MIN_INTERVAL - elapsed)
    with _api_lock:
        _last_api_call = _time.monotonic()

    try:
        import requests
        url = settings.threat_intel_api_url.rstrip("/") + "/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": settings.threat_intel_max_age}
        resp = requests.get(url, headers=headers, params=params, timeout=5.0)
        if resp.status_code == 429:
            log.warning("Threat-intel API rate-limited for %s; backing off", ip)
            _record_api_failure()
            # Do NOT cache — 429 is transient; retry next time.
            return None
        if resp.status_code == 404:
            # IP not found in DB — cache as clean.
            result = IntelResult(ip=ip, abuse_confidence_score=0, total_reports=0)
            _get_cache().set(ip, result)
            _record_api_success()
            return result
        if resp.status_code != 200:
            # Transient server error — do NOT cache. Real error — log at warning.
            log.warning("Threat-intel API returned %s for %s", resp.status_code, ip)
            _record_api_failure()
            return None
        data = resp.json()
        result = _parse_abuseipdb(data, ip)
        _get_cache().set(ip, result)
        _record_api_success()
        return result
    except Exception as exc:
        # Network errors / timeouts — do NOT cache; the IP may be fine next time.
        log.warning("Threat-intel lookup failed for %s: %s", ip, exc)
        _record_api_failure()
        return None


# ---------------------------------------------------------------------------
# Circuit breaker (simple consecutive-failure counter)
# ---------------------------------------------------------------------------

_CIRCUIT_THRESHOLD = 5      # consecutive failures before opening
_CIRCUIT_COOLDOWN = 60.0    # seconds before half-open retry
_circuit_failures = 0
_circuit_opened_at = 0.0
_circuit_lock = threading.Lock()


def _record_api_success() -> None:
    global _circuit_failures
    with _circuit_lock:
        _circuit_failures = 0


def _record_api_failure() -> None:
    global _circuit_failures, _circuit_opened_at
    with _circuit_lock:
        _circuit_failures += 1
        if _circuit_failures >= _CIRCUIT_THRESHOLD and _circuit_opened_at == 0.0:
            _circuit_opened_at = _time.monotonic()
            log.warning(
                "Threat-intel circuit OPEN after %d consecutive failures; "
                "cooling down for %ds",
                _circuit_failures, int(_CIRCUIT_COOLDOWN),
            )


def _circuit_open() -> bool:
    """Return True if the breaker is currently open (skip API)."""
    global _circuit_opened_at
    with _circuit_lock:
        if _circuit_opened_at == 0.0:
            return False
        if _time.monotonic() - _circuit_opened_at >= _CIRCUIT_COOLDOWN:
            # Half-open: let one request through.
            _circuit_opened_at = 0.0
            log.info("Threat-intel circuit HALF-OPEN; retrying")
            return False
        return True


def _is_private(ip: str) -> bool:
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def reset_cache() -> None:
    """Clear the cache (used in tests)."""
    global _intel_cache
    if _intel_cache is not None:
        _intel_cache.clear()
