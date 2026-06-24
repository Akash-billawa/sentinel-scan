"""Scan classification.

Maps a bag of *technique signals* gathered from a burst of packets from
one source IP into a likely scan type with a confidence score.

Architecture:
    Packet → Feature Extraction → **Rule Engine** → Risk Scoring → Alert

The classifier delegates to :mod:`backend.rules`, which implements a
weighted-scoring pipeline inspired by Suricata/ET OPEN rules.  Each rule
contributes a score based on how well the traffic matches a known scan
pattern.  Fingerprint values (window size, MSS) are **confidence
boosters**, not hard requirements — so the engine detects Nmap,
RustScan, Masscan, and custom scanners alike.

The pipeline is extensible: AI anomaly detection or threat-intel feeds
can later plug in as new scoring stages without rewriting this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from backend.rules import DetectionRule, RuleMatch, evaluate_rules


# ---------------------------------------------------------------------------
# Scan type constants
# ---------------------------------------------------------------------------

SCAN_SYN = "SYN Scan (Stealth)"
SCAN_CONNECT = "TCP Connect Scan"
SCAN_ACK = "ACK Scan"
SCAN_XMAS = "Xmas Scan"
SCAN_NULL = "NULL Scan"
SCAN_FIN = "FIN Scan"
SCAN_UDP = "UDP Scan"
SCAN_PING = "Ping Sweep"
SCAN_ICMP_FLOOD = "ICMP Flood"
SCAN_FRAG = "Fragmented Scan"
SCAN_MASS = "Mass Scan"
SCAN_SVC_ENUM = "Service Enumeration"
SCAN_HORIZONTAL = "Horizontal Scan"
SCAN_VERTICAL = "Vertical Scan"
SCAN_TUNNEL = "Tunnel/Proxy Activity"
SCAN_PERSISTENT = "Persistent Connection"
SCAN_GENERIC_TCP = "Generic TCP Probe"
SCAN_GENERIC_UDP = "UDP Probe"
SCAN_GENERIC_ICMP = "ICMP Probe"
SCAN_UNKNOWN = "Unknown"


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    scan_type: str
    confidence: float  # 0..100
    contributing_signals: List[str]
    # Optional: individual rule matches (populated when using rules engine)
    rule_matches: Optional[List[RuleMatch]] = None


# ---------------------------------------------------------------------------
# SID resolution from config
# ---------------------------------------------------------------------------

def _resolve_enabled_sids() -> Optional[frozenset[int]]:
    """Parse SENTINEL_SCAN_RULES into a frozenset of enabled SIDs.

    Returns ``None`` if the value is "all" (or empty), which tells
    :func:`evaluate_rules` to evaluate every rule.
    """
    try:
        from backend.config import get_settings
        raw = get_settings().scan_rules.strip().lower()
    except Exception:
        return None
    if not raw or raw == "all":
        return None
    sids = set()
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            sids.add(int(part))
    return frozenset(sids) if sids else None


# ---------------------------------------------------------------------------
# Legacy helpers (kept for backward compat with direct callers)
# ---------------------------------------------------------------------------

def _flags_set(flags: Dict[str, bool], names: List[str]) -> bool:
    return all(flags.get(n) for n in names)


def _no_flags(flags: Dict[str, bool]) -> bool:
    return not any(flags.values())


# ---------------------------------------------------------------------------
# Primary classifier
# ---------------------------------------------------------------------------

def classify(signals: Dict) -> ClassificationResult:
    """Return the best matching scan type and a 0-100 confidence.

    This is the main entry point.  It runs the weighted-rule pipeline
    from :mod:`backend.rules`, picks the highest-scoring rule match, and
    wraps it in a :class:`ClassificationResult`.  If no rule fires above
    the noise floor, a generic fallback label is returned.
    """

    # ---- resolve enabled SIDs from config --------------------------------
    enabled_sids = _resolve_enabled_sids()

    # ---- run the rule engine pipeline ------------------------------------
    matches = evaluate_rules(signals, enabled_sids=enabled_sids)

    # ---- filter out low-value labels for presentation -------------------
    # Tunnel and Persistent Connection are useful for suppression but
    # shouldn't be the *primary* classification unless nothing else fires.
    _noise_labels = {"Tunnel/Proxy Activity", "Persistent Connection"}
    strong_matches = [m for m in matches if m.rule.name not in _noise_labels]

    if strong_matches:
        best = strong_matches[0]
    elif matches:
        # Only noise labels matched — use the best one but with reduced
        # confidence so the caller knows this isn't a real scan.
        best = matches[0]
    else:
        # Nothing matched — fall back to basic protocol labels.
        return _fallback(signals)

    # ---- build result ----------------------------------------------------
    contributing = []
    for m in matches[:5]:
        tag = f"{m.rule.name}: {', '.join(m.reasons[:2])}" if m.reasons else m.rule.name
        contributing.append(tag)

    confidence = round(min(best.score * 100, 100), 1)

    return ClassificationResult(
        scan_type=best.rule.scan_type,
        confidence=confidence,
        contributing_signals=contributing,
        rule_matches=matches,
    )


def _fallback(signals: Dict) -> ClassificationResult:
    """Return a generic label when no rule matches."""
    has_tcp = signals.get("has_tcp", False)
    has_udp = signals.get("has_udp", False)
    has_icmp = signals.get("has_icmp", False)
    packet_count = signals.get("packet_count", 0)
    unique_targets = signals.get("unique_targets", 0)
    unique_ports = signals.get("unique_ports", 0)
    rate = signals.get("rate", 0.0)

    # Protocol-specific labels before tunnel heuristics — a UDP burst to
    # a single port is better reported as "UDP Probe" than as a tunnel.
    if has_tcp and unique_targets == 1 and unique_ports <= 3 and rate >= 50:
        return ClassificationResult(
            scan_type=SCAN_TUNNEL,
            confidence=75.0,
            contributing_signals=["Tunnel/Proxy Activity", f"Single target, {unique_ports} port(s), repetitive"],
        )

    if has_tcp and unique_targets == 1 and unique_ports <= 3 and rate < 50 and packet_count > 10:
        return ClassificationResult(
            scan_type=SCAN_PERSISTENT,
            confidence=65.0,
            contributing_signals=["Persistent Connection", f"Single target, {unique_ports} port(s), steady traffic"],
        )

    # Generic fallbacks.
    if has_tcp:
        label = SCAN_GENERIC_TCP
        reason = "TCP traffic, no specific signature"
    elif has_udp:
        label = SCAN_GENERIC_UDP
        reason = "UDP traffic, no specific signature"
    elif has_icmp:
        label = SCAN_GENERIC_ICMP
        reason = "ICMP traffic, no specific signature"
    else:
        label = SCAN_UNKNOWN
        reason = "no data"

    return ClassificationResult(
        scan_type=label,
        confidence=50.0,
        contributing_signals=[reason],
    )
