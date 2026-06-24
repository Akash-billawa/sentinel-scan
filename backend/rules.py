"""Detection rule engine — Suricata-inspired weighted scoring pipeline.

Instead of rigid pattern matching (which attackers can evade by tweaking
fingerprints), this engine uses a **weighted-score pipeline**:

    Packet → Feature Extraction → Rule Scoring → Risk Assessment → Alert

Each rule contributes a score based on how well the traffic matches a
known scan pattern.  Fingerprint values (window size, MSS) are
**confidence boosters**, not hard requirements — so the engine detects
Nmap, RustScan, Masscan, and custom scanners alike.

The pipeline is designed to be extensible: later additions (AI anomaly
detection, threat-intel feeds) can plug in as new scoring stages without
rewriting the classifier.

Rule format (inspired by Suricata/ET OPEN, but adapted for weighted
scoring):

    DetectionRule(
        sid         = 3400001,           # Suricata-style signature ID
        name        = "SYN Scan",        # Human label
        scan_type   = "SYN Scan",        # Classification result
        priority    = 1,                 # 1=high, 2=medium, 3=low
        base_score  = 0.5,               # Base confidence (0..1)
        score       = lambda s: ...,     # Scoring function(signals) -> 0..1
        required    = lambda s: ...,     # Hard precondition (must pass)
    )

Scoring:
    final_score = base_score × score(signals)
    The ``required`` predicate gates the rule entirely — if it returns
    False the rule is not evaluated at all (used for protocol gating).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Rule dataclass
# ---------------------------------------------------------------------------

@dataclass
class DetectionRule:
    """A single detection rule in the scoring pipeline."""

    sid: int
    name: str
    scan_type: str
    priority: int  # 1 = high, 2 = medium, 3 = low
    base_score: float  # base confidence 0..1 (before fingerprint boosters)
    # Scoring function: returns 0..1 based on signal strength.
    score: Callable[[Dict], float]
    # Optional hard precondition — if False, rule is skipped entirely.
    required: Optional[Callable[[Dict], bool]] = None


@dataclass
class RuleMatch:
    """A rule that matched, with its computed score."""

    rule: DetectionRule
    score: float  # 0..1 final score
    reasons: List[str]  # human-readable reasons


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flags_set(flags: Dict[str, bool], names: List[str]) -> bool:
    return all(flags.get(n) for n in names)


def _no_flags(flags: Dict[str, bool]) -> bool:
    return not any(flags.values())


# Common port sets (Suricata ET OPEN convention).
_COMMON_PORTS = frozenset({
    21, 22, 23, 25, 53, 80, 88, 110, 135, 137, 138, 139, 143,
    161, 389, 443, 445, 465, 514, 587, 636, 853, 993, 995, 1194,
    1433, 1720, 3306, 3389, 8080, 8443, 11211, 27017, 51820,
})


# ---------------------------------------------------------------------------
# Detection rules — ordered by importance
# ---------------------------------------------------------------------------

def _build_rules() -> List[DetectionRule]:
    """Build the full rule set.  Called once at module load time."""

    rules: List[DetectionRule] = []

    # ------------------------------------------------------------------
    # 1. HORIZONTAL SCAN — many hosts, same port  (Very High importance)
    # ------------------------------------------------------------------
    def _horizontal_score(s: Dict) -> float:
        targets = s.get("unique_targets", 0)
        ports = s.get("unique_ports", 0)
        if targets < 3:
            return 0.0
        # Score scales with number of targets (more = more certain).
        score = min(1.0, targets / 30)
        # Fewer ports = stronger horizontal signal.
        if ports <= 1:
            score = min(1.0, score + 0.3)
        elif ports <= 3:
            score = min(1.0, score + 0.15)
        return score

    rules.append(DetectionRule(
        sid=3400100, name="Horizontal Scan", scan_type="Horizontal Scan",
        priority=1, base_score=0.9,
        score=_horizontal_score,
        required=lambda s: s.get("unique_targets", 0) >= 3 and s.get("unique_ports", 0) >= 1,
    ))

    # ------------------------------------------------------------------
    # 2. VERTICAL SCAN — many ports, same host  (Very High importance)
    # ------------------------------------------------------------------
    def _vertical_score(s: Dict) -> float:
        ports = s.get("unique_ports", 0)
        targets = s.get("unique_targets", 0)
        if ports < 10:
            return 0.0
        # Score scales with port count.
        score = min(1.0, ports / 100)
        # Single target = pure vertical scan.
        if targets == 1:
            score = min(1.0, score + 0.2)
        elif targets <= 3:
            score = min(1.0, score + 0.1)
        # Bonus for hitting uncommon ports (not just 80/443).
        port_list = s.get("unique_port_list", [])
        uncommon = [p for p in port_list if p not in _COMMON_PORTS]
        if len(uncommon) > 5:
            score = min(1.0, score + 0.1)
        return score

    rules.append(DetectionRule(
        sid=3400101, name="Vertical Scan", scan_type="Vertical Scan",
        priority=1, base_score=0.9,
        score=_vertical_score,
        required=lambda s: s.get("unique_ports", 0) >= 10,
    ))

    # ------------------------------------------------------------------
    # 3. SYN SCAN — high SYN ratio, low completion, many ports
    # ------------------------------------------------------------------
    def _syn_scan_score(s: Dict) -> float:
        syn_ratio = s.get("syn_ratio", 0)
        completion = s.get("tcp_completion_ratio", 0)
        ports = s.get("unique_ports", 0)
        if syn_ratio <= 0.5 or completion > 0.3:
            return 0.0
        score = 0.0
        # Core signal: SYN dominance + low completion.
        score += min(0.5, syn_ratio * 0.6)
        score += min(0.2, (1.0 - completion) * 0.25)
        # Port breadth.
        if ports >= 20:
            score += 0.15
        elif ports >= 5:
            score += 0.08
        # Fingerprint boosters (not requirements).
        win = s.get("window_value")
        mss = s.get("mss_value")
        if win == 1024:
            score += 0.08  # Nmap default SYN scan window
        if mss == 1460:
            score += 0.05  # Ethernet MSS
        elif mss and 500 <= mss <= 1500:
            score += 0.03  # Any reasonable MSS
        return min(1.0, score)

    rules.append(DetectionRule(
        sid=3400001, name="SYN Scan", scan_type="SYN Scan (Stealth)",
        priority=1, base_score=0.85,
        score=_syn_scan_score,
        required=lambda s: s.get("has_tcp", False),
    ))

    # ------------------------------------------------------------------
    # 4. CONNECT SCAN — moderate SYN ratio, moderate completion
    # ------------------------------------------------------------------
    def _connect_scan_score(s: Dict) -> float:
        syn_ratio = s.get("syn_ratio", 0)
        completion = s.get("tcp_completion_ratio", 0)
        ports = s.get("unique_ports", 0)
        if not (0.2 < syn_ratio <= 0.85 and completion >= 0.25 and ports >= 5):
            return 0.0
        score = 0.0
        score += min(0.4, syn_ratio * 0.5)
        score += min(0.3, completion * 0.4)
        if ports >= 20:
            score += 0.15
        # Window fingerprint: Nmap Connect scan uses ~32120.
        win = s.get("window_value")
        if win and 30000 <= win <= 35000:
            score += 0.08
        return min(1.0, score)

    rules.append(DetectionRule(
        sid=3400003, name="Connect Scan", scan_type="TCP Connect Scan",
        priority=1, base_score=0.80,
        score=_connect_scan_score,
        required=lambda s: s.get("has_tcp", False),
    ))

    # ------------------------------------------------------------------
    # 5. ACK SCAN — ACK-only flags, probing firewall rules
    # ------------------------------------------------------------------
    def _ack_scan_score(s: Dict) -> float:
        flags = s.get("flags_seen", {})
        ports = s.get("unique_ports", 0)
        # ACK only: ACK set, SYN not set.
        if not flags.get("ACK") or flags.get("SYN"):
            return 0.0
        if ports < 3:
            return 0.0
        score = 0.3
        if ports >= 10:
            score += 0.2
        elif ports >= 5:
            score += 0.1
        # Window fingerprint: Nmap ACK scan uses 1024.
        win = s.get("window_value")
        if win == 1024:
            score += 0.15
        # Pure ACK (no other flags) = stronger signal.
        other_flags = [f for f, v in flags.items() if v and f != "ACK"]
        if not other_flags:
            score += 0.15
        return min(1.0, score)

    rules.append(DetectionRule(
        sid=3400004, name="ACK Scan", scan_type="ACK Scan",
        priority=1, base_score=0.75,
        score=_ack_scan_score,
        required=lambda s: s.get("has_tcp", False),
    ))

    # ------------------------------------------------------------------
    # 6. XMAS SCAN — FIN+PSH+URG flags
    # ------------------------------------------------------------------
    def _xmas_score(s: Dict) -> float:
        flags = s.get("flags_seen", {})
        if not _flags_set(flags, ["FIN", "PSH", "URG"]):
            return 0.0
        score = 0.7
        count = s.get("packet_count", 0)
        if count >= 3:
            score += 0.15
        return min(1.0, score)

    rules.append(DetectionRule(
        sid=3400005, name="XMAS Scan", scan_type="Xmas Scan",
        priority=2, base_score=0.90,
        score=_xmas_score,
        required=lambda s: s.get("has_tcp", False),
    ))

    # ------------------------------------------------------------------
    # 7. NULL SCAN — no TCP flags set
    # ------------------------------------------------------------------
    def _null_score(s: Dict) -> float:
        flags = s.get("flags_seen", {})
        if not _no_flags(flags):
            return 0.0
        score = 0.65
        count = s.get("packet_count", 0)
        if count >= 3:
            score += 0.15
        return min(1.0, score)

    rules.append(DetectionRule(
        sid=3400009, name="NULL Scan", scan_type="NULL Scan",
        priority=1, base_score=0.85,
        score=_null_score,
        required=lambda s: s.get("has_tcp", False),
    ))

    # ------------------------------------------------------------------
    # 8. FIN SCAN — FIN only, no SYN, no ACK
    # ------------------------------------------------------------------
    def _fin_score(s: Dict) -> float:
        flags = s.get("flags_seen", {})
        if not flags.get("FIN") or flags.get("SYN") or flags.get("ACK"):
            return 0.0
        score = 0.65
        count = s.get("packet_count", 0)
        if count >= 3:
            score += 0.15
        return min(1.0, score)

    rules.append(DetectionRule(
        sid=3400010, name="FIN Scan", scan_type="FIN Scan",
        priority=1, base_score=0.80,
        score=_fin_score,
        required=lambda s: s.get("has_tcp", False),
    ))

    # ------------------------------------------------------------------
    # 9. UDP SCAN — UDP-only traffic, multiple ports
    # ------------------------------------------------------------------
    def _udp_scan_score(s: Dict) -> float:
        if not s.get("has_udp", False) or s.get("has_tcp", False):
            return 0.0
        ports = s.get("unique_ports", 0)
        if ports < 3:
            return 0.0
        score = min(1.0, ports / 20)
        return score

    rules.append(DetectionRule(
        sid=3400007, name="UDP Scan", scan_type="UDP Scan",
        priority=2, base_score=0.80,
        score=_udp_scan_score,
    ))

    # ------------------------------------------------------------------
    # 10. PING SWEEP — ICMP to many hosts
    # ------------------------------------------------------------------
    def _ping_sweep_score(s: Dict) -> float:
        if not s.get("has_icmp", False) or s.get("has_tcp", False):
            return 0.0
        targets = s.get("unique_targets", 0)
        if targets < 3:
            return 0.0
        score = min(1.0, targets / 20)
        return score

    rules.append(DetectionRule(
        sid=3400013, name="Ping Sweep", scan_type="Ping Sweep",
        priority=2, base_score=0.85,
        score=_ping_sweep_score,
    ))

    # ------------------------------------------------------------------
    # 10b. ICMP FLOOD — high-rate ICMP to a single host
    #      (distinct from Ping Sweep which targets many hosts).
    # ------------------------------------------------------------------
    def _icmp_flood_score(s: Dict) -> float:
        if not s.get("has_icmp", False) or s.get("has_tcp", False):
            return 0.0
        targets = s.get("unique_targets", 0)
        rate = s.get("rate", 0)
        if targets > 2 or rate < 100:
            return 0.0
        score = min(1.0, rate / 2000)  # 2000 pps = 1.0
        # Single target is a stronger flood signal.
        if targets <= 1:
            score = min(1.0, score + 0.2)
        return score

    rules.append(DetectionRule(
        sid=3400014, name="ICMP Flood", scan_type="ICMP Flood",
        priority=1, base_score=0.80,
        score=_icmp_flood_score,
    ))

    # ------------------------------------------------------------------
    # 11. MASSCAN — extremely high rate, SYN-dominant
    # ------------------------------------------------------------------
    def _masscan_score(s: Dict) -> float:
        rate = s.get("rate", 0)
        syn_ratio = s.get("syn_ratio", 0)
        if rate < 500 or syn_ratio < 0.6:
            return 0.0
        score = 0.0
        if rate >= 5000:
            score += 0.5
        elif rate >= 1500:
            score += 0.3
        else:
            score += 0.15
        score += min(0.3, syn_ratio * 0.35)
        ports = s.get("unique_ports", 0)
        if ports >= 100:
            score += 0.15
        elif ports >= 20:
            score += 0.08
        return min(1.0, score)

    rules.append(DetectionRule(
        sid=3400011, name="Masscan", scan_type="Mass Scan",
        priority=1, base_score=0.90,
        score=_masscan_score,
        required=lambda s: s.get("has_tcp", False),
    ))

    # ------------------------------------------------------------------
    # 12. SERVICE ENUMERATION — many ports, full handshakes
    # ------------------------------------------------------------------
    def _service_enum_score(s: Dict) -> float:
        ports = s.get("unique_ports", 0)
        completion = s.get("tcp_completion_ratio", 0)
        syn_ratio = s.get("syn_ratio", 0)
        if ports < 15 or completion < 0.3 or syn_ratio > 0.6:
            return 0.0
        score = min(0.6, ports / 100)
        score += min(0.3, completion * 0.4)
        return min(1.0, score)

    rules.append(DetectionRule(
        sid=3400012, name="Service Enumeration", scan_type="Service Enumeration",
        priority=2, base_score=0.70,
        score=_service_enum_score,
        required=lambda s: s.get("has_tcp", False),
    ))

    # ------------------------------------------------------------------
    # 13. FRAGMENTED SCAN — IP fragmentation bits set
    # ------------------------------------------------------------------
    def _frag_score(s: Dict) -> float:
        # fragmentation detected via IP-level signals
        frag_count = s.get("fragmented_count", 0)
        total = s.get("packet_count", 0)
        if total == 0 or frag_count < 3:
            return 0.0
        ratio = frag_count / total
        return min(1.0, 0.4 + ratio * 0.5)

    rules.append(DetectionRule(
        sid=3400006, name="Fragmented Scan", scan_type="Fragmented Scan",
        priority=1, base_score=0.75,
        score=_frag_score,
    ))

    return rules


# Pre-built rule list (module-level singleton).
RULES: List[DetectionRule] = _build_rules()


# ---------------------------------------------------------------------------
# Pipeline: evaluate all rules against signals
# ---------------------------------------------------------------------------

def evaluate_rules(
    signals: Dict,
    enabled_sids: Optional[frozenset[int]] = None,
) -> List[RuleMatch]:
    """Run all detection rules against the signal bag.

    Returns a list of :class:`RuleMatch` for every rule that matched
    (score > 0), sorted by score descending.  If *enabled_sids* is
    provided, only rules with those SIDs are evaluated.

    The pipeline is intentionally simple so it can be extended later
    with AI anomaly scoring or threat-intel enrichment without changing
    the caller.
    """
    matches: List[RuleMatch] = []

    for rule in RULES:
        if enabled_sids is not None and rule.sid not in enabled_sids:
            continue

        # Hard precondition gate.
        if rule.required is not None and not rule.required(signals):
            continue

        raw = rule.score(signals)
        if raw <= 0.0:
            continue

        final = rule.base_score * raw
        if final < 0.15:  # noise floor — don't bother reporting
            continue

        reasons = _build_reasons(rule, signals, raw)
        matches.append(RuleMatch(rule=rule, score=round(final, 3), reasons=reasons))

    matches.sort(key=lambda m: m.score, reverse=True)
    return matches


def _build_reasons(rule: DetectionRule, signals: Dict, raw: float) -> List[str]:
    """Generate human-readable reasons for why a rule matched."""
    reasons: List[str] = []
    ports = signals.get("unique_ports", 0)
    targets = signals.get("unique_targets", 0)
    syn = signals.get("syn_ratio", 0)
    comp = signals.get("tcp_completion_ratio", 0)
    rate = signals.get("rate", 0)

    if "Horizontal" in rule.name:
        reasons.append(f"{targets} unique targets")
        if ports <= 3:
            reasons.append(f"only {ports} port(s) — targeted")
    elif "Vertical" in rule.name:
        reasons.append(f"{ports} unique ports")
        if targets == 1:
            reasons.append("single host")
    elif "SYN Scan" in rule.name:
        reasons.append(f"SYN ratio {syn:.0%}")
        reasons.append(f"completion {comp:.0%}")
        win = signals.get("window_value")
        mss = signals.get("mss_value")
        if win == 1024:
            reasons.append("window=1024 (Nmap fingerprint)")
        if mss == 1460:
            reasons.append("mss=1460 (Ethernet default)")
    elif "Connect" in rule.name:
        reasons.append(f"SYN ratio {syn:.0%}, completion {comp:.0%}")
    elif "ACK" in rule.name:
        reasons.append("ACK-only probes")
        reasons.append(f"{ports} ports targeted")
    elif "XMAS" in rule.name:
        reasons.append("FIN+PSH+URG flags")
    elif "NULL" in rule.name:
        reasons.append("No TCP flags set")
    elif "FIN" in rule.name:
        reasons.append("FIN-only probes")
    elif "UDP" in rule.name:
        reasons.append(f"UDP to {ports} ports")
    elif "Ping" in rule.name:
        reasons.append(f"ICMP to {targets} hosts")
    elif "ICMP Flood" in rule.name:
        reasons.append(f"ICMP flood at {rate:.0f} pps")
        if targets <= 1:
            reasons.append("single target")
    elif "Mass" in rule.name:
        reasons.append(f"Rate {rate:.0f} pps")
    elif "Service" in rule.name:
        reasons.append(f"{ports} ports, full handshakes")
    elif "Fragment" in rule.name:
        reasons.append("IP fragmentation detected")

    return reasons
