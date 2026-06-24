"""Risk scoring.

Computes a 0-10 risk score and a discrete severity band for a detected
attack.  The score is a weighted sum of normalised factors and is
deliberately conservative — any single dominant indicator should
already push the score into the "high" band.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict


@dataclass
class RiskAssessment:
    score: float  # 0 - 10
    level: str    # low | medium | high | critical

    def to_dict(self) -> Dict:
        return {"score": round(self.score, 1), "level": self.level}


# Weights for each factor (sum to 1.0).  These are the *relative*
# importance of each factor, not the final score.
_W_PORTS = 0.25
_W_RATE = 0.20
_W_DURATION = 0.05
_W_TECHNIQUE = 0.30
_W_VOLUME = 0.20


def _norm_ports(p: int) -> float:
    """Log-saturate the unique-ports count into 0..1."""

    if p <= 0:
        return 0.0
    return min(1.0, math.log10(max(p, 1)) / math.log10(1000))  # 1000 ports -> 1.0


def _norm_rate(r: float) -> float:
    if r <= 0:
        return 0.0
    return min(1.0, math.log10(max(r, 1)) / math.log10(10000))  # 10k pps -> 1.0


def _norm_duration(d: float) -> float:
    """A long-running scan is more dangerous (recurrent probing)."""

    if d <= 0:
        return 0.0
    return min(1.0, math.log10(max(d, 1)) / math.log10(3600))  # 1h -> 1.0


# Technique multipliers — these are the *severity* of a given technique.
_TECHNIQUE_SEVERITY = {
    # Reconnaissance — low severity
    "Ping Sweep": 0.25,
    "Generic TCP Probe": 0.35,
    "UDP Probe": 0.35,
    "ICMP Probe": 0.30,
    # Active scanning — medium severity
    "UDP Scan": 0.50,
    "TCP Connect Scan": 0.55,
    "Service Enumeration": 0.70,
    # Stealth / evasion — high severity
    "SYN Scan (Stealth)": 0.75,
    "ACK Scan": 0.70,
    "Fragmented Scan": 0.75,
    "FIN Scan": 0.80,
    "NULL Scan": 0.80,
    "Xmas Scan": 0.90,
    # Volume — high severity
    "Mass Scan": 0.85,
    "ICMP Flood": 0.65,
    # Network-level recon — very high severity
    "Horizontal Scan": 0.95,
    "Vertical Scan": 0.90,
    # Background / benign — very low severity
    "Tunnel/Proxy Activity": 0.10,
    "Persistent Connection": 0.05,
    "Unknown": 0.20,
}


def _technique_factor(scan_type: str) -> float:
    return _TECHNIQUE_SEVERITY.get(scan_type, 0.4)


def _norm_volume(packet_count: int, target_count: int) -> float:
    """A combined 'how much' factor."""

    if packet_count <= 0 and target_count <= 0:
        return 0.0
    raw = math.log10(packet_count + 1) * 0.6 + math.log10(target_count + 1) * 0.4
    return min(1.0, raw / 4.0)


def assess(
    scan_type: str,
    *,
    unique_ports: int,
    rate: float,
    duration: float,
    packet_count: int,
    unique_targets: int,
) -> RiskAssessment:
    parts = [
        _W_PORTS * _norm_ports(unique_ports),
        _W_RATE * _norm_rate(rate),
        _W_DURATION * _norm_duration(duration),
        _W_TECHNIQUE * _technique_factor(scan_type),
        _W_VOLUME * _norm_volume(packet_count, unique_targets),
    ]
    raw = sum(parts)  # 0..1
    # Stretch into 1..10 with a soft floor for non-zero scans so they
    # never report as "0.0/10" (which reads as "no risk" to operators).
    score = 1.0 + raw * 9.0

    # --- Port-count penalty: few ports = much lower risk ---
    # Real reconnaissance probes many ports.  High packet volume to
    # ≤3 ports is a session/tunnel, not recon — cap the score.
    # Exception: horizontal/vertical scans are high-risk regardless.
    _high_risk_labels = {"Horizontal Scan", "Vertical Scan"}
    if scan_type not in _high_risk_labels:
        if unique_ports <= 1:
            score = min(score, 3.0)
        elif unique_ports <= 3:
            score = min(score, 4.5)

    # --- Target-count bonus: many targets = horizontal sweep ---
    if unique_targets >= 20:
        score = min(10.0, score + 1.0)
    elif unique_targets >= 10:
        score = min(10.0, score + 0.5)

    if score >= 8.0:
        level = "critical"
    elif score >= 6.0:
        level = "high"
    elif score >= 3.5:
        level = "medium"
    else:
        level = "low"

    return RiskAssessment(score=round(score, 1), level=level)
