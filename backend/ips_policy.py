"""IPS Policy — defines what actions to take based on risk level.

Human-in-the-Loop IPS: risk >= approval threshold produces a
PendingAction requiring operator approval before any block is applied.
The block is deferred to the firewall manager only after the operator
(or the timeout) says so.

Thresholds are read from config (``SENTINEL_IPS_APPROVAL_THRESHOLD`` and
``SENTINEL_IPS_AUTO_BLOCK_THRESHOLD`` env vars) so operators can tune
sensitivity without touching code.  The defaults (4.0 / 8.0) match the
``.env.example`` documentation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass
class IPSAction:
    """Action to take for a detected threat."""

    action: str  # "alert" | "approve" | "auto_block"
    reason: str


# Default thresholds — overridden when ``evaluate()`` receives settings.
_ALERT_ONLY_MAX = 6.0
_AUTO_BLOCK_MIN = 9.0

# Scan types that always require approval (regardless of risk score)
ALWAYS_APPROVE = {
    "ACK Scan",
    "Fragmented Scan",
    "NULL Scan",
    "FIN Scan",
    "Xmas Scan",
}

# Scan types that auto-block (critical threats)
AUTO_BLOCK_TYPES = {
    "Mass Scan",
}


def evaluate(
    risk_score: float,
    scan_type: str,
    *,
    alert_only_max: float = _ALERT_ONLY_MAX,
    auto_block_min: float = _AUTO_BLOCK_MIN,
) -> IPSAction:
    """Determine IPS action based on risk score and scan type.

    Parameters
    ----------
    risk_score:
        Normalised risk score (0-10).
    scan_type:
        Classified scan type label.
    alert_only_max:
        Risk below this → ``alert`` only (no IPS action).
        Default 6.0.  Set from ``Settings.ips_approval_threshold``.
    auto_block_min:
        Risk at or above this → immediate ``auto_block`` (bypass approval).
        Default 9.0.  Set from ``Settings.ips_auto_block_threshold``.
    """
    # Check scan-type overrides first
    if scan_type in AUTO_BLOCK_TYPES:
        return IPSAction(action="auto_block", reason=f"Scan type '{scan_type}' is auto-blocked")

    if scan_type in ALWAYS_APPROVE:
        return IPSAction(action="approve", reason=f"Scan type '{scan_type}' requires manual review")

    # Risk-based decision
    if risk_score >= auto_block_min:
        return IPSAction(action="auto_block", reason=f"Risk score {risk_score:.1f} exceeds auto-block threshold")
    elif risk_score >= alert_only_max:
        return IPSAction(action="approve", reason=f"Risk score {risk_score:.1f} requires human approval")
    else:
        return IPSAction(action="alert", reason=f"Risk score {risk_score:.1f} — alert only")
