"""Audit log for IPS decisions (Allow / Block / Timeout).

Spec #6 — record every decision with the IP, risk score, decision
type, and timestamp. We use the standard ``logging`` package so the
output lands wherever the project's logging is configured (file,
stdout, etc.) without adding a new dependency.

A single ``AuditStore`` would be overkill for this — the python
``logging`` module IS the audit store, and `%(asctime)s` already
gives the timestamp.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional


_audit_log = logging.getLogger("sentinelscan.ips.audit")


def log_decision(action, decision: str, by: str, extra: Optional[Dict[str, Any]] = None) -> None:
    """Record a single IPS decision.

    :param action: the PendingAction that was decided.
    :param decision: one of "allow", "block", "timeout_block".
    :param by: who decided ("dashboard", "telegram", "timeout").
    :param extra: optional dict of additional context (firewall result, ttl, ...).
    """
    extra = extra or {}
    _audit_log.info(
        "decision=%s ip=%s risk=%.1f threat=%s by=%s action_id=%s%s",
        decision,
        getattr(action, "source_ip", "?"),
        getattr(action, "risk_score", 0.0),
        getattr(action, "threat_type", "?"),
        by,
        getattr(action, "id", "?"),
        " " + " ".join(f"{k}={v}" for k, v in extra.items()) if extra else "",
    )
