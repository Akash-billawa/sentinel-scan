"""Approval Manager — handles pending IPS actions requiring operator review.

When the detection engine finds a threat that requires approval (per IPS policy),
it creates a pending action here. The operator can approve or deny via:
- Dashboard API
- Telegram bot commands
- Direct API calls

Pending actions auto-expire after a configurable timeout (default: 60 seconds).
"""

from __future__ import annotations

import json
import logging
import threading
import time as _time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional

from .config import get_settings

log = logging.getLogger("sentinelscan.ips.approval")


class ActionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    EXECUTED = "executed"


@dataclass
class PendingAction:
    """A single pending IPS action requiring operator review."""

    id: str
    attack_id: int
    source_ip: str
    destination_ip: str = ""           # added: target of the scan
    threat_type: str = ""
    risk_score: float = 0.0
    risk_level: str = "low"
    confidence: float = 0.0
    ports: List[int] = field(default_factory=list)   # added: ports touched
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    status: ActionStatus = ActionStatus.PENDING
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    reason: str = ""

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "attack_id": self.attack_id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "threat_type": self.threat_type,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "ports": list(self.ports or []),
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
            "expires_at": self.expires_at.isoformat() + "Z" if self.expires_at else None,
            "status": self.status.value,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat() + "Z" if self.decided_at else None,
            "executed_at": self.executed_at.isoformat() + "Z" if self.executed_at else None,
            "reason": self.reason,
        }


# Callback type for when an action is decided
ActionCallback = Callable[[PendingAction], None]


class ApprovalManager:
    """Thread-safe manager for pending IPS approval actions."""

    def __init__(self, timeout_seconds: int = 60) -> None:
        self._actions: Dict[str, PendingAction] = {}
        self._lock = threading.Lock()
        self._callbacks: List[ActionCallback] = []
        self._timeout = timeout_seconds
        self._expiry_thread: Optional[threading.Thread] = None
        self._running = False

    @property
    def timeout(self) -> int:
        """Return the approval timeout in seconds."""
        return self._timeout

    def start(self) -> None:
        """Start the expiry checker thread."""
        if self._running:
            return
        self._running = True
        self._expiry_thread = threading.Thread(
            target=self._expiry_loop, name="approval-expiry", daemon=True
        )
        self._expiry_thread.start()
        log.info("Approval manager started (timeout=%ds)", self._timeout)

    def stop(self) -> None:
        """Stop the expiry checker."""
        self._running = False
        if self._expiry_thread:
            self._expiry_thread.join(timeout=2.0)
            self._expiry_thread = None
        log.info("Approval manager stopped")

    def add_callback(self, fn: ActionCallback) -> None:
        """Register a callback for when actions are decided."""
        with self._lock:
            self._callbacks.append(fn)

    def create_action(
        self,
        attack_id: int,
        source_ip: str,
        threat_type: str,
        risk_score: float,
        risk_level: str,
        confidence: float,
        reason: str = "",
        destination_ip: str = "",
        ports: Optional[List[int]] = None,
    ) -> PendingAction:
        """Create a new pending approval action."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        action_id = f"evt_{uuid.uuid4().hex[:8]}"

        action = PendingAction(
            id=action_id,
            attack_id=attack_id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            threat_type=threat_type,
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            ports=list(ports or []),
            created_at=now,
            expires_at=now + timedelta(seconds=self._timeout),
            reason=reason,
        )

        with self._lock:
            self._actions[action_id] = action

        log.info(
            "Created approval action %s for %s -> %s (%s, risk=%.1f, ports=%s)",
            action_id, source_ip, destination_ip or "?", threat_type, risk_score, action.ports,
        )
        return action

    def approve(self, action_id: str, by: str = "operator") -> Optional[PendingAction]:
        """Approve a pending action."""
        with self._lock:
            action = self._actions.get(action_id)
            if not action or action.status != ActionStatus.PENDING:
                return None
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            action.status = ActionStatus.APPROVED
            action.decided_by = by
            action.decided_at = now
        log.info("Action %s APPROVED by %s", action_id, by)
        self._fire_callbacks(action)
        return action

    def deny(self, action_id: str, by: str = "operator") -> Optional[PendingAction]:
        """Deny a pending action."""
        with self._lock:
            action = self._actions.get(action_id)
            if not action or action.status != ActionStatus.PENDING:
                return None
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            action.status = ActionStatus.DENIED
            action.decided_by = by
            action.decided_at = now
        log.info("Action %s DENIED by %s", action_id, by)
        self._fire_callbacks(action)
        return action

    def mark_executed(self, action_id: str) -> None:
        """Mark an approved action as executed (firewall rule applied)."""
        with self._lock:
            action = self._actions.get(action_id)
            if action:
                action.status = ActionStatus.EXECUTED
                action.executed_at = datetime.now(timezone.utc).replace(tzinfo=None)

    def get_action(self, action_id: str) -> Optional[PendingAction]:
        """Get a pending action by ID."""
        with self._lock:
            return self._actions.get(action_id)

    def list_pending(self) -> List[PendingAction]:
        """List all pending actions, newest first."""
        with self._lock:
            pending = [
                a for a in self._actions.values()
                if a.status == ActionStatus.PENDING
            ]
        pending.sort(key=lambda a: a.created_at, reverse=True)
        return pending

    def list_all(self, limit: int = 100) -> List[PendingAction]:
        """List all actions (any status), newest first."""
        with self._lock:
            actions = list(self._actions.values())
        actions.sort(key=lambda a: a.created_at, reverse=True)
        return actions[:limit]

    def cleanup_expired(self) -> int:
        """Expire all overdue pending actions. Returns count expired.

        Spec requirement #4: an action that times out defaults to **block**
        and is logged with reason "Approval Timeout". This mirrors what a
        human would do at the deadline — if they didn't say Allow, the
        safe default is to block.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        expired_count = 0
        newly_expired: List[PendingAction] = []
        with self._lock:
            for action in self._actions.values():
                if action.status == ActionStatus.PENDING and action.expires_at < now:
                    action.status = ActionStatus.EXPIRED
                    action.decided_by = "timeout"
                    action.decided_at = now
                    action.reason = (action.reason or "") + " | Approval Timeout"
                    expired_count += 1
                    newly_expired.append(action)
                    log.info("Action %s EXPIRED (no response — defaulting to block)", action.id)
        # Spec: timed-out actions default to BLOCK. Lazy-import so we don't
        # pull the firewall manager in until the first timeout actually fires.
        for action in newly_expired:
            self._fire_callbacks(action)
            try:
                from .firewall_manager import get_firewall_manager, BlockResult
                fw = get_firewall_manager()
                result = fw.block_ip(
                    action.source_ip,
                    reason=f"Approval Timeout: {action.threat_type} (risk={action.risk_score:.1f})",
                )
                if result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED):
                    self.mark_executed(action.id)
                # Spec #6 — audit-log the timeout
                from . import audit as _audit
                _audit.log_decision(action, "timeout_block", "timeout", {
                    "firewall_result": result.value,
                })
            except Exception as exc:
                log.error("Timeout-block failed for %s: %s", action.source_ip, exc)
            # Unmark from rate limiter either way — the decision window is closed.
            try:
                from .pending_rate_limiter import get_pending_rate_limiter
                get_pending_rate_limiter().unmark_pending(action.source_ip)
            except Exception:
                pass
        # Prune old non-pending actions to prevent unbounded memory growth.
        self._prune_old_actions()
        return expired_count

    def _prune_old_actions(self) -> None:
        """Remove non-pending actions older than 24 hours to cap memory."""
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
        with self._lock:
            to_remove = [
                aid for aid, a in self._actions.items()
                if a.status != ActionStatus.PENDING and a.created_at < cutoff
            ]
            for aid in to_remove:
                del self._actions[aid]
        if to_remove:
            log.debug("Pruned %d old approval actions", len(to_remove))

    def _expiry_loop(self) -> None:
        """Background thread that checks for expired actions."""
        while self._running:
            try:
                self.cleanup_expired()
            except Exception as exc:
                log.warning("Expiry check failed: %s", exc)
            # Sleep in small chunks so we can stop quickly
            for _ in range(60):  # 60 * 1s = 60s
                if not self._running:
                    return
                _time.sleep(1.0)

    def _fire_callbacks(self, action: PendingAction) -> None:
        """Fire all registered callbacks."""
        with self._lock:
            callbacks = list(self._callbacks)
        for fn in callbacks:
            try:
                fn(action)
            except Exception as exc:
                log.warning("Callback failed: %s", exc)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_manager: Optional[ApprovalManager] = None


def get_approval_manager() -> ApprovalManager:
    global _manager
    if _manager is None:
        settings = get_settings()
        _manager = ApprovalManager(timeout_seconds=settings.ips_approval_timeout)
    return _manager
