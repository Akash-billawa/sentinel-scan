"""Firewall Manager — applies block/unblock rules via OS firewall.

Production-grade firewall enforcement for SentinelScan's Human-in-the-Loop
IPS. A *backend* abstracts the platform differences; the manager picks
the best available backend at startup and delegates.

Supported backends:
    * WindowsDefenderBackend  — ``New-NetFirewallRule`` (Windows)
    * LinuxIptablesBackend    — ``iptables`` (legacy Linux)
    * LinuxNftablesBackend    — ``nftables`` (modern Linux, preferred)

Persistence, dedup, validation, expiry, and audit logging are owned by
:class:`FirewallManager`. Each backend is responsible only for translating
an add/remove request into the OS-specific command.

Safety:
    * ``127.0.0.0/8``, ``169.254.0.0/16``, multicast, broadcast and
      ``SENTINEL_PROTECTED_CIDRS`` are refused by default — see
      :func:`_is_protected_ip`.
    * Duplicate block returns ``BlockResult.ALREADY_BLOCKED`` without
      touching the OS.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import re
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timedelta
import time as _time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from . import database as db

log = logging.getLogger("sentinelscan.ips.firewall")


class BlockResult(str, Enum):
    """Tri-state outcome of a block/unblock attempt so callers can distinguish
    'OS firewall rule applied' from 'only recorded in app state' from 'noop'.
    """
    APPLIED = "applied"
    RECORDED_ONLY = "recorded_only"   # OS firewall not applied (no admin / unsupported)
    ALREADY_BLOCKED = "already_blocked"
    INVALID = "invalid"
    FAILED = "failed"
    UNAPPLIED = "unapplied"          # removed OS rule
    ALREADY_ABSENT = "already_absent"  # no rule to remove
    PARTIAL = "partial"              # removed from one chain only
    PROTECTED = "protected"          # refused: IP is loopback/multicast/broadcast/in protected CIDR


class EnforcementStatus(str, Enum):
    """Lifecycle of a block record, per spec #2.

    The transitions are:
        PENDING    — saved but the OS hasn't been asked yet
        APPLIED    — backend.apply_block returned True
        VERIFIED   — backend.verify_block confirmed the rule is in the OS
        FAILED     — apply_block or verify_block failed; see failure_reason
    """
    PENDING = "pending"
    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"


@dataclass
class _ReapplySummary:
    success: int = 0
    failed: int = 0
    finished_at: str = ""


def _validate_ip(ip: str) -> str:
    """Validate and return a canonical IP address string.

    Raises ``ValueError`` if the input is not a valid IPv4 or IPv6 address.
    This prevents any injection via crafted IP strings.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return str(addr)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip!r}")


def _sanitize_for_powershell(value: str) -> str:
    """Escape a string for safe embedding in a PowerShell single-quoted string.

    PowerShell single-quoted strings treat only ``'`` and ```` as special.
    We also strip any control characters that could break the command.
    """
    # Remove control characters (newlines, tabs, etc.)
    cleaned = re.sub(r'[\x00-\x1f\x7f]', '', value)
    # Escape single quotes by doubling them
    return cleaned.replace("'", "''")


@dataclass
class FirewallRule:
    """Represents a managed firewall rule."""

    ip: str
    direction: str  # "inbound" | "outbound" | "both"
    action: str     # "block" | "allow"
    rule_name: str
    created_at: str
    reason: str


class FirewallManager:
    """Manages OS firewall rules for IP blocking."""

    def __init__(self) -> None:
        self._platform = platform.system().lower()
        self._blocked_ips: Dict[str, FirewallRule] = {}
        self._lock = threading.Lock()  # protects _blocked_ips
        self._expiry_thread: Optional[threading.Thread] = None
        self._running = False
        # Health surface for /api/ips/status (loaded count + last load error).
        self._last_load_count: int = 0
        self._last_load_error: str = ""
        self._last_reapply = _ReapplySummary()
        # Windows-only: set to True at startup when SentinelScan is not
        # running as Administrator. When True, all OS firewall operations
        # fail-fast with a single clear error instead of spamming the log
        # with "Access is denied" on every boot / block attempt.
        self._windows_unprivileged: bool = False
        # Windows-only: set to True when the Windows Firewall service
        # (MpsSvc) is actually running. Without it, rules are stored but
        # never enforced at the OS level.
        self._windows_firewall_running: Optional[bool] = None
        self._load_blocked_from_db()
        self.start_expiry_checker()

    def _load_blocked_from_db(self) -> None:
        """Load previously blocked IPs from database on startup."""
        try:
            with db.session_scope() as s:
                from sqlalchemy import select
                rows = list(s.scalars(select(db.BlockedIP)))
                with self._lock:
                    for row in rows:
                        self._blocked_ips[row.ip] = FirewallRule(
                            ip=row.ip,
                            direction=row.direction,
                            action=row.action,
                            rule_name=row.rule_name,
                            created_at=row.created_at.isoformat() + "Z" if row.created_at else "",
                            reason=row.reason or "",
                        )
            self._last_load_count = len(self._blocked_ips)
            self._last_load_error = ""
            log.info("Loaded %d blocked IPs from database", len(self._blocked_ips))

            # Windows-only: if SentinelScan isn't running as Administrator,
            # every New-NetFirewallRule and schtasks call will fail with
            # "Access is denied". Detect this ONCE at startup and skip the
            # reapply / verify background threads so the log isn't flooded
            # with the same error on every boot.
            if self._platform == "windows":
                self._windows_firewall_running = _is_firewall_service_running()
                if not _is_elevated():
                    self._windows_unprivileged = True
                    log.error(
                        "SentinelScan is NOT running as Administrator on Windows. "
                        "OS firewall operations are disabled until you restart "
                        "run.py with 'Run as Administrator'. Loaded %d blocked IPs "
                        "from database but skipping reapply / verify on boot.",
                        len(self._blocked_ips),
                    )
                    return

            # Re-apply firewall rules on startup (iptables rules are lost on reboot)
            if self._blocked_ips:
                from .config import get_settings
                settings = get_settings()
                if settings.ips_reapply_on_boot:
                    t = threading.Thread(
                        target=self._reapply_firewall_rules,
                        name="firewall-reapply",
                        daemon=True,
                    )
                    t.start()

                # Spec #6: on every startup, verify every persisted block
                # actually exists in the OS. Repair missing rules; mark
                # permanently-broken ones FAILED.
                t2 = threading.Thread(
                    target=self._verify_persisted_rules,
                    name="firewall-verify",
                    daemon=True,
                )
                t2.start()

        except Exception as exc:
            self._last_load_count = len(self._blocked_ips)
            self._last_load_error = str(exc)
            # Ponytail: warn loudly — empty state here means yesterday's blocks
            # are silently dropped. Operator must see this on the status page.
            log.error("Failed to load blocked IPs: %s", exc)

    def health(self) -> Dict[str, object]:
        """Return a small status snapshot for /api/ips/status."""
        with self._lock:
            blocked_count = len(self._blocked_ips)
        return {
            "blocked_count": blocked_count,
            "last_load_count": self._last_load_count,
            "last_load_error": self._last_load_error,
            "last_reapply": {
                "success": self._last_reapply.success,
                "failed": self._last_reapply.failed,
                "finished_at": self._last_reapply.finished_at,
            },
            # Expose Windows elevation state so the dashboard can show a
            # single "Run as Administrator" banner instead of the user
            # having to read the stderr of every block attempt.
            "windows_unprivileged": self._windows_unprivileged,
            "windows_firewall_running": self._windows_firewall_running,
            "enforcement_available": _can_enforce_os_firewall(),
        }

    def _reapply_firewall_rules(self) -> None:
        """Re-apply all blocked IPs to the OS firewall on startup."""
        reapplied = 0
        failed = 0
        with self._lock:
            items = list(self._blocked_ips.items())
        for ip, rule in items:
            try:
                if self._platform == "windows":
                    success, diag = _block_windows(ip, rule.rule_name, rule.direction)
                elif self._platform == "linux":
                    success, diag = _block_linux(ip, rule.rule_name, rule.direction)
                else:
                    success, diag = False, {"apply_stderr": "unsupported platform"}

                if success:
                    reapplied += 1
                else:
                    failed += 1
                    log.warning("Failed to re-apply firewall rule for %s: rc=%s stderr=%s",
                                ip, diag.get("apply_exit_code"), str(diag.get("apply_stderr") or "")[:200])
            except Exception as exc:
                failed += 1
                log.warning("Error re-applying firewall rule for %s: %s", ip, exc)

        from datetime import datetime, timezone
        self._last_reapply = _ReapplySummary(
            success=reapplied,
            failed=failed,
            finished_at=datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        )

        if reapplied > 0 or failed > 0:
            log.info("Firewall rules re-applied: %d success, %d failed", reapplied, failed)

    # --- Startup verification + repair (spec #6) ---------------------------

    def _verify_persisted_rules(self) -> None:
        """Walk every un-removed BlockedIP row and confirm the OS still has it.

        For each row:
          * If the OS confirms the rule → status=VERIFIED, verified_at=now.
          * If the OS says no → try to re-apply. If re-apply+verify works,
            mark VERIFIED. Otherwise mark FAILED with the last error so the
            dashboard shows the operator what's broken on boot.
        """
        from datetime import datetime, timezone
        backend = get_backend()
        try:
            from sqlalchemy import select
            with db.session_scope() as s:
                rows = list(s.scalars(
                    select(db.BlockedIP)
                    .where(db.BlockedIP.removed_at.is_(None))
                ))
        except Exception as exc:
            log.error("Startup verification could not load DB rows: %s", exc)
            return

        if not rows:
            return
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        verified_count = 0
        repaired_count = 0
        failed_count = 0
        for row in rows:
            try:
                ok, detail = backend.verify_block(row.ip, row.rule_name)
                if ok:
                    _update_db_status(
                        row.ip, status=EnforcementStatus.VERIFIED.value,
                        verified_at=now, failure_reason=None,
                    )
                    verified_count += 1
                    continue
                # Missing — try one re-apply+verify pass.
                reapplied, diag = backend.apply_block(row.ip, row.rule_name, row.direction or "inbound")
                if reapplied:
                    ok2, detail2 = backend.verify_block(row.ip, row.rule_name)
                    if ok2:
                        _update_db_status(
                            row.ip, status=EnforcementStatus.VERIFIED.value,
                            verified_at=now, failure_reason=None,
                            apply_exit_code=diag.get("apply_exit_code"),
                            apply_stdout=diag.get("apply_stdout", ""),
                            apply_stderr=diag.get("apply_stderr", ""),
                            apply_exception=diag.get("apply_exception", ""),
                            apply_command=diag.get("apply_command", ""),
                            direct_apply_command=diag.get("direct_apply_command", ""),
                            direct_apply_exit_code=diag.get("direct_apply_exit_code"),
                            direct_apply_stdout=diag.get("direct_apply_stdout", ""),
                            direct_apply_stderr=diag.get("direct_apply_stderr", ""),
                            direct_apply_exception=diag.get("direct_apply_exception", ""),
                            fallback_apply_command=diag.get("fallback_apply_command", ""),
                            fallback_apply_exit_code=diag.get("fallback_apply_exit_code"),
                            fallback_apply_stdout=diag.get("fallback_apply_stdout", ""),
                            fallback_apply_stderr=diag.get("fallback_apply_stderr", ""),
                            fallback_apply_exception=diag.get("fallback_apply_exception", ""),
                            last_attempt_path=diag.get("last_attempt_path", ""),
                        )
                        _save_to_db(
                            row.ip, row.direction or "inbound", row.action,
                            row.rule_name, row.reason,
                            status=EnforcementStatus.VERIFIED.value,
                            backend=backend.name, verified_at=now,
                        )
                        _audit_block_decision(
                            row.ip, "startup_repair", "startup", row.reason or "",
                            extra={"backend": backend.name, "detail": detail},
                        )
                        repaired_count += 1
                        continue
                    detail = detail2
                # Permanent failure. Capture apply-block diagnostics so the
                # operator sees the exact command, rc and stderr on the row.
                _update_db_status(
                    row.ip, status=EnforcementStatus.FAILED.value,
                    verified_at=None, failure_reason=detail,
                    apply_exit_code=diag.get("apply_exit_code"),
                    apply_stdout=diag.get("apply_stdout", ""),
                    apply_stderr=diag.get("apply_stderr", ""),
                    apply_exception=diag.get("apply_exception", ""),
                    apply_command=diag.get("apply_command", ""),
                    direct_apply_command=diag.get("direct_apply_command", ""),
                    direct_apply_exit_code=diag.get("direct_apply_exit_code"),
                    direct_apply_stdout=diag.get("direct_apply_stdout", ""),
                    direct_apply_stderr=diag.get("direct_apply_stderr", ""),
                    direct_apply_exception=diag.get("direct_apply_exception", ""),
                    fallback_apply_command=diag.get("fallback_apply_command", ""),
                    fallback_apply_exit_code=diag.get("fallback_apply_exit_code"),
                    fallback_apply_stdout=diag.get("fallback_apply_stdout", ""),
                    fallback_apply_stderr=diag.get("fallback_apply_stderr", ""),
                    fallback_apply_exception=diag.get("fallback_apply_exception", ""),
                    last_attempt_path=diag.get("last_attempt_path", ""),
                )
                _audit_block_decision(
                    row.ip, "startup_verify_failed", "startup", row.reason or "",
                    extra={"backend": backend.name, "detail": detail,
                           "apply_exit_code": diag.get("apply_exit_code")},
                )
                failed_count += 1
            except Exception as exc:
                log.error("Startup verification raised for %s: %s", row.ip, exc)
                failed_count += 1
        log.info(
            "Startup firewall verification: %d verified, %d repaired, %d failed",
            verified_count, repaired_count, failed_count,
        )

    # --- Expiry checker ---------------------------------------------------

    def start_expiry_checker(self) -> None:
        """Start the background thread that checks for expired blocks."""
        if self._running:
            return
        self._running = True
        self._expiry_thread = threading.Thread(
            target=self._expiry_loop,
            name="firewall-expiry",
            daemon=True,
        )
        self._expiry_thread.start()

    def stop_expiry_checker(self) -> None:
        """Stop the expiry checker."""
        self._running = False
        if self._expiry_thread:
            self._expiry_thread.join(timeout=2.0)
            self._expiry_thread = None

    def _expiry_loop(self) -> None:
        """Background thread that checks for expired blocks."""
        while self._running:
            try:
                self._check_expired_blocks()
            except Exception as exc:
                log.warning("Expiry check failed: %s", exc)
            # Sleep in small chunks so we can stop quickly
            for _ in range(60):  # 60 * 1s = 60s
                if not self._running:
                    return
                _time.sleep(1.0)

    def _check_expired_blocks(self) -> None:
        """Check for and remove expired blocks."""
        try:
            from .config import get_settings
            settings = get_settings()
        except Exception:
            return

        # Skip if expiry is disabled
        if settings.ips_block_expiry <= 0:
            return

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        expired_ips = []

        # Check each blocked IP for expiry
        with self._lock:
            items = list(self._blocked_ips.items())
        for ip, rule in items:
            if not rule.created_at:
                continue
            try:
                created = datetime.fromisoformat(rule.created_at.replace("Z", "+00:00")).replace(tzinfo=None)
                elapsed = (now - created).total_seconds()
                if elapsed > settings.ips_block_expiry:
                    expired_ips.append(ip)
            except (ValueError, TypeError):
                continue

        # Unblock expired IPs
        for ip in expired_ips:
            log.info("Block expired for %s (after %ds)", ip, settings.ips_block_expiry)
            self.unblock_ip(ip)

    def block_ip(self, ip: str, reason: str = "", direction: str = "inbound",
                 decision_source: str = "operator") -> BlockResult:
        """Block an IP via the configured backend. See :class:`BlockResult`."""
        try:
            ip = _validate_ip(ip)
        except ValueError as exc:
            log.error("block_ip rejected invalid IP: %s", exc)
            return BlockResult.INVALID

        # Spec #5: refuse protected IPs to prevent accidental self-block.
        if _is_protected_ip(ip):
            log.warning(
                "block_ip REFUSED protected IP %s (reason=%r source=%s)",
                ip, reason, decision_source,
            )
            _audit_block_decision(ip, "refused_protected", decision_source, reason)
            return BlockResult.PROTECTED

        with self._lock:
            if ip in self._blocked_ips:
                log.info("IP %s is already blocked", ip)
                return BlockResult.ALREADY_BLOCKED

        rule_name = f"SentinelScan Block {ip}"
        try:
            backend = get_backend()
            # Phase 1: apply. Backend now returns (ok, diag) so we can
            # surface the exact command/rc/stderr on the dashboard row.
            applied, diag = backend.apply_block(ip, rule_name, direction)

            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).replace(tzinfo=None)

            # Phase 2: verify (spec #1). ``apply_block`` returning ok=True
            # only means the OS accepted the command — verify_block proves
            # the rule is actually present.
            verified = False
            verify_detail = "verification skipped (apply_block did not report success)"
            if applied:
                verified, verify_detail = backend.verify_block(ip, rule_name)

            status = (
                EnforcementStatus.VERIFIED if verified
                else EnforcementStatus.FAILED
            )
            failure_reason = None if verified else verify_detail

            rule = FirewallRule(
                ip=ip, direction=direction, action="block",
                rule_name=rule_name, created_at=now.isoformat() + "Z",
                reason=reason,
            )
            with self._lock:
                self._blocked_ips[ip] = rule

            # Persist with verification + apply-block diagnostics.
            _save_to_db(
                ip, direction, "block", rule_name, reason,
                status=status.value, backend=backend.name,
                verified_at=now if verified else None,
                failure_reason=failure_reason,
                apply_exit_code=diag.get("apply_exit_code"),
                apply_stdout=diag.get("apply_stdout", ""),
                apply_stderr=diag.get("apply_stderr", ""),
                apply_exception=diag.get("apply_exception", ""),
                apply_command=diag.get("apply_command", ""),
                direct_apply_command=diag.get("direct_apply_command", ""),
                direct_apply_exit_code=diag.get("direct_apply_exit_code"),
                direct_apply_stdout=diag.get("direct_apply_stdout", ""),
                direct_apply_stderr=diag.get("direct_apply_stderr", ""),
                direct_apply_exception=diag.get("direct_apply_exception", ""),
                fallback_apply_command=diag.get("fallback_apply_command", ""),
                fallback_apply_exit_code=diag.get("fallback_apply_exit_code"),
                fallback_apply_stdout=diag.get("fallback_apply_stdout", ""),
                fallback_apply_stderr=diag.get("fallback_apply_stderr", ""),
                fallback_apply_exception=diag.get("fallback_apply_exception", ""),
                last_attempt_path=diag.get("last_attempt_path", ""),
            )
            _audit_block_decision(ip, "block", decision_source, reason, extra={
                "backend": backend.name,
                "applied": applied,
                "verified": verified,
                "status": status.value,
                "verify_detail": verify_detail if not verified else "",
                "apply_exit_code": diag.get("apply_exit_code"),
            })
            if verified:
                log.info("Blocked+VERIFIED IP %s via %s (source=%s)",
                         ip, backend.name, decision_source)
                return BlockResult.APPLIED
            if applied:
                # OS accepted the command but verification failed — surface
                # as RECORDED_ONLY so the dashboard shows the FAILED state.
                log.warning("Block for %s applied but VERIFICATION FAILED: %s",
                            ip, verify_detail)
                return BlockResult.RECORDED_ONLY
            log.warning("Block for %s did NOT apply via %s: %s",
                        ip, backend.name, verify_detail)
            return BlockResult.RECORDED_ONLY

        except Exception as exc:
            log.error("Failed to block IP %s: %s", ip, exc)
            _audit_block_decision(ip, "block_failed", decision_source, reason, extra={
                "error": str(exc),
            })
            return BlockResult.FAILED

    def unblock_ip(self, ip: str, decision_source: str = "operator") -> BlockResult:
        """Remove a block rule via the configured backend."""
        try:
            ip = _validate_ip(ip)
        except ValueError:
            return BlockResult.INVALID
        with self._lock:
            if ip not in self._blocked_ips:
                log.info("IP %s is not blocked", ip)
                return BlockResult.ALREADY_ABSENT
            rule = self._blocked_ips[ip]

        try:
            backend = get_backend()
            result = backend.remove_block(ip, rule.rule_name)
            # Spec #4: sync SentinelScan state with OS firewall state.
            if result in (BlockResult.UNAPPLIED, BlockResult.PARTIAL, BlockResult.ALREADY_ABSENT):
                with self._lock:
                    self._blocked_ips.pop(ip, None)
                _remove_from_db(ip)
            log.info("Unblocked IP %s via %s (source=%s, result=%s)",
                     ip, backend.name, decision_source, result.value)
            _audit_block_decision(ip, "unblock", decision_source, rule.reason, extra={
                "backend": backend.name,
                "result": result.value,
            })
            return result

        except Exception as exc:
            log.error("Failed to unblock IP %s: %s", ip, exc)
            _audit_block_decision(ip, "unblock_failed", decision_source, rule.reason, extra={
                "error": str(exc),
            })
            return BlockResult.FAILED

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        with self._lock:
            return ip in self._blocked_ips

    def list_blocked(self) -> List[FirewallRule]:
        """List all currently blocked IPs."""
        with self._lock:
            return list(self._blocked_ips.values())

# --- Windows implementation ---

def _is_elevated() -> bool:
    """Return True when the current process runs as Administrator.

    Cheap probe: ``net session`` succeeds only for accounts in the
    local Administrators group (TokenElevationType == Full). If it fails
    or times out, treat as non-elevated.
    """
    try:
        r = subprocess.run(
            ["net", "session"],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _is_firewall_service_running() -> Optional[bool]:
    """Return True when the Windows Firewall service (MpsSvc) is running.

    Returns None when not on Windows. Without the firewall service,
    ``New-NetFirewallRule`` commands succeed but no filtering is enforced
    at the OS level.
    """
    if platform.system().lower() != "windows":
        return None
    try:
        r = subprocess.run(
            ["sc", "query", "MpsSvc"],
            capture_output=True, text=True, timeout=10,
        )
        return "RUNNING" in r.stdout
    except Exception:
        return None


def _can_enforce_os_firewall() -> bool:
    """Return True when the OS can actually enforce block rules.

    On Windows this requires: Administrator privileges AND the Windows
    Firewall service (MpsSvc) to be running. On Linux it only requires
    iptables/nftables to be functional (checked by backend probe at
    startup).
    """
    p = platform.system().lower()
    if p == "windows":
        return _is_elevated() and (_is_firewall_service_running() is not False)
    return True  # Linux backends work as long as the binary is present


def _powershell_run(ps_script: str, timeout: int = 30) -> tuple:
    """Invoke a PowerShell script synchronously and return (rc, stdout, stderr).

    Uses ``powershell -NoProfile -ExecutionPolicy Bypass -Command <script>``
    so the calling shell's ExecutionPolicy never blocks us. The function is
    synchronous on purpose: the caller needs to know the rule exists
    *before* verify_block queries the OS.
    """
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", ps_script,
    ]
    log.debug("firewall._powershell_run CMD=%s", cmd)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        log.debug(
            "firewall._powershell_run rc=%s stdout=%r stderr=%r",
            r.returncode, str(r.stdout or "")[:500], str(r.stderr or "")[:500],
        )
        return (r.returncode, r.stdout or "", r.stderr or "")
    except FileNotFoundError:
        return (127, "", "powershell.exe not found on PATH")
    except subprocess.TimeoutExpired:
        return (124, "", f"powershell timed out after {timeout}s")
    except Exception as exc:
        return (1, "", f"subprocess.run raised: {exc!r}")


def _run_via_schtasks(task_name: str, ps_script: str, wait_seconds: float = 10.0) -> tuple:
    """Run ``ps_script`` as SYSTEM via schtasks.

    Windows refuses /tr payloads longer than 261 characters, so we
    write the script to a short-lived temp file and reference it from
    /tr. Returns (rc, stdout, stderr) from the elevated PowerShell,
    or a non-zero rc if the schtasks /create or /run itself fails.
    """
    import tempfile
    import os as _os
    fd, path = tempfile.mkstemp(suffix=".ps1", prefix="sentinelscan-")
    try:
        with _os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(ps_script)
        # /tr value: "powershell -NoProfile -ExecutionPolicy Bypass -File <path>"
        tr = 'powershell -NoProfile -ExecutionPolicy Bypass -File "' + path + '"'
        create_cmd = [
            "schtasks", "/create", "/tn", task_name,
            "/tr", tr, "/sc", "once", "/st", (datetime.now() + timedelta(minutes=1)).strftime("%H:%M"),
            "/ru", "SYSTEM", "/rl", "HIGHEST", "/f",
        ]
        log.debug("firewall._run_via_schtasks CMD=%s", create_cmd)
        cr = subprocess.run(create_cmd, capture_output=True, text=True, timeout=15)
        log.debug("firewall._run_via_schtasks create rc=%s stderr=%r",
                  cr.returncode, cr.stderr)
        if cr.returncode != 0:
            return (cr.returncode, "", "schtasks /create failed: " + cr.stderr.strip())
        rr = subprocess.run(
            ["schtasks", "/run", "/tn", task_name],
            capture_output=True, text=True, timeout=30,
        )
        log.debug("firewall._run_via_schtasks run rc=%s stdout=%r stderr=%r",
                  rr.returncode, rr.stdout, rr.stderr)
        # The /run call returns once the task is queued. Poll for the
        # script file to be released (Windows holds the handle open
        # while the script runs), or until wait_seconds elapses.
        waited = 0.0
        while waited < wait_seconds:
            try:
                _os.rename(path, path + ".done")
                # If we got here, the elevated PowerShell has released the file.
                try:
                    _os.remove(path + ".done")
                except OSError:
                    pass
                return (0, "", "")
            except OSError:
                _time.sleep(0.2)
                waited += 0.2
        return (124, "", "schtasks /run timed out after " + str(wait_seconds) + "s")
    finally:
        try:
            _os.remove(path)
        except OSError:
            pass
        # Best-effort cleanup of the scheduled task itself.
        try:
            subprocess.run(["schtasks", "/delete", "/tn", task_name, "/f"],
                           capture_output=True, text=True, timeout=10)
        except Exception as exc:
            log.debug("schtasks cleanup failed for %s: %s", task_name, exc)


def _block_windows(ip: str, rule_name: str, direction: str) -> tuple:
    """Create a Windows Defender Firewall rule blocking ``ip``.

    Runs ``New-NetFirewallRule`` directly via PowerShell. Requires the
    SentinelScan process itself to be elevated (Administrator). If the
    direct call fails with a permission error, fall back to ``schtasks``
    to launch the same PowerShell as SYSTEM — useful for environments
    where the service runs as a service account without elevation.

    Returns ``(ok, diag)``. ``diag`` always contains every forensic field
    (command, exit_code, stdout, stderr, exception) so a FAILED row in
    the DB tells the operator exactly what went wrong.
    """
    # Fail fast when SentinelScan isn't running as Administrator on Windows.
    # Both the direct PowerShell path and the schtasks SYSTEM fallback need
    # elevation; without it every attempt produces the same "Access is denied"
    # noise. Surface a single, clear explanation instead.
    if not _is_elevated():
        diag: Dict[str, object] = {
            "apply_command": "",
            "apply_exit_code": None,
            "apply_stdout": "",
            "apply_stderr": (
                "SentinelScan is not running as Administrator on Windows. "
                "Restart run.py with 'Run as Administrator' to enable "
                "firewall rule enforcement."
            ),
            "apply_exception": "",
            "direct_apply_command": "",
            "direct_apply_exit_code": None,
            "direct_apply_stdout": "",
            "direct_apply_stderr": "",
            "direct_apply_exception": "",
            "fallback_apply_command": "",
            "fallback_apply_exit_code": None,
            "fallback_apply_stdout": "",
            "fallback_apply_stderr": "",
            "fallback_apply_exception": "",
            "last_attempt_path": "",
        }
        log.debug(
            "firewall._block_windows skipped for %s: not running as Administrator",
            ip,
        )
        return (False, diag)
    ps_cmd_repr = "powershell -NoProfile -ExecutionPolicy Bypass -Command <New-NetFirewallRule>"
    diag: Dict[str, object] = {
        # Last attempt (= source of the final status). Overwritten in-place
        # below when the schtasks fallback runs.
        "apply_command": "",
        "apply_exit_code": None,
        "apply_stdout": "",
        "apply_stderr": "",
        "apply_exception": "",
        # Phase 6 dual-path: direct = New-NetFirewallRule; fallback = schtasks
        # SYSTEM. Both preserved so the operator can see why each path
        # failed independently of the final outcome.
        "direct_apply_command": "",
        "direct_apply_exit_code": None,
        "direct_apply_stdout": "",
        "direct_apply_stderr": "",
        "direct_apply_exception": "",
        "fallback_apply_command": "",
        "fallback_apply_exit_code": None,
        "fallback_apply_stdout": "",
        "fallback_apply_stderr": "",
        "fallback_apply_exception": "",
        "last_attempt_path": "",
    }
    log.debug(
        "firewall._block_windows START ip=%s rule=%r dir=%s elevated=%s",
        ip, rule_name, direction, _is_elevated(),
    )
    safe_ip = _sanitize_for_powershell(ip)
    safe_rule_name = _sanitize_for_powershell(rule_name)

    ps_script = (
        "$ErrorActionPreference = 'Stop'; "
        "Get-NetFirewallRule -DisplayName '" + safe_rule_name + "' "
        "-ErrorAction SilentlyContinue | Remove-NetFirewallRule "
        "-ErrorAction SilentlyContinue; "
        "$rule = New-NetFirewallRule "
        "-DisplayName '" + safe_rule_name + "' "
        "-Direction Inbound -RemoteAddress " + safe_ip + " "
        "-Action Block -Description 'SentinelScan IPS auto-block'; "
        "Write-Output ('OK ' + $rule.Name)"
    )
    diag["apply_command"] = ps_cmd_repr
    diag["direct_apply_command"] = ps_cmd_repr
    diag["last_attempt_path"] = "direct"
    log.debug("firewall._block_windows New-NetFirewallRule SCRIPT=%s", ps_script)

    rc, stdout, stderr = _powershell_run(ps_script, timeout=30)
    diag["apply_exit_code"] = rc
    diag["apply_stdout"] = stdout or ""
    diag["apply_stderr"] = stderr or ""
    diag["direct_apply_exit_code"] = rc
    diag["direct_apply_stdout"] = stdout or ""
    diag["direct_apply_stderr"] = stderr or ""
    log.debug(
        "firewall._block_windows powershell rc=%s stdout=%r stderr=%r",
        rc, str(stdout or "")[:500], str(stderr or "")[:500],
    )
    if rc == 0 and stdout.strip().startswith("OK "):
        log.info("firewall._block_windows OK rule=%r ip=%s", rule_name, ip)
        return (True, diag)

    # Direct call failed — try schtasks SYSTEM fallback. The diagnostic
    # surface for the direct attempt stays in direct_apply_* — we don't
    # clobber it. The apply_* mirror is overwritten to reflect the last
    # attempt (= the fallback) so the row tells the truth about which
    # command's result determined the final status.
    log.warning(
        "firewall._block_windows direct PowerShell failed "
        "(rc=%s stderr=%r) — falling back to schtasks SYSTEM",
        rc, stderr.strip(),
    )
    task_name = "SentinelScan-Block-" + ip.replace(".", "-")
    fallback_command_repr = (
        "schtasks SYSTEM -> powershell -NoProfile -ExecutionPolicy Bypass "
        "-File <SentinelScan-Block.ps1>  (script: " + ps_script + ")"
    )
    try:
        rc2, out2, err2 = _run_via_schtasks(task_name, ps_script, wait_seconds=10.0)
        # Mirror the schtasks result into BOTH apply_* (last attempt) and
        # fallback_apply_* (preserved diagnostic of the fallback itself).
        diag["apply_exit_code"] = rc2
        diag["apply_stdout"] = (out2 or "")
        diag["apply_stderr"] = (err2 or "")
        diag["apply_command"] = fallback_command_repr
        diag["fallback_apply_command"] = fallback_command_repr
        diag["fallback_apply_exit_code"] = rc2
        diag["fallback_apply_stdout"] = (out2 or "")
        diag["fallback_apply_stderr"] = (err2 or "")
        diag["last_attempt_path"] = "fallback"
        log.debug("firewall._block_windows schtasks rc=%s stderr=%r", rc2, err2)
        if rc2 != 0:
            log.error("firewall._block_windows schtasks fallback failed: %s", err2)
            return (False, diag)
        # Now poll verify_block up to 10 s for the rule to appear.
        for _ in range(50):
            ok, _ = _verify_windows(rule_name, ip)
            if ok:
                log.info("firewall._block_windows schtasks fallback OK rule=%r", rule_name)
                return (True, diag)
            _time.sleep(0.2)
        log.error("firewall._block_windows schtasks fallback: rule still not present after 10s")
        diag["apply_stderr"] = (diag["apply_stderr"] or "") + "\nschtasks: rule not present after 10s poll"
        diag["fallback_apply_stderr"] = diag["apply_stderr"]
        return (False, diag)
    except Exception as exc:
        import traceback as _tb
        tb = _tb.format_exc()
        diag["apply_exception"] = tb
        diag["fallback_apply_exception"] = tb
        log.error("firewall._block_windows raised: %s", exc)
        return (False, diag)

def _verify_windows(rule_name: str, ip: str = "") -> tuple:
    """Return (ok, detail) confirming the named rule exists in Windows Firewall.

    When ``ip`` is supplied we additionally verify the rule's RemoteAddress
    set actually contains it — a stale rule with the same DisplayName but
    a different address is still a failure.
    """
    safe_name = _sanitize_for_powershell(rule_name)
    safe_ip = _sanitize_for_powershell(ip) if ip else ""
    if safe_ip:
        ps = (
            "$rule = Get-NetFirewallRule -DisplayName '" + safe_name + "' "
            "-ErrorAction SilentlyContinue; "
            "if ($rule -eq $null) { 'ABSENT' } else { "
            "  $addr = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule "
            "           -ErrorAction SilentlyContinue).RemoteAddress; "
            "  if ('" + safe_ip + "' -in $addr) { 'OK' } "
            "  else { 'ADDR_MISMATCH:' + ($addr -join ',') } "
            "}"
        )
    else:
        ps = (
            "if ((Get-NetFirewallRule -DisplayName '" + safe_name + "' "
            "-ErrorAction SilentlyContinue) -ne $null) { 'OK' } else { 'ABSENT' }"
        )
    rc, stdout, stderr = _powershell_run(ps, timeout=15)
    out = stdout.strip()
    if rc != 0:
        return (False, "powershell rc=" + str(rc) + " stderr=" + repr(stderr.strip()))
    if out == "OK":
        return (True, "verified: '" + rule_name + "' present" + (", remote=" + ip if ip else ""))
    if out.startswith("ADDR_MISMATCH"):
        rest = out.split(":", 1)[1]
        return (False, "rule present but RemoteAddress is " + repr(rest) + ", expected " + repr(ip))
    return (False, "rule '" + rule_name + "' not found in Windows Defender (stdout=" + repr(out) + ")")


def _cleanup_task(task_name: str) -> None:
    """Remove a scheduled task after use."""
    try:
        subprocess.run(
            ["schtasks", "/delete", "/tn", task_name, "/f"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as exc:
        # ponytail: best-effort cleanup; debug keeps noise low but visible if someone grep's for it
        log.debug("firewall task cleanup failed for %s: %s", task_name, exc)

def _unblock_windows(rule_name: str) -> BlockResult:
    """Remove a Windows firewall rule by name.

    Synchronous direct PowerShell call. When the direct call can't remove
    the rule (the running token lacks the privilege), falls back to
    schtasks SYSTEM — and waits for the elevated task to complete before
    returning.
    """
    log.debug("firewall._unblock_windows START rule=%r elevated=%s",
              rule_name, _is_elevated())
    safe_rule_name = _sanitize_for_powershell(rule_name)

    ps_script = (
        "$ErrorActionPreference = 'Stop'; "
        "$existing = Get-NetFirewallRule -DisplayName '" + safe_rule_name + "' "
        "-ErrorAction SilentlyContinue; "
        "if ($existing -eq $null) { Write-Output 'ABSENT'; exit 0 }; "
        "$existing | Remove-NetFirewallRule -ErrorAction Stop; "
        "$after = Get-NetFirewallRule -DisplayName '" + safe_rule_name + "' "
        "-ErrorAction SilentlyContinue; "
        "if ($after -eq $null) { Write-Output 'GONE' } else { Write-Output 'STILL_THERE' }"
    )
    rc, stdout, stderr = _powershell_run(ps_script, timeout=20)
    out = stdout.strip()
    log.debug("firewall._unblock_windows direct rc=%s stdout=%r stderr=%r",
              rc, out, stderr.strip())

    if out == "ABSENT":
        return BlockResult.ALREADY_ABSENT
    if out == "GONE":
        return BlockResult.UNAPPLIED
    if out == "STILL_THERE":
        # Direct call couldn't remove — try schtasks SYSTEM.
        log.warning("firewall._unblock_windows direct call left rule present; "
                    "falling back to schtasks SYSTEM")
        task_name = "SentinelScan-Unblock-" + rule_name.replace(" ", "-")
        ps_elev = (
            "Get-NetFirewallRule -DisplayName '" + safe_rule_name + "' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule"
        )
        cr, _out, err = _run_via_schtasks(task_name, ps_elev, wait_seconds=10.0)
        if cr != 0:
            log.error("firewall._unblock_windows schtasks fallback failed: %s", err)
            return BlockResult.FAILED
        for _ in range(50):
            ok, _ = _verify_windows(rule_name, "")
            if not ok:
                return BlockResult.UNAPPLIED
            _time.sleep(0.2)
        return BlockResult.FAILED

    # PowerShell failed outright.
    log.error("firewall._unblock_windows direct PowerShell failed "
              "(rc=%s stderr=%r stdout=%r)", rc, stderr.strip(), out)
    return BlockResult.FAILED


# --- Linux implementation ---

def _block_linux(ip: str, rule_name: str, direction: str) -> tuple:
    """Block IP using iptables.

    Honours direction (inbound, outbound, both).
    """
    diag: Dict[str, object] = {
        "apply_command": "",
        "apply_exit_code": None,
        "apply_stdout": "",
        "apply_stderr": "",
        "apply_exception": "",
    }
    try:
        directions = []
        if direction in ("inbound", "both"):
            directions.append(("INPUT", "-s"))
        if direction in ("outbound", "both"):
            directions.append(("OUTPUT", "-d"))

        success = True
        last_cmd = ""
        last_rc = None
        last_stdout = ""
        last_stderr = ""
        for chain, flag in directions:
            # Check if rule already exists
            check_cmd = ["iptables", "-C", chain, flag, ip, "-j", "DROP"]
            log.debug("firewall._block_linux CMD=%s", check_cmd)
            check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
            if check_result.returncode != 0:
                # Add new rule
                cmd = ["iptables", "-A", chain, flag, ip, "-j", "DROP"]
                log.debug("firewall._block_linux CMD=%s", cmd)
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                last_cmd = " ".join(cmd)
                last_rc = result.returncode
                last_stdout = result.stdout or ""
                last_stderr = result.stderr or ""
                log.debug("firewall._block_linux rc=%s stdout=%r stderr=%r",
                          result.returncode, str(last_stdout)[:500], str(last_stderr)[:500])
                if result.returncode != 0:
                    log.error("iptables failed for %s on %s: %s", flag, chain, result.stderr)
                    success = False
            else:
                log.info("iptables rule already exists for %s on %s", ip, chain)

        diag["apply_command"] = last_cmd
        diag["apply_exit_code"] = last_rc
        diag["apply_stdout"] = last_stdout
        diag["apply_stderr"] = last_stderr
        return (success, diag)
    except FileNotFoundError:
        log.error("iptables not found — cannot apply Linux firewall rule")
        diag["apply_exception"] = "iptables not found on PATH"
        return (False, diag)
    except subprocess.TimeoutExpired:
        log.error("iptables command timed out")
        diag["apply_exception"] = "iptables subprocess timed out"
        return (False, diag)
    except Exception as exc:
        import traceback as _tb
        diag["apply_exception"] = _tb.format_exc()
        log.error("firewall._block_linux raised: %s", exc)
        return (False, diag)

def _unblock_linux(ip: str) -> BlockResult:
    """Remove iptables rules for the given IP from both INPUT and OUTPUT chains.

    Returns:
      - UNAPPLIED      both chains removed
      - ALREADY_ABSENT neither chain had a rule
      - PARTIAL        one chain had a rule (still treat as success for caller)
      - FAILED         unexpected error
    """
    in_deleted = False
    out_deleted = False
    in_present = False
    out_present = False
    try:
        # Probe first so we know whether the rule existed before delete.
        r_in_check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10,
        )
        in_present = r_in_check.returncode == 0
        r_out_check = subprocess.run(
            ["iptables", "-C", "OUTPUT", "-d", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10,
        )
        out_present = r_out_check.returncode == 0

        if in_present:
            r_in = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10,
            )
            in_deleted = r_in.returncode == 0
            if not in_deleted:
                log.error("iptables INPUT delete failed for %s: %s", ip, r_in.stderr)
        if out_present:
            r_out = subprocess.run(
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10,
            )
            out_deleted = r_out.returncode == 0
            if not out_deleted:
                log.error("iptables OUTPUT delete failed for %s: %s", ip, r_out.stderr)

        if in_deleted or out_deleted:
            if in_present and out_present and not (in_deleted and out_deleted):
                return BlockResult.PARTIAL
            return BlockResult.UNAPPLIED
        return BlockResult.ALREADY_ABSENT
    except FileNotFoundError:
        log.error("iptables not found — cannot remove Linux firewall rule")
        return BlockResult.FAILED
    except subprocess.TimeoutExpired:
        log.error("iptables delete timed out for %s", ip)
        return BlockResult.FAILED

# --- Database persistence ---

def _save_to_db(ip: str, direction: str, action: str, rule_name: str,
                reason: str, status: Optional[str] = None,
                backend: Optional[str] = None,
                verified_at=None,
                failure_reason: Optional[str] = None,
                apply_exit_code: Optional[int] = None,
                apply_stdout: Optional[str] = None,
                apply_stderr: Optional[str] = None,
                apply_exception: Optional[str] = None,
                apply_command: Optional[str] = None,
                direct_apply_command: Optional[str] = None,
                direct_apply_exit_code: Optional[int] = None,
                direct_apply_stdout: Optional[str] = None,
                direct_apply_stderr: Optional[str] = None,
                direct_apply_exception: Optional[str] = None,
                fallback_apply_command: Optional[str] = None,
                fallback_apply_exit_code: Optional[int] = None,
                fallback_apply_stdout: Optional[str] = None,
                fallback_apply_stderr: Optional[str] = None,
                fallback_apply_exception: Optional[str] = None,
                last_attempt_path: Optional[str] = None) -> None:
    """Persist blocked IP to database with enforcement verification fields.

    Spec #2: every block attempt must end in VERIFIED or FAILED. If a
    caller passes ``status=None`` (or omits it) we treat that as a
    programming error and force FAILED — never PENDING — so the operator
    never sees a row stuck in the transient state.

    The five ``apply_*`` fields capture the exact apply_block command,
    rc, stdout, stderr, and exception so a FAILED row is debuggable
    without re-running the OS command by hand. The ``direct_apply_*`` /
    ``fallback_apply_*`` sets preserve diagnostics for BOTH execution
    paths (Windows direct New-NetFirewallRule vs schtasks SYSTEM fallback)
    so the operator can tell which path produced the final status.
    """
    if status is None:
        log.error(
            "_save_to_db called without explicit terminal status for %s — "
            "defaulting to FAILED (defensive: never write PENDING)",
            ip,
        )
        status = EnforcementStatus.FAILED.value
        failure_reason = failure_reason or "internal: _save_to_db called without status"
    if status not in (
        EnforcementStatus.VERIFIED.value,
        EnforcementStatus.FAILED.value,
        EnforcementStatus.PENDING.value,  # allowed only for legacy migration paths
        EnforcementStatus.APPLIED.value,  # allowed only as a transient
    ):
        log.error("_save_to_db rejected invalid status %r for %s", status, ip)
        status = EnforcementStatus.FAILED.value
        failure_reason = f"internal: invalid status {status!r}"

    try:
        from sqlalchemy import select
        with db.session_scope() as s:
            existing = s.scalar(
                select(db.BlockedIP)
                .where(db.BlockedIP.ip == ip, db.BlockedIP.removed_at.is_(None))
                .order_by(db.BlockedIP.id.desc())
            )
            if existing is not None:
                existing.direction = direction
                existing.action = action
                existing.rule_name = rule_name
                existing.reason = reason
                if status is not None:
                    existing.status = status
                if backend is not None:
                    existing.backend = backend
                if verified_at is not None:
                    existing.verified_at = verified_at
                if failure_reason is not None:
                    existing.failure_reason = failure_reason
                if apply_exit_code is not None:
                    existing.apply_exit_code = apply_exit_code
                if apply_stdout is not None:
                    existing.apply_stdout = apply_stdout
                if apply_stderr is not None:
                    existing.apply_stderr = apply_stderr
                if apply_exception is not None:
                    existing.apply_exception = apply_exception
                if apply_command is not None:
                    existing.apply_command = apply_command
                if direct_apply_command is not None:
                    existing.direct_apply_command = direct_apply_command
                if direct_apply_exit_code is not None:
                    existing.direct_apply_exit_code = direct_apply_exit_code
                if direct_apply_stdout is not None:
                    existing.direct_apply_stdout = direct_apply_stdout
                if direct_apply_stderr is not None:
                    existing.direct_apply_stderr = direct_apply_stderr
                if direct_apply_exception is not None:
                    existing.direct_apply_exception = direct_apply_exception
                if fallback_apply_command is not None:
                    existing.fallback_apply_command = fallback_apply_command
                if fallback_apply_exit_code is not None:
                    existing.fallback_apply_exit_code = fallback_apply_exit_code
                if fallback_apply_stdout is not None:
                    existing.fallback_apply_stdout = fallback_apply_stdout
                if fallback_apply_stderr is not None:
                    existing.fallback_apply_stderr = fallback_apply_stderr
                if fallback_apply_exception is not None:
                    existing.fallback_apply_exception = fallback_apply_exception
                if last_attempt_path is not None:
                    existing.last_attempt_path = last_attempt_path
                return
            blocked = db.BlockedIP(
                ip=ip,
                direction=direction,
                action=action,
                rule_name=rule_name,
                reason=reason,
                status=status,
                backend=backend,
                verified_at=verified_at,
                failure_reason=failure_reason,
                apply_exit_code=apply_exit_code,
                apply_stdout=apply_stdout,
                apply_stderr=apply_stderr,
                apply_exception=apply_exception,
                apply_command=apply_command,
                direct_apply_command=direct_apply_command,
                direct_apply_exit_code=direct_apply_exit_code,
                direct_apply_stdout=direct_apply_stdout,
                direct_apply_stderr=direct_apply_stderr,
                direct_apply_exception=direct_apply_exception,
                fallback_apply_command=fallback_apply_command,
                fallback_apply_exit_code=fallback_apply_exit_code,
                fallback_apply_stdout=fallback_apply_stdout,
                fallback_apply_stderr=fallback_apply_stderr,
                fallback_apply_exception=fallback_apply_exception,
                last_attempt_path=last_attempt_path,
            )
            s.add(blocked)
    except Exception as exc:
        log.warning("Failed to persist blocked IP %s: %s", ip, exc)

def _update_db_status(ip: str, status: Optional[str] = None,
                      verified_at=None,
                      failure_reason: Optional[str] = None,
                      apply_exit_code: Optional[int] = None,
                      apply_stdout: Optional[str] = None,
                      apply_stderr: Optional[str] = None,
                      apply_exception: Optional[str] = None,
                      apply_command: Optional[str] = None,
                      direct_apply_command: Optional[str] = None,
                      direct_apply_exit_code: Optional[int] = None,
                      direct_apply_stdout: Optional[str] = None,
                      direct_apply_stderr: Optional[str] = None,
                      direct_apply_exception: Optional[str] = None,
                      fallback_apply_command: Optional[str] = None,
                      fallback_apply_exit_code: Optional[int] = None,
                      fallback_apply_stdout: Optional[str] = None,
                      fallback_apply_stderr: Optional[str] = None,
                      fallback_apply_exception: Optional[str] = None,
                      last_attempt_path: Optional[str] = None) -> None:
    """Update verification + apply-diagnostic fields on the most recent live row for ``ip``.

    Accepts the dual-path diag (direct_* / fallback_* / last_attempt_path)
    so /api/firewall/rediagnose and startup repair can persist the full
    forensic surface without losing the direct-path stderr to the
    fallback override.
    """
    try:
        from sqlalchemy import select
        with db.session_scope() as s:
            row = s.scalar(
                select(db.BlockedIP)
                .where(db.BlockedIP.ip == ip, db.BlockedIP.removed_at.is_(None))
                .order_by(db.BlockedIP.id.desc())
            )
            if row is None:
                return
            if status is not None:
                row.status = status
            if verified_at is not None:
                row.verified_at = verified_at
            if failure_reason is not None:
                row.failure_reason = failure_reason
            if apply_exit_code is not None:
                row.apply_exit_code = apply_exit_code
            if apply_stdout is not None:
                row.apply_stdout = apply_stdout
            if apply_stderr is not None:
                row.apply_stderr = apply_stderr
            if apply_exception is not None:
                row.apply_exception = apply_exception
            if apply_command is not None:
                row.apply_command = apply_command
            if direct_apply_command is not None:
                row.direct_apply_command = direct_apply_command
            if direct_apply_exit_code is not None:
                row.direct_apply_exit_code = direct_apply_exit_code
            if direct_apply_stdout is not None:
                row.direct_apply_stdout = direct_apply_stdout
            if direct_apply_stderr is not None:
                row.direct_apply_stderr = direct_apply_stderr
            if direct_apply_exception is not None:
                row.direct_apply_exception = direct_apply_exception
            if fallback_apply_command is not None:
                row.fallback_apply_command = fallback_apply_command
            if fallback_apply_exit_code is not None:
                row.fallback_apply_exit_code = fallback_apply_exit_code
            if fallback_apply_stdout is not None:
                row.fallback_apply_stdout = fallback_apply_stdout
            if fallback_apply_stderr is not None:
                row.fallback_apply_stderr = fallback_apply_stderr
            if fallback_apply_exception is not None:
                row.fallback_apply_exception = fallback_apply_exception
            if last_attempt_path is not None:
                row.last_attempt_path = last_attempt_path
    except Exception as exc:
        log.warning("Failed to update blocked IP %s status: %s", ip, exc)

def _remove_from_db(ip: str) -> None:
    """Remove blocked IP from database."""
    try:
        with db.session_scope() as s:
            from sqlalchemy import delete
            s.execute(delete(db.BlockedIP).where(db.BlockedIP.ip == ip))
    except Exception as exc:
        log.warning("Failed to remove blocked IP %s from DB: %s", ip, exc)


def _audit_block_decision(ip: str, action: str, source: str,
                          reason: str = "", extra: Optional[Dict] = None) -> None:
    """Spec #6: log every firewall add/remove with IP, timestamp,
    decision source and result."""
    from .audit import _audit_log
    extra = extra or {}
    extra_str = " " + " ".join(f"{k}={v}" for k, v in extra.items()) if extra else ""
    _audit_log.info(
        "decision=%s ip=%s source=%s reason=%r%s",
        action, ip, source, reason, extra_str,
    )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_manager: Optional[FirewallManager] = None


def get_firewall_manager() -> FirewallManager:
    global _manager
    if _manager is None:
        _manager = FirewallManager()
    return _manager


# ===========================================================================
# FirewallBackend abstraction layer
# ===========================================================================
# The previous monolithic FirewallManager coupled OS commands to policy.
# Splitting "what to do" from "how to do it on this OS" lets us add new
# backends (nftables) and unit-test the rule-application path with mocks.

class FirewallBackend(ABC):
    """Strategy interface for OS-level firewall rule application.

    ``verify_block`` is the second half of the contract: after apply_block
    succeeds, the manager calls verify_block to *prove* the rule is
    actually present in the OS before it will report APPLIED.
    """

    name: str = "abstract"

    @abstractmethod
    def is_available(self) -> bool:
        """True if this backend can actually run on the current host."""

    @abstractmethod
    def apply_block(self, ip: str, rule_name: str, direction: str) -> tuple:
        """Apply a drop rule. Returns ``(ok: bool, diag: dict)``.

        ``diag`` is the forensic surface for the dashboard: keys are
        ``apply_command`` (exact shell invocation), ``apply_exit_code``
        (subprocess rc), ``apply_stdout``, ``apply_stderr``, and
        ``apply_exception`` (traceback if the OS call raised). Always
        populated — empty string when not applicable — so a FAILED row
        can answer "what command ran and what did it say?".
        """

    @abstractmethod
    def remove_block(self, ip: str, rule_name: str) -> 'BlockResult':
        """Remove the rule. See :class:`BlockResult` for the tri-state."""

    @abstractmethod
    def verify_block(self, ip: str, rule_name: str) -> tuple:
        """Confirm the rule is present in the OS firewall.

        Returns ``(verified: bool, detail: str)``. ``detail`` is a
        human-readable explanation surfaced to the audit log and the
        dashboard failure_reason field — include the OS command output
        on failure so the operator can debug without re-running by hand.
        """


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

class WindowsDefenderBackend(FirewallBackend):
    name = "windows_defender"

    def is_available(self) -> bool:
        return platform.system().lower() == "windows"

    def apply_block(self, ip: str, rule_name: str, direction: str) -> tuple:
        try:
            return _block_windows(ip, rule_name, direction)
        except Exception as exc:
            import traceback as _tb
            log.error("WindowsDefenderBackend.apply_block raised: %s", exc)
            return (False, {
                "apply_command": "",
                "apply_exit_code": None,
                "apply_stdout": "",
                "apply_stderr": "",
                "apply_exception": _tb.format_exc(),
            })

    def remove_block(self, ip: str, rule_name: str) -> 'BlockResult':
        return _unblock_windows(rule_name)

    def verify_block(self, ip: str, rule_name: str) -> tuple:
        """Query Windows Defender for our rule + remote IP."""
        return _verify_windows(rule_name, ip)


# ---------------------------------------------------------------------------
# Linux: iptables (legacy fallback)
# ---------------------------------------------------------------------------

class LinuxIptablesBackend(FirewallBackend):
    name = "linux_iptables"

    def is_available(self) -> bool:
        return platform.system().lower() == "linux" and shutil.which("iptables") is not None

    def apply_block(self, ip: str, rule_name: str, direction: str) -> tuple:
        try:
            return _block_linux(ip, rule_name, direction)
        except Exception as exc:
            import traceback as _tb
            log.error("LinuxIptablesBackend.apply_block raised: %s", exc)
            return (False, {
                "apply_command": "",
                "apply_exit_code": None,
                "apply_stdout": "",
                "apply_stderr": "",
                "apply_exception": _tb.format_exc(),
            })

    def remove_block(self, ip: str, rule_name: str) -> 'BlockResult':
        return _unblock_linux(ip)

    def verify_block(self, ip: str, rule_name: str) -> tuple:
        """``iptables -C`` is exit-status membership test — perfect for this."""
        try:
            r = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                return (True, f"verified: iptables rule for {ip} present in INPUT chain")
            # Also check OUTPUT if direction was 'both' — best-effort.
            r2 = subprocess.run(
                ["iptables", "-C", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
            if r2.returncode == 0:
                return (True, f"verified: iptables rule for {ip} present in OUTPUT chain")
            return (False, f"iptables -C returned {r.returncode}: "
                           f"stdout={r.stdout.strip()!r} stderr={r.stderr.strip()!r}")
        except FileNotFoundError:
            return (False, "iptables not found")
        except subprocess.TimeoutExpired:
            return (False, "iptables verify_block timed out")
        except Exception as exc:
            return (False, f"iptables verify_block raised: {exc}")


# ---------------------------------------------------------------------------
# Linux: nftables (preferred on modern Linux)
# ---------------------------------------------------------------------------

# ponytail: nftables needs a base table+chain we own. We use the
# ``inet`` family so a single rule covers IPv4 and IPv6 without
# separate commands — keeps the spec's "preferred" claim honest.
_NFT_TABLE = "sentinelscan"
_NFT_CHAIN = "input_drop"
_NFT_PRIORITY = -100   # runs before any accept-everything default


def _nft_table_present() -> bool:
    """True if the SentinelScan nftables table exists."""
    try:
        r = subprocess.run(
            ["nft", "list", "table", "inet", _NFT_TABLE],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _nft_ensure_table() -> bool:
    """Create the SentinelScan nftables table + chain if missing."""
    try:
        # nft refuses to recreate existing objects — that's fine,
        # stderr from those failures is harmless.
        subprocess.run(
            ["nft", "add", "table", "inet", _NFT_TABLE],
            capture_output=True, text=True, timeout=5,
        )
        subprocess.run(
            ["nft", "add", "chain", "inet", _NFT_TABLE, _NFT_CHAIN,
             "{", "type", "filter", "hook", "input", "priority", str(_NFT_PRIORITY), ";", "policy", "accept", ";", "}"],
            capture_output=True, text=True, timeout=5,
        )
        return _nft_table_present()
    except Exception as exc:
        log.warning("nft ensure-table failed: %s", exc)
        return False


class LinuxNftablesBackend(FirewallBackend):
    name = "linux_nftables"

    def is_available(self) -> bool:
        if platform.system().lower() != "linux" or shutil.which("nft") is None:
            return False
        return _nft_ensure_table()

    def apply_block(self, ip: str, rule_name: str, direction: str) -> tuple:
        diag: Dict[str, object] = {
            "apply_command": "",
            "apply_exit_code": None,
            "apply_stdout": "",
            "apply_stderr": "",
            "apply_exception": "",
        }
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            diag["apply_exception"] = f"invalid IP: {ip!r}"
            return (False, diag)
        family = "ip" if addr.version == 4 else "ip6"
        set_name = f"blocked_v{addr.version}"
        try:
            cmds = [
                ["nft", "add", "set", "inet", _NFT_TABLE, set_name,
                 "{", "type", family, "_addr", ";", "}"],
                ["nft", "add", "element", "inet", _NFT_TABLE, set_name, "{", ip, "}"],
                ["nft", "add", "rule", "inet", _NFT_TABLE, _NFT_CHAIN,
                 family, "saddr", "@" + set_name, "drop"],
            ]
            last_rc = None
            last_stdout = ""
            last_stderr = ""
            last_cmd = ""
            for cmd in cmds:
                log.debug("firewall.nft CMD=%s", cmd)
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                last_cmd = " ".join(cmd)
                last_rc = r.returncode
                last_stdout = r.stdout or ""
                last_stderr = r.stderr or ""
                log.debug("firewall.nft rc=%s stdout=%r stderr=%r",
                          r.returncode, str(last_stdout)[:500], str(last_stderr)[:500])
                if r.returncode != 0:
                    diag["apply_command"] = last_cmd
                    diag["apply_exit_code"] = last_rc
                    diag["apply_stdout"] = last_stdout
                    diag["apply_stderr"] = last_stderr
                    return (False, diag)
            diag["apply_command"] = last_cmd
            diag["apply_exit_code"] = last_rc
            diag["apply_stdout"] = last_stdout
            diag["apply_stderr"] = last_stderr
            return (True, diag)
        except Exception as exc:
            import traceback as _tb
            diag["apply_exception"] = _tb.format_exc()
            log.error("nft apply_block failed for %s: %s", ip, exc)
            return (False, diag)

    def remove_block(self, ip: str, rule_name: str) -> 'BlockResult':
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return BlockResult.INVALID
        family = "ip" if addr.version == 4 else "ip6"
        set_name = f"blocked_v{addr.version}"
        try:
            probe = subprocess.run(
                ["nft", "get", "element", "inet", _NFT_TABLE, set_name, "{", ip, "}"],
                capture_output=True, text=True, timeout=5,
            )
            if probe.returncode != 0:
                return BlockResult.ALREADY_ABSENT
            subprocess.run(
                ["nft", "delete", "element", "inet", _NFT_TABLE, set_name, "{", ip, "}"],
                capture_output=True, text=True, timeout=5,
            )
            return BlockResult.UNAPPLIED
        except Exception as exc:
            log.error("nft remove_block failed for %s: %s", ip, exc)
            return BlockResult.FAILED

    def verify_block(self, ip: str, rule_name: str) -> tuple:
        """``nft get element`` on the named set is the canonical probe."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return (False, f"invalid IP: {ip!r}")
        family = "ip" if addr.version == 4 else "ip6"
        set_name = f"blocked_v{addr.version}"
        try:
            r = subprocess.run(
                ["nft", "get", "element", "inet", _NFT_TABLE, set_name, "{", ip, "}"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                return (True, f"verified: {ip} present in nft set {set_name}")
            return (False, f"nft get element rc={r.returncode} "
                           f"stderr={r.stderr.strip()!r}")
        except FileNotFoundError:
            return (False, "nft not found")
        except subprocess.TimeoutExpired:
            return (False, "nft verify_block timed out")
        except Exception as exc:
            return (False, f"nft verify_block raised: {exc}")


def _pick_backend() -> FirewallBackend:
    """Probe candidates in spec order: nftables → iptables → Windows."""
    for cls in (LinuxNftablesBackend, LinuxIptablesBackend, WindowsDefenderBackend):
        b = cls()
        if b.is_available():
            log.info("Firewall backend selected: %s", b.name)
            return b
    log.warning("No firewall backend available; records kept in app state only")
    return WindowsDefenderBackend()  # placeholder — every call will fail safely


# ---------------------------------------------------------------------------
# IP validation — protect the operator from self-inflicted footguns.
# ---------------------------------------------------------------------------

_PROTECTED_CACHE: Dict[str, List] = {}


def _load_protected_cidrs() -> List:
    """Lazy-load + memoize the protected CIDR list from settings."""
    if "cidrs" in _PROTECTED_CACHE:
        return _PROTECTED_CACHE["cidrs"]
    from .config import get_settings
    s = get_settings()
    cidrs = []
    for raw in s.ips_protected_cidrs or []:
        try:
            cidrs.append(ipaddress.ip_network(raw, strict=False))
        except ValueError as exc:
            log.warning("Ignoring bad protected CIDR %r: %s", raw, exc)
    _PROTECTED_CACHE["cidrs"] = cidrs
    return cidrs


def _is_protected_ip(ip: str) -> bool:
    """True if the IP is one we must never block by default.

    Refuses loopback, link-local, multicast, broadcast, anything in
    ``SENTINEL_PROTECTED_CIDRS``. ``SENTINEL_PROTECTED_ALLOW_BYPASS=true``
    disables this for test/staging environments.
    """
    from .config import get_settings
    s = get_settings()
    if s.ips_protected_allow_bypass:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # refuse to act on a malformed IP at all
    if addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return True
    if addr.version == 4 and str(addr) == "255.255.255.255":
        return True
    for net in _load_protected_cidrs():
        try:
            if addr.version == net.version and addr in net:
                return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# Backend singleton + test override
# ---------------------------------------------------------------------------

_backend_singleton: Optional[FirewallBackend] = None


def get_backend() -> FirewallBackend:
    global _backend_singleton
    if _backend_singleton is None:
        _backend_singleton = _pick_backend()
    return _backend_singleton


def set_backend(backend: Optional[FirewallBackend]) -> None:
    """Override the auto-detected backend. Tests use this; production
    code should leave it alone."""
    global _backend_singleton
    _backend_singleton = backend
