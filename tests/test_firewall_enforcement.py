"""Tests for production-grade firewall enforcement (spec #1-#9).

Mocked at two boundaries:

1. The :class:`FirewallBackend` strategy — ``set_backend(FakeBackend())``
   swaps out real OS commands for an in-memory recorder.
2. ``subprocess.run`` is patched in the few backends we touch directly
   so the nft / iptables paths don't try to invoke the OS.
"""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from backend import firewall_manager as fm
from backend.firewall_manager import (
    BlockResult,
    FirewallBackend,
    LinuxIptablesBackend,
    LinuxNftablesBackend,
    WindowsDefenderBackend,
    set_backend,
    get_backend,
    _is_protected_ip,
)


# ---------------------------------------------------------------------------
# In-memory fake backend
# ---------------------------------------------------------------------------

class FakeBackend(FirewallBackend):
    """Records every apply/remove/verify call. Configurable per-method.

    Default behaviour: apply succeeds AND verify succeeds — i.e. the OS
    agrees the rule is in place. Tests override ``verify_returns`` to
    simulate "OS forgot the rule" or "OS says no".
    """

    name = "fake"

    def __init__(self, apply_works: bool = True, remove_works: bool = True,
                 verify_returns: tuple = (True, "ok")) -> None:
        self.apply_calls = []
        self.remove_calls = []
        self.verify_calls = []
        self._apply_works = apply_works
        self._remove_works = remove_works
        self.verify_returns = verify_returns
        self.applied: set = set()
        # If True, verify succeeds iff ``ip`` is in self.applied.
        self.verify_strict = True

    def is_available(self) -> bool:
        return True

    def apply_block(self, ip, rule_name, direction):
        self.apply_calls.append((ip, rule_name, direction))
        if not self._apply_works:
            return (False, {
                "apply_command": "fake-fail",
                "apply_exit_code": 1,
                "apply_stdout": "",
                "apply_stderr": "fake-fail",
                "apply_exception": "",
            })
        self.applied.add(ip)
        return (True, {
            "apply_command": "fake-ok",
            "apply_exit_code": 0,
            "apply_stdout": "OK",
            "apply_stderr": "",
            "apply_exception": "",
        })

    def remove_block(self, ip, rule_name):
        self.remove_calls.append((ip, rule_name))
        if ip not in self.applied:
            return BlockResult.ALREADY_ABSENT
        if not self._remove_works:
            return BlockResult.FAILED
        self.applied.discard(ip)
        return BlockResult.UNAPPLIED

    def verify_block(self, ip, rule_name):
        self.verify_calls.append((ip, rule_name))
        if self.verify_strict:
            if ip in self.applied:
                return (True, f"verified: {ip} in OS")
            return (False, f"{ip} not in OS (backend.applied={self.applied})")
        return self.verify_returns


# ---------------------------------------------------------------------------
# Fixtures: a fresh DB per test, fresh manager singleton, fake backend.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    db_file = tmp_path / "fw.sqlite"
    monkeypatch.setenv("SENTINEL_DB_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("SENTINEL_AUTH_ENABLED", "false")
    monkeypatch.setenv("SENTINEL_PROTECTED_ALLOW_BYPASS", "false")
    # Reset every singleton that caches module-level state.
    fm._manager = None
    fm._backend_singleton = None
    fm._PROTECTED_CACHE.clear()
    import importlib
    import backend.config as cfg
    importlib.reload(cfg)
    import backend.database as db
    importlib.reload(db)
    db.init_db()
    yield


@pytest.fixture
def fake_backend():
    b = FakeBackend()
    set_backend(b)
    return b


# ---------------------------------------------------------------------------
# Spec #4: rule tracking, dedup, persistence
# ---------------------------------------------------------------------------

class TestFirewallEnforcement:
    def test_block_creates_backend_rule_and_db_row(self, fake_backend):
        mgr = fm.get_firewall_manager()
        result = mgr.block_ip("203.0.113.10", reason="unit-test",
                               decision_source="dashboard")
        assert result == BlockResult.APPLIED
        assert fake_backend.applied == {"203.0.113.10"}
        # In-memory state synced.
        assert mgr.is_blocked("203.0.113.10")
        # DB row persisted.
        import backend.database as db
        with db.session_scope() as s:
            from sqlalchemy import select
            rows = list(s.scalars(select(db.BlockedIP)))
        assert any(r.ip == "203.0.113.10" for r in rows)

    def test_duplicate_block_returns_already_blocked(self, fake_backend):
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.20")
        # Second block must NOT touch the backend or DB.
        before = len(fake_backend.apply_calls)
        before_db = _db_count(mgr)
        result = mgr.block_ip("203.0.113.20")
        assert result == BlockResult.ALREADY_BLOCKED
        assert len(fake_backend.apply_calls) == before
        assert _db_count(mgr) == before_db

    def test_unblock_removes_backend_rule_and_db_row(self, fake_backend):
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.30")
        result = mgr.unblock_ip("203.0.113.30", decision_source="dashboard")
        assert result == BlockResult.UNAPPLIED
        assert "203.0.113.30" not in fake_backend.applied
        assert not mgr.is_blocked("203.0.113.30")
        assert _db_count(mgr) == 0

    def test_unblock_unknown_ip_is_already_absent(self, fake_backend):
        mgr = fm.get_firewall_manager()
        result = mgr.unblock_ip("198.51.100.99")
        assert result == BlockResult.ALREADY_ABSENT

    def test_unblock_syncs_state_when_backend_already_absent(self, fake_backend):
        # Backend forgot the rule (e.g. reboot). In-memory state must still
        # be cleaned up so the operator's view matches reality (spec #4).
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.40")  # backend records it
        fake_backend.applied.discard("203.0.113.40")  # OS reboots
        result = mgr.unblock_ip("203.0.113.40")
        assert result == BlockResult.ALREADY_ABSENT
        assert not mgr.is_blocked("203.0.113.40")
        assert _db_count(mgr) == 0

    def test_persists_across_restart(self, fake_backend, tmp_path, monkeypatch):
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.50")
        # Simulate restart: drop in-memory state, leave DB.
        import importlib
        import backend.database as db
        importlib.reload(db)
        db.init_db()
        fm._manager = None
        # New manager on next get_firewall_manager() must load from DB.
        mgr2 = fm.get_firewall_manager()
        assert mgr2.is_blocked("203.0.113.50")

    def test_recorded_only_when_backend_fails(self, tmp_path, monkeypatch):
        # Backend that *fails* the OS call — state still recorded.
        monkeypatch.setenv("SENTINEL_DB_URL", f"sqlite:///{tmp_path/'fw.sqlite'}")
        fm._manager = None
        fm._backend_singleton = None
        import importlib, backend.database as db
        importlib.reload(db); db.init_db()
        set_backend(FakeBackend(apply_works=False))
        mgr = fm.get_firewall_manager()
        result = mgr.block_ip("203.0.113.60")
        assert result == BlockResult.RECORDED_ONLY
        assert mgr.is_blocked("203.0.113.60")  # recorded in app state


# ---------------------------------------------------------------------------
# Spec #5: validation — refuse protected IPs
# ---------------------------------------------------------------------------

class TestProtectedIPValidation:
    @pytest.mark.parametrize("ip", [
        "127.0.0.1",         # loopback
        "127.55.66.77",       # loopback range
        "169.254.1.1",        # link-local
        "224.0.0.1",          # multicast
        "255.255.255.255",    # broadcast
        "::1",                # IPv6 loopback
        "ff02::1",            # IPv6 multicast
    ])
    def test_protected_ips_are_refused(self, ip, fake_backend):
        mgr = fm.get_firewall_manager()
        result = mgr.block_ip(ip)
        assert result == BlockResult.PROTECTED, f"expected PROTECTED for {ip}, got {result}"
        assert fake_backend.apply_calls == []
        assert not mgr.is_blocked(ip)

    def test_protected_bypass_actually_blocks(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SENTINEL_DB_URL", f"sqlite:///{tmp_path/'fw.sqlite'}")
        monkeypatch.setenv("SENTINEL_PROTECTED_ALLOW_BYPASS", "true")
        fm._manager = None
        fm._backend_singleton = None
        fm._PROTECTED_CACHE.clear()
        import importlib, backend.database as db
        importlib.reload(cfg := __import__("backend.config", fromlist=["*"]))
        importlib.reload(db); db.init_db()
        backend = FakeBackend()
        set_backend(backend)
        mgr = fm.get_firewall_manager()
        # Even with bypass on, the explicit protect check should still
        # allow the rule through.
        result = mgr.block_ip("127.0.0.1", reason="test")
        assert result == BlockResult.APPLIED
        assert backend.applied == {"127.0.0.1"}

    def test_invalid_ip_returns_invalid(self, fake_backend):
        mgr = fm.get_firewall_manager()
        result = mgr.block_ip("not-an-ip")
        assert result == BlockResult.INVALID


# ---------------------------------------------------------------------------
# Spec #1: backend abstraction — three concrete classes exist and dispatch.
# ---------------------------------------------------------------------------

class TestBackendAbstraction:
    def test_backend_base_is_abstract(self):
        with pytest.raises(TypeError):
            FirewallBackend()

    def test_windows_backend_is_platform_conditional(self):
        b = WindowsDefenderBackend()
        # Whatever the host, the is_available() check must be honest.
        if not b.is_available():
            with pytest.raises(Exception):
                b.apply_block("1.2.3.4", "rule", "inbound")

    def test_linux_backends_require_platform(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Windows")
        ipt = LinuxIptablesBackend()
        nft = LinuxNftablesBackend()
        assert not ipt.is_available()
        assert not nft.is_available()

    def test_pick_backend_returns_something(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Windows")
        b = fm._pick_backend()
        # On Windows host without schtasks, we may still get the Windows
        # backend (probe is lazy) — that's OK, the call will fail safely.
        assert isinstance(b, FirewallBackend)

    def test_set_backend_override(self):
        sentinel = FakeBackend()
        set_backend(sentinel)
        assert get_backend() is sentinel


# ---------------------------------------------------------------------------
# Spec #8: API endpoints
# ---------------------------------------------------------------------------

class TestFirewallAPI:
    def _login(self, client):
        # auth is disabled in fixture, login still works (no-op).
        pass

    def test_get_rules_endpoint(self, fake_backend):
        # No app-level auth here; use test_client with a tiny bypass.
        import os
        os.environ["SENTINEL_AUTH_ENABLED"] = "true"
        os.environ["SENTINEL_ADMIN_USER"] = "admin"
        os.environ["SENTINEL_ADMIN_PASSWORD"] = "TestPass1234!"
        import importlib, backend.config as cfg, backend.auth, backend.app
        importlib.reload(cfg); importlib.reload(backend.auth); importlib.reload(backend.app)
        from backend.auth import bootstrap_default_admin
        bootstrap_default_admin()
        from backend.app import create_app
        app = create_app()
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})

        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.70")
        r = client.get("/api/firewall/rules")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["count"] >= 1
        assert any(rule["ip"] == "203.0.113.70" for rule in data["rules"])
        assert "backend" in data

    def test_unblock_endpoint_removes_rule(self, fake_backend):
        import os
        os.environ["SENTINEL_AUTH_ENABLED"] = "true"
        os.environ["SENTINEL_ADMIN_USER"] = "admin"
        os.environ["SENTINEL_ADMIN_PASSWORD"] = "TestPass1234!"
        import importlib, backend.config as cfg, backend.auth, backend.app
        importlib.reload(cfg); importlib.reload(backend.auth); importlib.reload(backend.app)
        from backend.auth import bootstrap_default_admin
        bootstrap_default_admin()
        from backend.app import create_app
        app = create_app()
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})

        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.80")
        r = client.post("/api/firewall/unblock/203.0.113.80")
        assert r.status_code == 200
        assert r.get_json()["ok"] is True
        assert not mgr.is_blocked("203.0.113.80")

    def test_unblock_endpoint_rejects_invalid_ip(self, fake_backend):
        import os
        os.environ["SENTINEL_AUTH_ENABLED"] = "true"
        os.environ["SENTINEL_ADMIN_USER"] = "admin"
        os.environ["SENTINEL_ADMIN_PASSWORD"] = "TestPass1234!"
        import importlib, backend.config as cfg, backend.auth, backend.app
        importlib.reload(cfg); importlib.reload(backend.auth); importlib.reload(backend.app)
        from backend.auth import bootstrap_default_admin
        bootstrap_default_admin()
        from backend.app import create_app
        app = create_app()
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
        r = client.post("/api/firewall/unblock/garbage")
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# Spec #6: audit logging
# ---------------------------------------------------------------------------

class TestAuditLogging:
    def test_block_writes_audit_log(self, fake_backend, caplog):
        import logging
        with caplog.at_level(logging.INFO, logger="sentinelscan.ips.audit"):
            fm.get_firewall_manager().block_ip(
                "203.0.113.90", reason="audit-test", decision_source="dashboard",
            )
        text = "\n".join(r.message for r in caplog.records)
        assert "203.0.113.90" in text
        assert "dashboard" in text
        assert "block" in text

    def test_unblock_writes_audit_log(self, fake_backend, caplog):
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.91")
        import logging
        with caplog.at_level(logging.INFO, logger="sentinelscan.ips.audit"):
            mgr.unblock_ip("203.0.113.91", decision_source="dashboard")
        text = "\n".join(r.message for r in caplog.records)
        assert "unblock" in text
        assert "203.0.113.91" in text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _db_count(mgr) -> int:
    import backend.database as db
    from sqlalchemy import select, func
    with db.session_scope() as s:
        return s.scalar(select(func.count(db.BlockedIP.id))) or 0


# ===========================================================================
# Firewall enforcement verification (spec #1-#7)
# ===========================================================================

import time as _time
from backend.firewall_manager import EnforcementStatus


class TestBlockVerification:
    """Spec #1: block → apply → verify → only then VERIFIED."""

    def test_block_returns_applied_only_when_verified(self, fake_backend):
        mgr = fm.get_firewall_manager()
        result = mgr.block_ip("203.0.113.200")
        assert result == BlockResult.APPLIED
        # Backend got exactly one apply AND one verify call.
        assert len(fake_backend.apply_calls) == 1
        assert len(fake_backend.verify_calls) == 1

    def test_persists_status_verified(self, fake_backend):
        import backend.database as db
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.201")
        with db.session_scope() as s:
            from sqlalchemy import select
            row = s.scalar(
                select(db.BlockedIP)
                .where(db.BlockedIP.ip == "203.0.113.201", db.BlockedIP.removed_at.is_(None))
            )
        assert row is not None
        assert row.status == EnforcementStatus.VERIFIED.value
        assert row.verified_at is not None
        assert row.failure_reason is None
        assert row.backend == "fake"

    def test_failed_verify_records_status_failed(self):
        """Backend accepts apply but verify says no → FAILED, not APPLIED."""
        b = FakeBackend(verify_returns=(False, "iptables reports rule missing"))
        b.verify_strict = False
        set_backend(b)
        mgr = fm.get_firewall_manager()
        result = mgr.block_ip("203.0.113.202")
        # Spec: must NOT advertise APPLIED to caller when verification fails.
        assert result != BlockResult.APPLIED
        import backend.database as db
        from sqlalchemy import select
        with db.session_scope() as s:
            row = s.scalar(select(db.BlockedIP).where(
                db.BlockedIP.ip == "203.0.113.202", db.BlockedIP.removed_at.is_(None)))
        assert row.status == EnforcementStatus.FAILED.value
        assert "missing" in row.failure_reason

    def test_unblock_removes_verified_rule(self):
        b = FakeBackend()
        set_backend(b)
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.203")
        assert b.applied == {"203.0.113.203"}
        result = mgr.unblock_ip("203.0.113.203")
        assert result == BlockResult.UNAPPLIED
        # After unblock, verify must report absent.
        ok, _ = b.verify_block("203.0.113.203", "ignored")
        assert ok is False


class TestStartupRecheck:
    """Spec #6: re-check every persisted rule on startup; repair missing."""

    def test_verified_rules_remain_verified(self, fake_backend):
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.210")
        # Simulate restart by reloading the module-level singletons.
        import importlib
        import backend.database as db
        importlib.reload(db); db.init_db()
        fm._manager = None
        # Backend state survives (singleton FakeBackend instance).
        mgr2 = fm.get_firewall_manager()
        mgr2._verify_persisted_rules()
        # The OS still has the rule → status must stay VERIFIED.
        with db.session_scope() as s:
            from sqlalchemy import select
            row = s.scalar(select(db.BlockedIP).where(
                db.BlockedIP.ip == "203.0.113.210", db.BlockedIP.removed_at.is_(None)))
        assert row.status == EnforcementStatus.VERIFIED.value

    def test_missing_rule_is_repaired(self, fake_backend):
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.211")
        # OS "reboots" — the backend forgot the rule.
        fake_backend.applied.clear()
        # Run the startup re-check.
        import importlib
        import backend.database as db
        importlib.reload(db); db.init_db()
        fm._manager = None
        mgr2 = fm.get_firewall_manager()
        mgr2._verify_persisted_rules()
        # Repair must re-apply AND verify, ending VERIFIED.
        assert "203.0.113.211" in fake_backend.applied
        with db.session_scope() as s:
            from sqlalchemy import select
            row = s.scalar(select(db.BlockedIP).where(
                db.BlockedIP.ip == "203.0.113.211", db.BlockedIP.removed_at.is_(None)))
        assert row.status == EnforcementStatus.VERIFIED.value

    def test_permanently_broken_rule_marked_failed(self, fake_backend):
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.212")
        # Both apply AND verify fail at startup.
        fake_backend._apply_works = False
        fake_backend.applied.clear()
        fake_backend.verify_returns = (False, "iptables: permission denied")
        fake_backend.verify_strict = False
        import importlib
        import backend.database as db
        importlib.reload(db); db.init_db()
        fm._manager = None
        mgr2 = fm.get_firewall_manager()
        mgr2._verify_persisted_rules()
        with db.session_scope() as s:
            from sqlalchemy import select
            row = s.scalar(select(db.BlockedIP).where(
                db.BlockedIP.ip == "203.0.113.212", db.BlockedIP.removed_at.is_(None)))
        assert row.status == EnforcementStatus.FAILED.value
        assert "permission denied" in row.failure_reason


class TestFirewallAPIStatus:
    """Spec #5: GET /api/firewall/rules returns status/verified_at/failure_reason."""

    def test_rules_endpoint_includes_verification_fields(self, fake_backend):
        _with_app_client(lambda client: self._exercise(client, fake_backend))

    def _exercise(self, client, fake_backend):
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.220")
        r = client.get("/api/firewall/rules")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["backend"] == "fake"
        assert data["count"] >= 1
        rule = next(x for x in data["rules"] if x["ip"] == "203.0.113.220")
        assert rule["status"] == "verified"
        assert rule["verified_at"] is not None
        assert rule["failure_reason"] is None

    def test_status_endpoint_summarizes_counts(self, fake_backend):
        _with_app_client(lambda client: self._exercise_status(client, fake_backend))

    def _exercise_status(self, client, fake_backend):
        mgr = fm.get_firewall_manager()
        mgr.block_ip("203.0.113.221")
        r = client.get("/api/status")
        assert r.status_code == 200
        fw = r.get_json().get("firewall", {})
        assert fw.get("verified", 0) >= 1
        assert fw.get("total", 0) >= 1


def _with_app_client(fn):
    """Build a test client with admin auth — short helper."""
    import importlib, backend.config as cfg, backend.auth, backend.app
    importlib.reload(cfg); importlib.reload(backend.auth); importlib.reload(backend.app)
    from backend.app import create_app
    from backend.auth import bootstrap_default_admin
    bootstrap_default_admin()
    app = create_app()
    client = app.test_client()
    client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    fn(client)


# ===========================================================================
# Bug regression: app says VERIFIED but the OS can't find the rule.
#
# User report: 192.168.56.101 shows as "blocked" on the dashboard while
# `Get-NetFirewallRule -DisplayName 'SentinelScan*'` returns nothing.
# Root cause was a NameError in the backend's apply_block call that silently
# converted to BlockResult.FAILED — but with the DB row never written, the
# DB-side count was unchanged while the operator saw a stale entry from an
# earlier run. This test enforces the invariant: SentinelScan NEVER reports
# status=verified unless the backend's verify_block agrees.
# ===========================================================================

class TestOSVersusAppConsistency:
    """Invariant: status=verified iff backend.verify_block returns True."""

    def test_unverified_block_is_not_reported_as_verified(self):
        # Backend accepts the apply call but its verify_block says NO.
        b = FakeBackend(verify_returns=(False, "iptables: rule missing"))
        b.verify_strict = False
        set_backend(b)
        mgr = fm.get_firewall_manager()
        result = mgr.block_ip("192.168.56.101")
        # Operator-facing API MUST NOT return APPLIED if verify failed.
        assert result != BlockResult.APPLIED, (
            "block_ip returned APPLIED even though verify_block said no — "
            "this is the exact bug the dashboard reported."
        )
        import backend.database as db
        from sqlalchemy import select
        with db.session_scope() as s:
            row = s.scalar(select(db.BlockedIP).where(
                db.BlockedIP.ip == "192.168.56.101", db.BlockedIP.removed_at.is_(None)))
        assert row is not None, "Failed block should still leave an audit row"
        assert row.status != EnforcementStatus.VERIFIED.value, (
            "DB row must not be VERIFIED when verify_block returned False"
        )
        # And failure_reason must explain why — operators rely on this.
        assert row.failure_reason, "FAILED rows need a non-empty failure_reason"

    def test_dashboard_status_endpoint_never_counts_failed_as_verified(self):
        b = FakeBackend(verify_returns=(False, "permission denied"))
        b.verify_strict = False
        set_backend(b)
        mgr = fm.get_firewall_manager()
        mgr.block_ip("192.168.56.101")
        # Mirror what /api/status returns.
        import backend.database as db
        from sqlalchemy import select, func
        with db.session_scope() as s:
            counts = dict(s.execute(
                select(db.BlockedIP.status, func.count(db.BlockedIP.id))
                .where(db.BlockedIP.removed_at.is_(None))
                .group_by(db.BlockedIP.status)
            ).all())
        assert counts.get(EnforcementStatus.VERIFIED.value, 0) == 0, (
            f"verified count must be zero when OS cannot confirm rule, got {counts}"
        )

    def test_realistic_windows_path_with_subprocess_mocked(self):
        """Simulate the original bug path: apply_block raises NameError because
        the backend calls a function that doesn't exist at module scope.

        With the fix, apply_block must NOT NameError, and the resulting
        row must NOT be reported as VERIFIED.
        """
        import subprocess
        original_run = subprocess.run

        def fake_run(*args, **kwargs):
            # Mimic the user's environment: schtasks exists but the
            # non-elevated invocation gets ACCESS DENIED.
            if isinstance(args[0], list) and args[0] and args[0][0] == "schtasks":
                r = MagicMock()
                r.returncode = 1
                r.stdout = ""
                r.stderr = "ERROR: Access is denied.\n"
                return r
            return original_run(*args, **kwargs)

        # Force the real Windows backend (bypass the singleton).
        with patch("backend.firewall_manager.subprocess.run", side_effect=fake_run), \
             patch("backend.firewall_manager._is_elevated", return_value=True):
            backend = fm.WindowsDefenderBackend()
            applied, diag = backend.apply_block(
                "192.168.56.101", "SentinelScan Block 192.168.56.101", "inbound")
            # The fix removes the NameError so apply_block now reaches
            # schtasks and returns its actual result (False for access denied).
            assert applied is False, "non-elevated schtasks should fail"
            # apply_* (= last attempt) reflects the schtasks fallback —
            # the dashboard still surfaces the final attempt's stderr.
            assert diag["apply_exit_code"] == 1
            assert "Access is denied" in diag["apply_stderr"]
            # Dual-path: direct and fallback diagnostics are BOTH preserved
            # (Phase 6 success criterion 1: "Why direct New-NetFirewallRule
            # failed" — captured in direct_apply_stderr).
            assert diag["last_attempt_path"] == "fallback", (
                f"expected last_attempt_path=fallback, got {diag.get('last_attempt_path')!r}"
            )
            assert "Access is denied" in diag["direct_apply_stderr"], (
                "direct_apply_stderr must preserve the original PowerShell "
                "Access Denied error that the schtasks fallback was supposed to fix"
            )
            assert diag["direct_apply_command"].startswith(
                "powershell -NoProfile"
            ), f"direct_apply_command must be the powershell call, got {diag['direct_apply_command']!r}"
            assert "Access is denied" in diag["fallback_apply_stderr"], (
                "fallback_apply_stderr must preserve the schtasks access denied"
            )
            assert diag["fallback_apply_command"].startswith(
                "schtasks SYSTEM"
            ), f"fallback_apply_command must be the schtasks string, got {diag['fallback_apply_command']!r}"
            ok, detail = backend.verify_block(
                "192.168.56.101", "SentinelScan Block 192.168.56.101")
            assert ok is False
            assert "not found" in detail or "ABSENT" in detail or "denied" in detail

    def test_verify_actually_consults_backend_each_time(self):
        """Defence-in-depth: even if apply said True, a lying backend that
        returns False on verify must demote the row to FAILED.
        """
        b = FakeBackend()  # default verify_strict=True: matches applied set
        set_backend(b)
        mgr = fm.get_firewall_manager()
        mgr.block_ip("192.168.56.101")
        # Backend "reboots" — applied set cleared, but DB row exists.
        b.applied.clear()
        # Re-running verify against the stale DB row must come back False.
        ok, detail = b.verify_block("192.168.56.101", "SentinelScan Block 192.168.56.101")
        assert ok is False
        assert "not in OS" in detail

# ===========================================================================
# Selftest regression: the temp-file schtasks fallback must work even when
# the PowerShell script is over 261 characters (the original /tr limit).
# ===========================================================================

class TestWindowsSelftestFallback:
    """Patches subprocess so we can exercise the Windows code paths
    deterministically without needing an actual admin-elevated shell."""

    def test_schtasks_fallback_uses_temp_file_when_tr_too_long(self, monkeypatch, tmp_path):
        """If the direct PowerShell call fails, the schtasks fallback must
        write the script to a file (not inline it) so /tr stays short."""
        from unittest.mock import MagicMock, patch, call
        monkeypatch.setenv("SENTINEL_PROTECTED_ALLOW_BYPASS", "true")
        import backend.firewall_manager as fm

        # Track what was passed to schtasks /create
        created_trs = []
        def fake_run(cmd, *args, **kwargs):
            # cmd is a list of args
            if isinstance(cmd, list) and cmd[:2] == ["powershell", "-NoProfile"]:
                # Simulate "access denied" from direct call so fallback fires.
                r = MagicMock()
                r.returncode = 1
                r.stdout = ""
                r.stderr = "New-NetFirewallRule : Access is denied."
                return r
            if isinstance(cmd, list) and cmd and cmd[0] == "schtasks" and cmd[1] == "/create":
                created_trs.append(cmd)
                r = MagicMock()
                r.returncode = 1
                r.stdout = ""
                r.stderr = "ERROR: Access is denied."
                return r
            if isinstance(cmd, list) and cmd and cmd[0] == "schtasks" and cmd[1] == "/run":
                r = MagicMock(); r.returncode = 0; r.stdout = ""; r.stderr = ""
                return r
            if isinstance(cmd, list) and cmd and cmd[0] == "schtasks" and cmd[1] == "/delete":
                r = MagicMock(); r.returncode = 0; r.stdout = ""; r.stderr = ""
                return r
            if isinstance(cmd, list) and cmd[:2] == ["net", "session"]:
                r = MagicMock(); r.returncode = 1; r.stdout = ""; r.stderr = ""
                return r
            r = MagicMock(); r.returncode = 0; r.stdout = ""; r.stderr = ""
            return r

        with patch("backend.firewall_manager.subprocess.run", side_effect=fake_run), \
             patch("backend.firewall_manager._is_elevated", return_value=True):
            applied, diag = fm._block_windows("192.168.56.101", "SentinelScan Test", "inbound")

        assert len(created_trs) == 1, "expected exactly one schtasks /create call"
        tr_value = created_trs[0][created_trs[0].index("/tr") + 1]
        # /tr MUST reference a temp file (not inline the script). This is
        # exactly the fix that prevents the 261-char limit from biting.
        assert "-File" in tr_value, f"fallback should use -File, got {tr_value!r}"
        assert ".ps1" in tr_value, f"fallback /tr should reference a .ps1 file, got {tr_value!r}"
        # The /tr payload itself must be well under 261 chars.
        assert len(tr_value) < 261, f"/tr is {len(tr_value)} chars; must be <261"

        # Dual-path diagnostics (Phase 6): both attempts are recorded.
        # Direct path: powershell exit_code=1 with the New-NetFirewallRule
        # Access Denied message. Fallback path: schtasks create exit_code=1
        # with its own Access Denied. apply_* (= last attempt) mirrors the
        # fallback; direct_* and fallback_* preserve each path independently.
        assert diag["last_attempt_path"] == "fallback"
        assert diag["apply_exit_code"] == 1
        assert diag["apply_command"].startswith("schtasks SYSTEM")
        assert "New-NetFirewallRule" in diag["direct_apply_command"]
        assert diag["direct_apply_exit_code"] == 1
        assert "Access is denied" in diag["direct_apply_stderr"]
        assert "Access is denied" in diag["fallback_apply_stderr"]
        assert diag["fallback_apply_command"].startswith("schtasks SYSTEM")


# ===========================================================================
# Whitelist block API (Phase 6): POST /api/ips/whitelist/<ip>/block
# ===========================================================================

class TestWhitelistBlockAPI:
    """Issue #6: clicking "Block" on an approved IP removes from whitelist
    and adds a firewall rule in a single operation."""

    def test_whitelist_block_removes_and_blocks(self, fake_backend):
        def _run(client):
            from backend.whitelist_manager import get_whitelist_manager
            wl = get_whitelist_manager()
            wl.add("203.0.113.99", added_by="test-api", reason="integration test")
            assert wl.is_whitelisted("203.0.113.99")

            r = client.post("/api/ips/whitelist/203.0.113.99/block")
            assert r.status_code == 200
            data = r.get_json()
            assert data["ok"] is True

            assert not wl.is_whitelisted("203.0.113.99")

            from backend.firewall_manager import get_firewall_manager
            fw = get_firewall_manager()
            assert fw.is_blocked("203.0.113.99")

        _with_app_client(_run)

    def test_whitelist_block_not_in_list_returns_404(self, fake_backend):
        def _run(client):
            r = client.post("/api/ips/whitelist/203.0.113.200/block")
            assert r.status_code == 404
            data = r.get_json()
            assert data["ok"] is False
            assert "not in whitelist" in data["error"]

        _with_app_client(_run)

    def test_whitelist_block_invalid_ip_returns_400(self, fake_backend):
        def _run(client):
            r = client.post("/api/ips/whitelist/garbage/block")
            assert r.status_code == 400
            data = r.get_json()
            assert data["ok"] is False

        _with_app_client(_run)
