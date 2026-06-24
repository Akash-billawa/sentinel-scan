"""Tests for IPS (Intrusion Prevention System) functionality."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from backend.ips_policy import evaluate, IPSAction, ALWAYS_APPROVE, AUTO_BLOCK_TYPES
from backend.approval_manager import ApprovalManager, ActionStatus, PendingAction
from backend.firewall_manager import FirewallManager, BlockResult, set_backend, LinuxIptablesBackend


# ---------------------------------------------------------------------------
# IPS Policy Tests
# ---------------------------------------------------------------------------

class TestIPSPolicy:
    def test_low_risk_returns_alert(self):
        result = evaluate(2.0, "Ping Sweep")
        assert result.action == "alert"
        assert "alert only" in result.reason.lower()

    def test_below_threshold_returns_alert(self):
        # Spec: only risk >= 6 should trigger the approval flow.
        result = evaluate(5.9, "SYN Scan")
        assert result.action == "alert"

    def test_medium_risk_returns_approve(self):
        # At the new >= 6 threshold, 6.5 should require approval.
        result = evaluate(6.5, "SYN Scan")
        assert result.action == "approve"
        assert "approval" in result.reason.lower()

    def test_high_risk_returns_approve(self):
        result = evaluate(8.0, "Vertical Scan")
        assert result.action == "approve"

    def test_critical_risk_returns_auto_block(self):
        result = evaluate(9.5, "Mass Scan")
        assert result.action == "auto_block"
        assert "auto-block" in result.reason.lower()

    def test_mass_scan_always_auto_blocks(self):
        result = evaluate(5.0, "Mass Scan")
        assert result.action == "auto_block"

    def test_ack_scan_always_requires_approval(self):
        result = evaluate(2.0, "ACK Scan")
        assert result.action == "approve"

    def test_fragmented_scan_always_requires_approval(self):
        result = evaluate(1.0, "Fragmented Scan")
        assert result.action == "approve"

    def test_null_scan_always_requires_approval(self):
        result = evaluate(3.0, "NULL Scan")
        assert result.action == "approve"

    def test_fin_scan_always_requires_approval(self):
        result = evaluate(4.0, "FIN Scan")
        assert result.action == "approve"

    def test_xmas_scan_always_requires_approval(self):
        result = evaluate(6.0, "Xmas Scan")
        assert result.action == "approve"


# ---------------------------------------------------------------------------
# Approval Manager Tests
# ---------------------------------------------------------------------------

class TestApprovalManager:
    def setup_method(self):
        self.mgr = ApprovalManager(timeout_seconds=60)

    def test_create_action(self):
        action = self.mgr.create_action(
            attack_id=1,
            source_ip="192.168.1.100",
            threat_type="SYN Scan",
            risk_score=6.5,
            risk_level="high",
            confidence=0.85,
            reason="Test"
        )
        assert action.status == ActionStatus.PENDING
        assert action.source_ip == "192.168.1.100"
        assert action.threat_type == "SYN Scan"
        assert action.id.startswith("evt_")

    def test_approve_action(self):
        action = self.mgr.create_action(
            attack_id=2,
            source_ip="10.0.0.50",
            threat_type="Vertical Scan",
            risk_score=7.0,
            risk_level="high",
            confidence=0.90,
        )
        approved = self.mgr.approve(action.id, by="admin")
        assert approved.status == ActionStatus.APPROVED
        assert approved.decided_by == "admin"
        assert approved.decided_at is not None

    def test_deny_action(self):
        action = self.mgr.create_action(
            attack_id=3,
            source_ip="172.16.0.1",
            threat_type="Xmas Scan",
            risk_score=8.5,
            risk_level="critical",
            confidence=0.95,
        )
        denied = self.mgr.deny(action.id, by="operator")
        assert denied.status == ActionStatus.DENIED
        assert denied.decided_by == "operator"

    def test_approve_nonexistent_returns_none(self):
        result = self.mgr.approve("nonexistent_id")
        assert result is None

    def test_deny_nonexistent_returns_none(self):
        result = self.mgr.deny("nonexistent_id")
        assert result is None

    def test_double_approve_returns_none(self):
        action = self.mgr.create_action(
            attack_id=4,
            source_ip="192.168.2.1",
            threat_type="SYN Scan",
            risk_score=5.0,
            risk_level="medium",
            confidence=0.80,
        )
        self.mgr.approve(action.id)
        result = self.mgr.approve(action.id)
        assert result is None

    def test_list_pending(self):
        self.mgr.create_action(5, "1.1.1.1", "SYN Scan", 5.0, "medium", 0.8)
        self.mgr.create_action(6, "2.2.2.2", "Vertical Scan", 7.0, "high", 0.9)
        pending = self.mgr.list_pending()
        assert len(pending) == 2

    def test_list_all(self):
        action = self.mgr.create_action(7, "3.3.3.3", "SYN Scan", 5.0, "medium", 0.8)
        self.mgr.approve(action.id)
        all_actions = self.mgr.list_all()
        assert len(all_actions) == 1
        assert all_actions[0].status == ActionStatus.APPROVED

    def test_to_dict(self):
        action = self.mgr.create_action(
            attack_id=8,
            source_ip="4.4.4.4",
            threat_type="ACK Scan",
            risk_score=6.0,
            risk_level="high",
            confidence=0.85,
        )
        d = action.to_dict()
        assert d["id"] == action.id
        assert d["source_ip"] == "4.4.4.4"
        assert d["threat_type"] == "ACK Scan"
        assert d["status"] == "pending"

    def test_callback_fires_on_approve(self):
        callback = Mock()
        self.mgr.add_callback(callback)
        action = self.mgr.create_action(9, "5.5.5.5", "SYN Scan", 5.0, "medium", 0.8)
        self.mgr.approve(action.id)
        callback.assert_called_once()
        assert callback.call_args[0][0].status == ActionStatus.APPROVED


# ---------------------------------------------------------------------------
# Firewall Manager Tests (mocked)
# ---------------------------------------------------------------------------

class TestFirewallManager:
    def setup_method(self):
        set_backend(LinuxIptablesBackend())
        self._elevated_patcher = patch('backend.firewall_manager._is_elevated', return_value=True)
        self._elevated_patcher.start()
        self.mgr = FirewallManager()
        # Stop the expiry checker to avoid thread issues in tests
        self.mgr.stop_expiry_checker()

    def teardown_method(self):
        self._elevated_patcher.stop()
        set_backend(None)

    @patch('backend.firewall_manager.db.session_scope')
    def test_block_ip_persists(self, mock_session):
        mock_session.return_value.__enter__ = Mock(return_value=Mock())
        mock_session.return_value.__exit__ = Mock(return_value=False)

        with patch.object(self.mgr, '_platform', 'linux'):
            with patch('subprocess.run', return_value=Mock(returncode=0, stderr='')):
                called = []
                def run_side_effect(cmd, **kwargs):
                    if '-A' in cmd:
                        called.append(cmd)
                    if '-C' in cmd:
                        if called:
                            return Mock(returncode=0, stderr='')
                        return Mock(returncode=1, stderr='')  # Rule not found
                    return Mock(returncode=0, stderr='')
                with patch('subprocess.run', side_effect=run_side_effect):
                    result = self.mgr.block_ip('192.168.1.100', reason='Test block')

        assert result == BlockResult.APPLIED
        assert self.mgr.is_blocked('192.168.1.100')

    def test_unblock_ip(self):
        # Manually add to blocked dict
        from backend.firewall_manager import FirewallRule
        self.mgr._blocked_ips['10.0.0.1'] = FirewallRule(
            ip='10.0.0.1',
            direction='inbound',
            action='block',
            rule_name='test',
            created_at='2024-01-01T00:00:00Z',
            reason='test',
        )

        with patch.object(self.mgr, '_platform', 'linux'):
            with patch('subprocess.run', return_value=Mock(returncode=0, stderr='')):
                result = self.mgr.unblock_ip('10.0.0.1')

        assert result == BlockResult.UNAPPLIED
        assert not self.mgr.is_blocked('10.0.0.1')

    def test_list_blocked(self):
        from backend.firewall_manager import FirewallRule
        self.mgr._blocked_ips.clear()
        self.mgr._blocked_ips['1.1.1.1'] = FirewallRule(
            ip='1.1.1.1', direction='inbound', action='block',
            rule_name='test1', created_at='', reason='r1'
        )
        self.mgr._blocked_ips['2.2.2.2'] = FirewallRule(
            ip='2.2.2.2', direction='inbound', action='block',
            rule_name='test2', created_at='', reason='r2'
        )
        blocked = self.mgr.list_blocked()
        assert len(blocked) == 2

    @patch('backend.firewall_manager.db.session_scope')
    def test_block_ip_linux_outbound(self, mock_session):
        mock_session.return_value.__enter__ = Mock(return_value=Mock())
        mock_session.return_value.__exit__ = Mock(return_value=False)

        with patch.object(self.mgr, '_platform', 'linux'):
            with patch('subprocess.run') as mock_run:
                called = []
                def run_side_effect(cmd, **kwargs):
                    if '-A' in cmd:
                        called.append(cmd)
                    if '-C' in cmd:
                        if called:
                            return Mock(returncode=0, stderr='')
                        return Mock(returncode=1, stderr='')
                    return Mock(returncode=0, stderr='')
                mock_run.side_effect = run_side_effect
                
                result = self.mgr.block_ip('192.168.1.100', reason='Test block outbound', direction='outbound')
                
                assert result == BlockResult.APPLIED
                assert self.mgr.is_blocked('192.168.1.100')
                
                called_cmds = [call[0][0] for call in mock_run.call_args_list]
                assert any('-C' in cmd and 'OUTPUT' in cmd and '-d' in cmd for cmd in called_cmds)
                assert any('-A' in cmd and 'OUTPUT' in cmd and '-d' in cmd for cmd in called_cmds)

    @patch('backend.firewall_manager.db.session_scope')
    def test_unblock_ip_linux_outbound(self, mock_session):
        mock_session.return_value.__enter__ = Mock(return_value=Mock())
        mock_session.return_value.__exit__ = Mock(return_value=False)

        from backend.firewall_manager import FirewallRule
        self.mgr._blocked_ips['192.168.1.100'] = FirewallRule(
            ip='192.168.1.100',
            direction='outbound',
            action='block',
            rule_name='SentinelScan Block 192.168.1.100',
            created_at='2024-01-01T00:00:00Z',
            reason='test',
        )

        with patch.object(self.mgr, '_platform', 'linux'):
            with patch('subprocess.run') as mock_run:
                # Mock unblock success (INPUT deletion fails, OUTPUT deletion succeeds)
                def run_side_effect(cmd, **kwargs):
                    if 'INPUT' in cmd:
                        return Mock(returncode=1, stderr='')
                    return Mock(returncode=0, stderr='')
                mock_run.side_effect = run_side_effect
                
                result = self.mgr.unblock_ip('192.168.1.100')
                
                assert result == BlockResult.UNAPPLIED
                assert not self.mgr.is_blocked('192.168.1.100')
                
                called_cmds = [call[0][0] for call in mock_run.call_args_list]
                assert any('INPUT' in cmd and '-s' in cmd for cmd in called_cmds)
                assert any('OUTPUT' in cmd and '-d' in cmd for cmd in called_cmds)

    @patch('backend.firewall_manager.db.session_scope')
    def test_reapply_rules_on_boot_async(self, mock_session):
        mock_db_rule = Mock()
        mock_db_rule.ip = "192.168.1.200"
        mock_db_rule.direction = "inbound"
        mock_db_rule.action = "block"
        mock_db_rule.rule_name = "SentinelScan Block 192.168.1.200"
        mock_db_rule.created_at = datetime.now()
        mock_db_rule.reason = "boot test"
        
        mock_session.return_value.__enter__ = Mock(return_value=Mock(scalars=Mock(return_value=[mock_db_rule])))
        mock_session.return_value.__exit__ = Mock(return_value=False)

        with patch('backend.firewall_manager.FirewallManager._reapply_firewall_rules') as mock_reapply:
            with patch('backend.firewall_manager.FirewallManager.start_expiry_checker'):
                mgr = FirewallManager()
                mgr.stop_expiry_checker()
                
                import time
                start_time = time.time()
                while not mock_reapply.called and time.time() - start_time < 2.0:
                    time.sleep(0.05)
                
                assert mock_reapply.called

    @patch('backend.firewall_manager.db.session_scope')
    def test_reapply_rules_on_boot_disabled(self, mock_session):
        mock_db_rule = Mock()
        mock_db_rule.ip = "192.168.1.200"
        mock_db_rule.direction = "inbound"
        mock_db_rule.action = "block"
        mock_db_rule.rule_name = "SentinelScan Block 192.168.1.200"
        mock_db_rule.created_at = datetime.now()
        mock_db_rule.reason = "boot test"
        
        mock_session.return_value.__enter__ = Mock(return_value=Mock(scalars=Mock(return_value=[mock_db_rule])))
        mock_session.return_value.__exit__ = Mock(return_value=False)

        from backend.config import get_settings
        settings = get_settings()
        original_val = settings.ips_reapply_on_boot
        settings.ips_reapply_on_boot = False
        try:
            with patch('backend.firewall_manager.FirewallManager._reapply_firewall_rules') as mock_reapply:
                with patch('backend.firewall_manager.FirewallManager.start_expiry_checker'):
                    mgr = FirewallManager()
                    mgr.stop_expiry_checker()
                    import time
                    time.sleep(0.5)
                    assert not mock_reapply.called
        finally:
            settings.ips_reapply_on_boot = original_val


# ---------------------------------------------------------------------------
# Integration: IPS Policy + Approval Manager
# ---------------------------------------------------------------------------

class TestIPSIntegration:
    def test_policy_drives_approval_flow(self):
        """Simulate the flow: detect -> evaluate -> create action -> approve."""
        mgr = ApprovalManager(timeout_seconds=30)

        # Simulate a detected attack
        risk_score = 6.5
        scan_type = "Vertical Scan"

        # Evaluate policy
        ips_action = evaluate(risk_score, scan_type)
        assert ips_action.action == "approve"

        # Create approval request
        action = mgr.create_action(
            attack_id=100,
            source_ip="192.168.10.50",
            threat_type=scan_type,
            risk_score=risk_score,
            risk_level="high",
            confidence=0.88,
            reason=ips_action.reason,
        )
        assert action.status == ActionStatus.PENDING

        # Operator approves
        approved = mgr.approve(action.id, by="admin")
        assert approved.status == ActionStatus.APPROVED
        assert approved.decided_by == "admin"

    def test_critical_auto_blocks(self):
        """Critical threats auto-block without approval."""
        mgr = ApprovalManager(timeout_seconds=30)

        # Simulate a critical attack
        risk_score = 9.0
        scan_type = "Mass Scan"

        # Evaluate policy
        ips_action = evaluate(risk_score, scan_type)
        assert ips_action.action == "auto_block"

        # No approval needed - would go straight to firewall
        # (we don't test firewall here, just policy)


# ---------------------------------------------------------------------------
# IPS Settings Tests
# ---------------------------------------------------------------------------

class TestIPSSettings:
    def test_default_settings(self):
        """Test default IPS settings."""
        from backend.config import Settings
        import os
        # Clear env overrides to test raw defaults
        env_keys = [
            "SENTINEL_IPS_ENABLED", "SENTINEL_IPS_MODE",
            "SENTINEL_IPS_APPROVAL_TIMEOUT", "SENTINEL_IPS_AUTO_BLOCK_THRESHOLD",
            "SENTINEL_IPS_APPROVAL_THRESHOLD", "SENTINEL_IPS_BLOCK_EXPIRY",
        ]
        saved = {k: os.environ.pop(k, None) for k in env_keys}
        try:
            settings = Settings()
            assert settings.ips_enabled is False
            assert settings.ips_mode == "approve"
            assert settings.ips_approval_timeout == 60
            assert settings.ips_auto_block_threshold == 8.0
            assert settings.ips_approval_threshold == 4.0
            assert settings.ips_block_expiry == 0
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_approval_manager_timeout(self):
        """Test approval manager respects timeout setting."""
        mgr = ApprovalManager(timeout_seconds=10)
        action = mgr.create_action(
            attack_id=200,
            source_ip="10.0.0.1",
            threat_type="SYN Scan",
            risk_score=5.0,
            risk_level="medium",
            confidence=0.8,
        )
        # Check that timeout is set correctly
        from datetime import datetime, timedelta
        now = datetime.now()
        diff = action.expires_at - action.created_at
        assert diff.total_seconds() == 10


# ---------------------------------------------------------------------------
# Block Expiry Tests
# ---------------------------------------------------------------------------

class TestBlockExpiry:
    def test_firewall_rule_created_at(self):
        """Test that FirewallRule tracks creation time."""
        from backend.firewall_manager import FirewallRule
        from datetime import datetime, timezone

        rule = FirewallRule(
            ip="192.168.1.100",
            direction="inbound",
            action="block",
            rule_name="test",
            created_at=datetime.now(timezone.utc).isoformat(),
            reason="test",
        )
        assert rule.created_at is not None
        assert rule.ip == "192.168.1.100"

    def test_expiry_disabled_by_default(self):
        """Test that block expiry is disabled by default."""
        from backend.config import Settings
        settings = Settings()
        assert settings.ips_block_expiry == 0  # 0 = never expire


# ---------------------------------------------------------------------------
# Human-in-the-Loop IPS module: whitelist, rate limiter, audit, duplicate
# decision rejection, timeout defaulting to block.
# ---------------------------------------------------------------------------

from backend.whitelist_manager import WhitelistManager
from backend.pending_rate_limiter import PendingRateLimiter


class TestWhitelistManager:
    def setup_method(self):
        self.wl = WhitelistManager(default_ttl_seconds=300, max_entries=3)

    def test_add_and_lookup(self):
        self.wl.add("10.0.0.1", reason="unit")
        assert self.wl.is_whitelisted("10.0.0.1")
        assert not self.wl.is_whitelisted("10.0.0.2")

    def test_duplicate_add_refreshes_entry(self):
        a = self.wl.add("10.0.0.1", ttl_seconds=60)
        b = self.wl.add("10.0.0.1", ttl_seconds=60)
        # Same ip, two adds — should be a single entry with refreshed TTL.
        assert self.wl.size() == 1
        assert b.added_at >= a.added_at

    def test_max_entries_evicts_oldest(self):
        for i in range(3):
            self.wl.add(f"10.0.0.{i + 1}", ttl_seconds=60 + i)
        # Fourth add should evict 10.0.0.1 (smallest TTL).
        self.wl.add("10.0.0.99", ttl_seconds=60)
        assert not self.wl.is_whitelisted("10.0.0.1")
        assert self.wl.is_whitelisted("10.0.0.99")

    def test_ttl_hard_cap(self):
        # Bizarre TTL should be clamped, not honoured as-is.
        e = self.wl.add("10.0.0.1", ttl_seconds=10 ** 12)
        from datetime import datetime, timezone
        ttl = (e.expires_at - e.added_at).total_seconds()
        assert ttl <= 24 * 3600  # 24h hard cap

    def test_expiry_prunes_on_lookup(self):
        import time as _t
        self.wl.add("10.0.0.1", ttl_seconds=1)
        _t.sleep(1.2)
        # First lookup prunes the expired entry.
        assert not self.wl.is_whitelisted("10.0.0.1")
        assert self.wl.size() == 0

    def test_background_sweep_removes_expired(self):
        import time as _t
        self.wl.add("10.0.0.1", ttl_seconds=1)
        _t.sleep(1.2)
        # Without any lookup, the sweep alone must clean up.
        removed = self.wl._sweep_once()
        assert removed == 1
        assert self.wl.size() == 0


class TestPendingRateLimiter:
    def test_bypass_for_non_pending_sources(self):
        rl = PendingRateLimiter(capacity=2, refill_per_sec=0.001)
        # 100 packets from a non-pending source must all pass.
        assert all(rl.note("1.1.1.1") for _ in range(100))

    def test_throttles_pending_source(self):
        rl = PendingRateLimiter(capacity=3, refill_per_sec=0.001)
        rl.mark_pending("2.2.2.2")
        allowed = sum(1 for _ in range(20) if rl.note("2.2.2.2"))
        assert allowed == 3  # capacity, nothing more

    def test_unmark_stops_throttling(self):
        rl = PendingRateLimiter(capacity=1, refill_per_sec=0.001)
        rl.mark_pending("3.3.3.3")
        assert rl.note("3.3.3.3")   # consumes the only token
        assert not rl.note("3.3.3.3")
        rl.unmark_pending("3.3.3.3")
        # Non-pending → bypass regardless of bucket state.
        assert rl.note("3.3.3.3")


class TestApprovalManagerSpecFields:
    """PendingAction must carry destination_ip + ports (spec #1)."""

    def test_destination_and_ports_round_trip(self):
        mgr = ApprovalManager(timeout_seconds=60)
        action = mgr.create_action(
            attack_id=42,
            source_ip="192.168.1.10",
            destination_ip="10.0.0.5",
            threat_type="SYN Scan",
            risk_score=7.0,
            risk_level="high",
            confidence=0.85,
            ports=[22, 80, 443],
            reason="spec #1",
        )
        d = action.to_dict()
        assert d["destination_ip"] == "10.0.0.5"
        assert d["ports"] == [22, 80, 443]


class TestDuplicateDecisionRejection:
    """Spec #8: prevent duplicate approvals."""

    def test_approve_is_idempotent(self):
        mgr = ApprovalManager(timeout_seconds=60)
        a = mgr.create_action(
            attack_id=1, source_ip="1.1.1.1", threat_type="SYN Scan",
            risk_score=7.0, risk_level="high", confidence=0.8,
        )
        assert mgr.approve(a.id).status == ActionStatus.APPROVED
        # Second call must return None — atomic guard prevents re-decision.
        assert mgr.approve(a.id) is None
        assert mgr.deny(a.id) is None

    def test_deny_is_idempotent(self):
        mgr = ApprovalManager(timeout_seconds=60)
        a = mgr.create_action(
            attack_id=1, source_ip="1.1.1.1", threat_type="SYN Scan",
            risk_score=7.0, risk_level="high", confidence=0.8,
        )
        assert mgr.deny(a.id).status == ActionStatus.DENIED
        assert mgr.deny(a.id) is None
        assert mgr.approve(a.id) is None


class TestTimeoutDefaultsToBlock:
    """Spec #4: timeout → default action = block."""

    def test_expired_action_is_marked_expired_with_timeout_reason(self):
        from datetime import datetime, timedelta, timezone
        mgr = ApprovalManager(timeout_seconds=1)
        a = mgr.create_action(
            attack_id=1, source_ip="1.1.1.1", threat_type="SYN Scan",
            risk_score=7.0, risk_level="high", confidence=0.8,
        )
        # Force expiry.
        with mgr._lock:
            a.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
        mgr.cleanup_expired()
        # Spec #4 contract: timeout marks decided_by=timeout and stamps
        # reason with "Approval Timeout". The terminal status (EXPIRED vs
        # EXECUTED) depends on whether the firewall applied, which is
        # environment-dependent — both terminal states are valid.
        assert a.status in (ActionStatus.EXPIRED, ActionStatus.EXECUTED)
        assert a.decided_by == "timeout"
        assert "Approval Timeout" in a.reason
