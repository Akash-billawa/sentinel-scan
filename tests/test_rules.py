"""Tests for the Suricata-inspired detection rule engine.

Covers every rule in backend/rules.py with both positive (should match)
and negative (should not match) cases.  Also tests the pipeline function
``evaluate_rules`` and the SID-filtering mechanism.
"""

from __future__ import annotations

import pytest
from backend.rules import (
    RULES,
    DetectionRule,
    RuleMatch,
    evaluate_rules,
    _build_reasons,
)
from backend.detector import _count_in_window, _mode_value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _syn_scan_signals(**overrides) -> dict:
    """Base signals for a typical Nmap SYN scan."""
    base = {
        "has_tcp": True,
        "has_udp": False,
        "has_icmp": False,
        "syn_ratio": 0.92,
        "tcp_completion_ratio": 0.05,
        "unique_ports": 50,
        "unique_targets": 1,
        "unique_port_list": list(range(1, 51)),
        "rate": 180.0,
        "packet_count": 200,
        "flags_seen": {"SYN": True, "ACK": False, "FIN": False, "PSH": False, "URG": False, "RST": False},
        "window_value": 1024,
        "mss_value": 1460,
        "source_count_70s": 15,
        "source_count_135s": 15,
        "fragmented_count": 0,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# _mode_value / _count_in_window
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_mode_value_majority(self):
        from collections import deque
        vals = [1024, 1024, 1024, 2048]
        assert _mode_value(vals) == 1024

    def test_mode_value_empty(self):
        assert _mode_value([]) is None

    def test_mode_value_single(self):
        assert _mode_value([42]) == 42

    def test_count_in_window(self):
        from collections import deque
        from backend.detector import PacketRecord
        from datetime import datetime, timedelta
        now = datetime(2026, 1, 1, 12, 0, 0)
        records = deque()
        # Chronological order: oldest first, newest last
        for i in range(20):
            records.append(PacketRecord(
                timestamp=now - timedelta(seconds=19 - i),
                source_ip="1.1.1.1", destination_ip="2.2.2.2",
                source_port=12345, destination_port=80,
                protocol="TCP", flags={"SYN": True},
            ))
        # 20 records spanning 0..19 seconds; 5s window from newest catches 6
        assert _count_in_window(records, 5) == 6
        # 100s window catches all 20
        assert _count_in_window(records, 100) == 20
        # 0s window catches only the newest
        assert _count_in_window(records, 0) == 1


# ---------------------------------------------------------------------------
# Rule existence
# ---------------------------------------------------------------------------

class TestRuleInventory:
    def test_all_rules_have_unique_sids(self):
        sids = [r.sid for r in RULES]
        assert len(sids) == len(set(sids)), f"Duplicate SIDs: {sids}"

    def test_all_rules_have_positive_base_score(self):
        for r in RULES:
            assert 0 < r.base_score <= 1.0, f"Rule {r.sid} bad base_score"

    def test_all_rules_have_required_or_scoring(self):
        for r in RULES:
            assert callable(r.score), f"Rule {r.sid} score not callable"


# ---------------------------------------------------------------------------
# SYN scan rule
# ---------------------------------------------------------------------------

class TestSYNScanRule:
    def _find(self):
        return next(r for r in RULES if r.sid == 3400001)

    def test_matches_classic_nmap_syn(self):
        rule = self._find()
        s = _syn_scan_signals()
        assert rule.score(s) > 0.5
        assert rule.required is None or rule.required(s)

    def test_matches_rustscan_variant(self):
        rule = self._find()
        s = _syn_scan_signals(window_value=8192, mss_value=1400)
        assert rule.score(s) > 0.3

    def test_no_match_when_low_syn_ratio(self):
        rule = self._find()
        s = _syn_scan_signals(syn_ratio=0.3)
        assert rule.score(s) == 0.0

    def test_no_match_when_high_completion(self):
        rule = self._find()
        s = _syn_scan_signals(tcp_completion_ratio=0.5)
        assert rule.score(s) == 0.0


# ---------------------------------------------------------------------------
# Horizontal scan rule
# ---------------------------------------------------------------------------

class TestHorizontalScanRule:
    def _find(self):
        return next(r for r in RULES if r.sid == 3400100)

    def test_matches_many_targets(self):
        rule = self._find()
        s = {"unique_targets": 30, "unique_ports": 1}
        assert rule.required(s)
        assert rule.score(s) > 0.5

    def test_no_match_few_targets(self):
        rule = self._find()
        s = {"unique_targets": 2, "unique_ports": 1}
        assert not rule.required(s)


# ---------------------------------------------------------------------------
# Vertical scan rule
# ---------------------------------------------------------------------------

class TestVerticalScanRule:
    def _find(self):
        return next(r for r in RULES if r.sid == 3400101)

    def test_matches_many_ports(self):
        rule = self._find()
        s = {"unique_ports": 100, "unique_targets": 1, "unique_port_list": list(range(100))}
        assert rule.required(s)
        assert rule.score(s) > 0.5

    def test_no_match_few_ports(self):
        rule = self._find()
        s = {"unique_ports": 5, "unique_targets": 1}
        assert not rule.required(s)


# ---------------------------------------------------------------------------
# ACK scan rule
# ---------------------------------------------------------------------------

class TestACKScanRule:
    def _find(self):
        return next(r for r in RULES if r.sid == 3400004)

    def test_matches_ack_only(self):
        rule = self._find()
        s = {
            "has_tcp": True,
            "flags_seen": {"ACK": True, "SYN": False, "FIN": False, "PSH": False, "URG": False},
            "unique_ports": 15,
            "window_value": 1024,
        }
        assert rule.required(s)
        assert rule.score(s) > 0.4

    def test_no_match_when_syn_also_set(self):
        rule = self._find()
        s = {
            "has_tcp": True,
            "flags_seen": {"ACK": True, "SYN": True},
            "unique_ports": 15,
        }
        assert rule.score(s) == 0.0


# ---------------------------------------------------------------------------
# XMAS / NULL / FIN rules
# ---------------------------------------------------------------------------

class TestSpecialFlagRules:
    def test_xmas(self):
        rule = next(r for r in RULES if r.sid == 3400005)
        s = {"has_tcp": True, "flags_seen": {"FIN": True, "PSH": True, "URG": True}, "packet_count": 5}
        assert rule.score(s) > 0.5

    def test_null(self):
        rule = next(r for r in RULES if r.sid == 3400009)
        s = {"has_tcp": True, "flags_seen": {"SYN": False, "ACK": False, "FIN": False, "PSH": False, "URG": False, "RST": False}, "packet_count": 5}
        assert rule.score(s) > 0.5

    def test_fin(self):
        rule = next(r for r in RULES if r.sid == 3400010)
        s = {"has_tcp": True, "flags_seen": {"FIN": True, "SYN": False, "ACK": False}, "packet_count": 5}
        assert rule.score(s) > 0.5


# ---------------------------------------------------------------------------
# UDP / Ping Sweep / Masscan rules
# ---------------------------------------------------------------------------

class TestOtherRules:
    def test_udp_scan(self):
        rule = next(r for r in RULES if r.sid == 3400007)
        s = {"has_udp": True, "has_tcp": False, "unique_ports": 20}
        assert rule.score(s) > 0.5

    def test_ping_sweep(self):
        rule = next(r for r in RULES if r.sid == 3400013)
        s = {"has_icmp": True, "has_tcp": False, "unique_targets": 25}
        assert rule.score(s) > 0.5

    def test_icmp_flood_high_rate(self):
        rule = next(r for r in RULES if r.sid == 3400014)
        s = {"has_icmp": True, "has_tcp": False, "rate": 1500, "unique_targets": 1}
        assert rule.score(s) > 0.5

    def test_icmp_flood_no_match_low_rate(self):
        rule = next(r for r in RULES if r.sid == 3400014)
        s = {"has_icmp": True, "has_tcp": False, "rate": 10, "unique_targets": 1}
        assert rule.score(s) == 0.0

    def test_icmp_flood_no_match_many_targets(self):
        rule = next(r for r in RULES if r.sid == 3400014)
        s = {"has_icmp": True, "has_tcp": False, "rate": 1500, "unique_targets": 10}
        assert rule.score(s) == 0.0

    def test_masscan(self):
        rule = next(r for r in RULES if r.sid == 3400011)
        s = {"has_tcp": True, "rate": 6000, "syn_ratio": 0.9, "unique_ports": 200}
        assert rule.score(s) > 0.5

    def test_fragmented_scan_matches_with_fragments(self):
        rule = next(r for r in RULES if r.sid == 3400006)
        s = {"fragmented_count": 30, "packet_count": 40}
        assert rule.score(s) > 0.5

    def test_fragmented_scan_no_match_few_fragments(self):
        rule = next(r for r in RULES if r.sid == 3400006)
        s = {"fragmented_count": 2, "packet_count": 100}
        assert rule.score(s) == 0.0

    def test_fragmented_scan_no_match_zero_fragments(self):
        rule = next(r for r in RULES if r.sid == 3400006)
        s = {"fragmented_count": 0, "packet_count": 100}
        assert rule.score(s) == 0.0


# ---------------------------------------------------------------------------
# evaluate_rules pipeline
# ---------------------------------------------------------------------------

class TestEvaluateRules:
    def test_syn_scan_returns_match(self):
        matches = evaluate_rules(_syn_scan_signals())
        assert len(matches) > 0
        assert any(m.rule.sid == 3400001 for m in matches)

    def test_horizontal_scan_returns_match(self):
        s = {"unique_targets": 50, "unique_ports": 1, "has_tcp": False, "has_udp": False, "has_icmp": False, "packet_count": 100, "rate": 50.0}
        matches = evaluate_rules(s)
        assert any(m.rule.sid == 3400100 for m in matches)

    def test_sid_filter(self):
        all_matches = evaluate_rules(_syn_scan_signals())
        filtered = evaluate_rules(_syn_scan_signals(), enabled_sids=frozenset({3400001}))
        assert len(filtered) <= len(all_matches)
        assert all(m.rule.sid == 3400001 for m in filtered)

    def test_results_sorted_by_score(self):
        matches = evaluate_rules(_syn_scan_signals())
        scores = [m.score for m in matches]
        assert scores == sorted(scores, reverse=True)

    def test_empty_signals_returns_nothing(self):
        matches = evaluate_rules({})
        assert matches == []
