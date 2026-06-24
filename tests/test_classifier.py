"""Tests for the scan classifier (backend/classifier.py).

Verifies that the classifier correctly maps signal bags to scan types
via the rules engine, handles fallback paths, and respects SID filtering.
"""

from __future__ import annotations

import pytest
from backend.classifier import classify, ClassificationResult, _resolve_enabled_sids
from backend.rules import RuleMatch


def _syn_signals(**kw) -> dict:
    base = {
        "has_tcp": True, "has_udp": False, "has_icmp": False,
        "syn_ratio": 0.92, "tcp_completion_ratio": 0.05,
        "unique_ports": 50, "unique_targets": 1,
        "unique_port_list": list(range(50)),
        "rate": 180.0, "packet_count": 200,
        "flags_seen": {"SYN": True, "ACK": False, "FIN": False, "PSH": False, "URG": False, "RST": False},
        "window_value": 1024, "mss_value": 1460,
        "source_count_70s": 10, "source_count_135s": 10,
        "fragmented_count": 0,
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# Happy-path classifications
# ---------------------------------------------------------------------------

class TestClassifySYN:
    def test_syn_scan(self):
        r = classify(_syn_signals())
        assert r.scan_type == "SYN Scan (Stealth)"
        assert r.confidence > 60

    def test_connect_scan(self):
        # Use <10 ports so vertical scan doesn't dominate
        r = classify(_syn_signals(syn_ratio=0.55, tcp_completion_ratio=0.6, unique_ports=8, unique_port_list=list(range(8))))
        assert "Connect" in r.scan_type or "TCP" in r.scan_type
        assert r.confidence > 40


class TestClassifyHorizontal:
    def test_horizontal(self):
        s = {"unique_targets": 40, "unique_ports": 1, "has_tcp": False, "has_udp": False, "has_icmp": False, "packet_count": 200, "rate": 50.0, "fragmented_count": 0, "unique_port_list": [22]}
        r = classify(s)
        assert r.scan_type == "Horizontal Scan"
        assert r.confidence > 60


class TestClassifyVertical:
    def test_vertical(self):
        s = {"unique_ports": 200, "unique_targets": 1, "unique_port_list": list(range(200)), "has_tcp": True, "has_udp": False, "has_icmp": False, "syn_ratio": 0.0, "tcp_completion_ratio": 0.0, "rate": 0.0, "packet_count": 500, "fragmented_count": 0, "flags_seen": {}}
        r = classify(s)
        assert r.scan_type == "Vertical Scan"
        assert r.confidence > 60


class TestClassifyNullXmasFin:
    def test_null_scan(self):
        s = {"has_tcp": True, "has_udp": False, "has_icmp": False, "flags_seen": {"SYN": False, "ACK": False, "FIN": False, "PSH": False, "URG": False, "RST": False}, "unique_ports": 10, "unique_targets": 1, "unique_port_list": list(range(10)), "syn_ratio": 0.0, "tcp_completion_ratio": 0.0, "rate": 0.0, "packet_count": 10, "fragmented_count": 0}
        r = classify(s)
        assert r.scan_type == "NULL Scan"

    def test_xmas_scan(self):
        s = {"has_tcp": True, "has_udp": False, "has_icmp": False, "flags_seen": {"FIN": True, "PSH": True, "URG": True, "SYN": False, "ACK": False}, "unique_ports": 5, "unique_targets": 1, "unique_port_list": list(range(5)), "syn_ratio": 0.0, "tcp_completion_ratio": 0.0, "rate": 0.0, "packet_count": 5, "fragmented_count": 0}
        r = classify(s)
        assert r.scan_type == "Xmas Scan"


class TestClassifyUDP:
    def test_udp_scan(self):
        s = {"has_tcp": False, "has_udp": True, "has_icmp": False, "unique_ports": 20, "unique_targets": 1, "unique_port_list": list(range(20)), "syn_ratio": 0.0, "tcp_completion_ratio": 0.0, "rate": 0.0, "packet_count": 20, "fragmented_count": 0, "flags_seen": {}}
        r = classify(s)
        assert r.scan_type == "UDP Scan"


class TestClassifyPingSweep:
    def test_ping_sweep(self):
        # Use <3 targets so horizontal scan doesn't trigger
        s = {"has_tcp": False, "has_udp": False, "has_icmp": True, "unique_targets": 10, "unique_ports": 0, "unique_port_list": [], "syn_ratio": 0.0, "tcp_completion_ratio": 0.0, "rate": 0.0, "packet_count": 10, "fragmented_count": 0, "flags_seen": {}}
        r = classify(s)
        assert r.scan_type == "Ping Sweep"

    def test_icmp_flood(self):
        s = {"has_tcp": False, "has_udp": False, "has_icmp": True, "unique_targets": 1, "unique_ports": 0, "unique_port_list": [], "syn_ratio": 0.0, "tcp_completion_ratio": 0.0, "rate": 2000, "packet_count": 200, "fragmented_count": 0, "flags_seen": {}}
        r = classify(s)
        assert r.scan_type == "ICMP Flood"


# ---------------------------------------------------------------------------
# Fallback / tunnel paths
# ---------------------------------------------------------------------------

class TestClassifyFallback:
    def test_generic_tcp(self):
        s = {"has_tcp": True, "has_udp": False, "has_icmp": False, "unique_ports": 1, "unique_targets": 1, "unique_port_list": [80], "syn_ratio": 0.5, "tcp_completion_ratio": 0.5, "rate": 5.0, "packet_count": 3, "fragmented_count": 0, "flags_seen": {"SYN": True, "ACK": True}}
        r = classify(s)
        assert r.scan_type in ("Generic TCP Probe", "TCP Connect Scan")

    def test_tunnel_detection(self):
        s = {"has_tcp": True, "has_udp": False, "has_icmp": False, "unique_ports": 2, "unique_targets": 1, "unique_port_list": [443, 8443], "syn_ratio": 0.1, "tcp_completion_ratio": 0.9, "rate": 80.0, "packet_count": 500, "fragmented_count": 0, "flags_seen": {"ACK": True}}
        r = classify(s)
        assert r.scan_type == "Tunnel/Proxy Activity"

    def test_persistent_connection(self):
        s = {"has_tcp": True, "has_udp": False, "has_icmp": False, "unique_ports": 1, "unique_targets": 1, "unique_port_list": [443], "syn_ratio": 0.0, "tcp_completion_ratio": 1.0, "rate": 5.0, "packet_count": 20, "fragmented_count": 0, "flags_seen": {"ACK": True}}
        r = classify(s)
        assert r.scan_type == "Persistent Connection"


# ---------------------------------------------------------------------------
# SID filtering
# ---------------------------------------------------------------------------

class TestSIDFilter:
    def test_allows_only_syn_rule(self):
        s = _syn_signals()
        r_all = classify(s)
        # Override config to only enable SID 3400001
        from backend import config
        old = config.get_settings().scan_rules
        config.get_settings().scan_rules = "3400001"
        try:
            r_filtered = classify(s)
            # Should still match SYN scan since that's the only rule enabled
            assert r_filtered.scan_type == "SYN Scan (Stealth)"
        finally:
            config.get_settings().scan_rules = old
            config.reset_settings()

    def test_disable_all_rules_falls_back(self):
        s = {"has_tcp": True, "has_udp": False, "has_icmp": False, "unique_ports": 1, "unique_targets": 1, "unique_port_list": [80], "syn_ratio": 0.5, "tcp_completion_ratio": 0.5, "rate": 5.0, "packet_count": 3, "fragmented_count": 0, "flags_seen": {"SYN": True, "ACK": True}}
        from backend import config
        old = config.get_settings().scan_rules
        config.get_settings().scan_rules = "none"
        try:
            r = classify(s)
            assert "Generic" in r.scan_type or "TCP" in r.scan_type
        finally:
            config.get_settings().scan_rules = old
            config.reset_settings()


# ---------------------------------------------------------------------------
# Rule matches attached to result
# ---------------------------------------------------------------------------

class TestRuleMatchesInResult:
    def test_populated(self):
        r = classify(_syn_signals())
        assert r.rule_matches is not None
        assert len(r.rule_matches) > 0
        assert all(isinstance(m, RuleMatch) for m in r.rule_matches)
