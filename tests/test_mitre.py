"""Tests for MITRE ATT&CK scan-type mapping."""

from backend.mitre import format_line, lookup


def test_lookup_known_scan_type():
    tactic, tid, name = lookup("Ping Sweep")
    assert tactic == "Discovery"
    assert tid == "T1018"
    assert name == "Remote System Discovery"


def test_lookup_unknown_scan_type_falls_back():
    tactic, tid, name = lookup("Not A Real Scan")
    assert tid == "T1046"
    assert name == "Network Service Discovery"


def test_format_line():
    assert format_line("SYN Scan (Stealth)") == "Discovery — T1046 Network Service Discovery"
