"""Tests for the reports module.

Verifies that CSV and PDF reports are generated correctly under empty
and populated database states, and that recommendations are dynamically
tailored based on the scan types found in the database.
"""

from __future__ import annotations

import csv
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend import config, database as db, reports


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Isolate DB and reports folder for each test."""
    original_db_url = config.get_settings().db_url
    original_secret_key = config.get_settings().secret_key

    db_file = tmp_path / "test.db"
    config.get_settings().db_url = f"sqlite:///{db_file}"
    config.get_settings().secret_key = "test-secret-key-not-default"
    
    # Mock the read-only reports_dir property on the class
    monkeypatch.setattr(config.Settings, "reports_dir", property(lambda self: tmp_path / "reports"))

    # Force re-initialisation of database layer
    db.init_db()

    yield

    # Close DB connection pool to avoid ResourceWarning / unclosed database warnings
    db.close_db()
    
    # Restore settings
    config.get_settings().db_url = original_db_url
    config.get_settings().secret_key = original_secret_key
    config.reset_settings()


def test_generate_csv_empty():
    path, count = reports.generate_csv()
    assert count == 0
    assert path.exists()
    assert path.name.endswith(".csv")

    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = list(csv.reader(f))
        assert len(reader) == 1  # only header row
        assert reader[0][0] == "id"


def test_generate_pdf_empty():
    path, count = reports.generate_pdf()
    assert count == 0
    assert path.exists()
    assert path.name.endswith(".pdf")
    # PDF should have non-zero size
    assert path.stat().st_size > 0


def test_generate_reports_with_data():
    # Insert dummy attacks
    with db.session_scope() as s:
        a1 = db.Attack(
            started_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=10),
            ended_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=9),
            duration_seconds=60.0,
            source_ip="1.2.3.4",
            source_country="United States",
            source_isp="Google LLC",
            source_asn="AS15169",
            scan_type="SYN Scan (Stealth)",
            scan_confidence=95.0,
            packet_count=50,
            unique_ports=10,
            unique_targets=1,
            target_ports_json="[22, 80, 443]",
            target_hosts_json='["192.168.1.10"]',
            risk_score=5.5,
            risk_level="medium",
            technique_signals_json='["SYN Scan (Stealth) (95%)"]',
        )
        a2 = db.Attack(
            started_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5),
            ended_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=4),
            duration_seconds=60.0,
            source_ip="5.6.7.8",
            source_country="India",
            source_isp="Airtel",
            source_asn="AS24560",
            scan_type="Xmas Scan",
            scan_confidence=90.0,
            packet_count=100,
            unique_ports=50,
            unique_targets=1,
            target_ports_json="[139, 445]",
            target_hosts_json='["192.168.1.11"]',
            risk_score=8.5,
            risk_level="critical",
            technique_signals_json='["Xmas Scan (90%)"]',
        )
        db.insert_attack(s, a1)
        db.insert_attack(s, a2)

    # 1. Test CSV with data
    csv_path, csv_count = reports.generate_csv()
    assert csv_count == 2
    assert csv_path.exists()
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = list(csv.reader(f))
        assert len(reader) == 3  # header + 2 rows
        # Check that we populated fields correctly
        assert reader[1][4] == "5.6.7.8"  # descending order by started_at (a2 is first)
        assert reader[2][4] == "1.2.3.4"

    # 2. Test PDF with data
    pdf_path, pdf_count = reports.generate_pdf()
    assert pdf_count == 2
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0


def test_recommendations_logic():
    from backend.reports import _recommendations

    # Test default recommendations
    empty_summary = {
        "by_scan": {},
        "by_risk": {},
        "by_tool": {},
        "by_country": {},
        "top_sources": [],
    }
    recs = _recommendations(empty_summary)
    assert len(recs) == 1
    assert "Continue passive monitoring" in recs[0]

    # Test dynamic recommendations for Xmas scan
    xmas_summary = {
        "by_scan": {"Xmas Scan": 1},
        "by_risk": {"medium": 1},
        "by_tool": {"Nmap": 1},
    }
    recs = _recommendations(xmas_summary)
    assert any("stealth" in r.lower() or "flag" in r.lower() for r in recs)
    assert any("nmap" in r.lower() for r in recs)

    # Test dynamic recommendations for Mass Scan
    mass_summary = {
        "by_scan": {"Mass Scan": 1},
        "by_risk": {"high": 1},
        "by_tool": {"Masscan": 1},
    }
    recs = _recommendations(mass_summary)
    assert any("rate-limit" in r.lower() for r in recs)
    assert any("fail2ban" in r.lower() or "syn-scan" in r.lower() for r in recs)

    # Test critical attacks threshold recommendations
    critical_summary = {
        "by_scan": {"SYN Scan (Stealth)": 3},
        "by_risk": {"critical": 3},
        "by_tool": {"Nmap": 3},
    }
    recs = _recommendations(critical_summary)
    assert any("quarantine" in r.lower() or "block" in r.lower() for r in recs)
