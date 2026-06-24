"""Tests for Phase A Improvements.

Verifies the correctness and robustness of:
- A3: Re-entrancy safe packet evaluation sequence checks.
- A5: Reverse-proxy Support (ProxyFix).
- A6: Encryption migration throttle (5,000 max row limit).
- A7: API limit enforcement in /api/attacks.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from sqlalchemy import text, select as sa_select

from backend.config import get_settings, Settings, reset_settings
from backend.app import create_app
from backend import database as db
from backend.detector import DetectionEngine, PacketRecord, SourceState
from backend.crypto import (
    migrate_plaintext_to_encrypted,
    migrate_encrypted_to_plaintext,
)


def test_proxy_fix_active(tmp_path, monkeypatch):
    """Test that Werkzeug ProxyFix is active and correctly handles remote address headers."""
    original_db_url = get_settings().db_url
    original_proxy_fix = get_settings().proxy_fix_count
    
    db_file = tmp_path / "test.db"
    get_settings().db_url = f"sqlite:///{db_file}"
    get_settings().proxy_fix_count = 1  # Enable ProxyFix with 1 proxy trust
    
    monkeypatch.setattr(Settings, "reports_dir", property(lambda self: tmp_path / "reports"))
    
    app = create_app(get_settings())
    app.config["TESTING"] = True
    
    @app.route("/test-ip")
    def test_ip():
        from flask import request
        return request.remote_addr
        
    client = app.test_client()
    try:
        # Request with X-Forwarded-For header
        r = client.get("/test-ip", headers={"X-Forwarded-For": "203.0.113.195"})
        assert r.data.decode("utf-8") == "203.0.113.195"
    finally:
        db.close_db()
        get_settings().db_url = original_db_url
        get_settings().proxy_fix_count = original_proxy_fix
        reset_settings()


def test_api_attacks_limit_boundaries(tmp_path, monkeypatch):
    """Test pagination limit capping and offset support on /api/attacks endpoint."""
    original_db_url = get_settings().db_url
    db_file = tmp_path / "test.db"
    get_settings().db_url = f"sqlite:///{db_file}"
    get_settings().auth_enabled = False  # Disable authentication to simplify client requests
    
    monkeypatch.setattr(Settings, "reports_dir", property(lambda self: tmp_path / "reports"))
    
    app = create_app(get_settings())
    app.config["TESTING"] = True
    
    client = app.test_client()
    try:
        # Populate database with 10 attacks
        with db.session_scope() as sess:
            for i in range(10):
                a = db.Attack(
                    source_ip=f"10.0.0.{i}",
                    source_mac="aa:bb:cc:dd:ee:ff",
                    scan_type="port_scan",
                    scan_confidence=0.8,
                    risk_score=7.0,
                    risk_level="high",
                    packet_count=50,
                    target_ports_json="[22,80,443]",
                    target_hosts_json='["10.0.0.1"]',
                    technique_signals_json='["signal: port_scan"]',
                )
                db.insert_attack(sess, a)
                
        # Limit > 500 should be capped to 500 (returning all 10)
        r = client.get("/api/attacks?limit=1000")
        assert r.status_code == 200
        assert len(r.get_json()) == 10
        
        # Limit <= 0 should be capped to 1 (returning 1)
        r = client.get("/api/attacks?limit=0")
        assert r.status_code == 200
        assert len(r.get_json()) == 1
        
        # Return exact limit requested
        r = client.get("/api/attacks?limit=3")
        assert r.status_code == 200
        assert len(r.get_json()) == 3
        
        # Offset requested
        r = client.get("/api/attacks?limit=3&offset=8")
        assert r.status_code == 200
        assert len(r.get_json()) == 2
        
    finally:
        db.close_db()
        get_settings().db_url = original_db_url
        reset_settings()


def test_db_encryption_migration_throttle(tmp_path):
    """Test that encryption and decryption migration helpers respect row limits."""
    original_db_url = get_settings().db_url
    original_encrypt_logs = get_settings().encrypt_logs
    original_secret_key = get_settings().secret_key
    
    db_file = tmp_path / "test.db"
    get_settings().db_url = f"sqlite:///{db_file}"
    get_settings().encrypt_logs = True
    get_settings().secret_key = "test-secret-key-not-default"
    
    db.init_db()
    
    # Insert 5 plaintext attacks directly via raw connection to bypass SQLAlchemy decorator
    sensitive_fields = (
        "source_ip", "source_mac", "source_hostname",
        "source_country", "source_isp", "source_asn",
        "source_os_guess", "source_tool_guess",
        "scan_type",
        "target_ports_json", "target_hosts_json",
        "technique_signals_json",
    )
    # started_at and ended_at are NOT NULL constraints in SQLite schema
    all_fields = sensitive_fields + ("started_at", "ended_at")
    cols_sql = ", ".join(all_fields)
    val_placeholders = ", ".join(f":{c}" for c in all_fields)
    ins_sql = f"INSERT INTO attacks ({cols_sql}) VALUES ({val_placeholders})"
    
    engine = db.get_engine()
    with engine.begin() as conn:
        for i in range(5):
            vals = {c: f"value_{i}" for c in sensitive_fields}
            vals["started_at"] = datetime.now().isoformat()
            vals["ended_at"] = datetime.now().isoformat()
            conn.execute(text(ins_sql), vals)
            
    try:
        # Encrypt only 2 rows
        updated = migrate_plaintext_to_encrypted(limit=2)
        assert updated == 2
        
        # Verify database contents: 2 rows should be encrypted (starts with "enc:v1:"), 3 plaintext
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT source_ip FROM attacks")).fetchall()
            encrypted_count = sum(1 for r in rows if r[0].startswith("enc:v1:"))
            plaintext_count = sum(1 for r in rows if not r[0].startswith("enc:v1:"))
            assert encrypted_count == 2
            assert plaintext_count == 3
            
        # Encrypt the remaining rows
        updated_remaining = migrate_plaintext_to_encrypted(limit=10)
        assert updated_remaining == 3
        
        # Decrypt only 2 rows
        decrypted = migrate_encrypted_to_plaintext(limit=2)
        assert decrypted == 2
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT source_ip FROM attacks")).fetchall()
            decrypted_count = sum(1 for r in rows if not r[0].startswith("enc:v1:"))
            assert decrypted_count == 2
            
    finally:
        db.close_db()
        get_settings().db_url = original_db_url
        get_settings().encrypt_logs = original_encrypt_logs
        get_settings().secret_key = original_secret_key
        reset_settings()


def test_detector_maybe_evaluate_sequence_mismatch(tmp_path):
    """Test that _maybe_evaluate checks eval_seq to prevent race updates."""
    original_db_url = get_settings().db_url
    db_file = tmp_path / "test.db"
    get_settings().db_url = f"sqlite:///{db_file}"
    get_settings().rate_threshold = 5
    get_settings().portsweep_threshold = 5
    
    db.init_db()
    engine = DetectionEngine(get_settings())
    engine.start(mode="sim", session_name="test-seq")
    
    try:
        # Create packet records
        packets = []
        base_time = datetime.now()
        for i in range(10):
            p = PacketRecord(
                timestamp=base_time,
                source_ip="192.168.1.100",
                destination_ip="10.0.0.1",
                source_port=1234,
                destination_port=80 + i,
                protocol="TCP",
                flags={"SYN": True},
            )
            packets.append(p)
            
        # Set up SourceState
        ip = "192.168.1.100"
        st = SourceState(source_ip=ip)
        from collections import deque
        st.packets = deque(packets)
        st.eval_seq = 5  # Current sequence is 5
        engine._state[ip] = st
        
        # 1. Call with obsolete sequence (eval_seq=4)
        engine._maybe_evaluate(
            source_ip=ip,
            packets_snapshot=packets,
            last_emit_snapshot={},
            eval_seq=4
        )
        assert engine._attack_count == 0
        with db.session_scope() as sess:
            attacks = sess.scalars(sa_select(db.Attack)).all()
            assert len(attacks) == 0
            
        # 2. Call with matching sequence (eval_seq=5)
        engine._maybe_evaluate(
            source_ip=ip,
            packets_snapshot=packets,
            last_emit_snapshot={},
            eval_seq=5
        )
        assert engine._attack_count == 1
        with db.session_scope() as sess:
            attacks = sess.scalars(sa_select(db.Attack)).all()
            assert len(attacks) == 1
            assert attacks[0].source_ip == ip
            
    finally:
        engine.stop()
        db.close_db()
        get_settings().db_url = original_db_url
        reset_settings()
