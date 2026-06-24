"""Tests for the Advanced Machine-Learning attack prediction engine."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
import pytest

from backend.config import get_settings, reset_settings
from backend import database as db
from backend.predictor import (
    train_models,
    predict_attack_behavior,
    _HAS_ML
)


def test_ml_fallback_heuristics(tmp_path):
    """Test that the predictor falls back to heuristics when there is not enough database data."""
    original_db_url = get_settings().db_url
    db_file = tmp_path / "test.db"
    get_settings().db_url = f"sqlite:///{db_file}"
    
    db.init_db()
    
    # Create 3 dummy attacks (fewer than 10 needed for training)
    with db.session_scope() as sess:
        for i in range(3):
            a = db.Attack(
                source_ip="192.168.1.50",
                source_mac="aa:bb:cc:dd:ee:ff",
                scan_type="syn_scan",
                scan_confidence=0.9,
                risk_score=8.5,
                risk_level="critical",
                packet_count=100,
                target_ports_json=json.dumps([80, 81, 82, 83, 84]),
                target_hosts_json='["10.0.0.1"]',
                technique_signals_json='["signal"]',
                started_at=datetime.now(),
                ended_at=datetime.now()
            )
            db.insert_attack(sess, a)
            
    try:
        # Predict on the first attack
        with db.session_scope() as sess:
            from sqlalchemy import select
            attack = sess.scalars(select(db.Attack).limit(1)).one()
            
        pred = predict_attack_behavior(attack)
        
        # Verify next ports (sequential scan [80, 81, 82, 83, 84] -> next: [85, 86, 87])
        assert pred["predicted_next_ports"] == [85, 86, 87]
        
        # Verify high follow-up probability fallback for critical risk score
        assert pred["follow_up_probability"] == 0.85
        assert "High probability" in pred["explanation"]
        
    finally:
        db.close_db()
        get_settings().db_url = original_db_url
        reset_settings()


@pytest.mark.skipif(not _HAS_ML, reason="scikit-learn not available")
def test_ml_training_and_prediction(tmp_path):
    """Test that the Decision Tree and Port Association models are trained and execute successfully."""
    original_db_url = get_settings().db_url
    db_file = tmp_path / "test.db"
    get_settings().db_url = f"sqlite:///{db_file}"
    
    db.init_db()
    
    # Create 12 dummy attacks to trigger training.
    # Group 1: IP '10.0.0.1' does follow-up scans (another attack within 10 minutes)
    # Group 2: IP '10.0.0.2' does not do follow-up scans (attacks spaced 1 hour apart)
    base_time = datetime.now()
    
    with db.session_scope() as sess:
        # 10.0.0.1 follow-ups (Label 1)
        for i in range(6):
            a = db.Attack(
                source_ip="10.0.0.1",
                source_mac="00:11:22:33:44:55",
                scan_type="syn_scan",
                scan_confidence=0.8,
                risk_score=9.0,
                risk_level="critical",
                packet_count=150,
                target_ports_json=json.dumps([80, 443, 8080]),
                target_hosts_json='["192.168.1.1"]',
                technique_signals_json='["signal"]',
                started_at=base_time + timedelta(minutes=i * 5),
                ended_at=base_time + timedelta(minutes=i * 5 + 1)
            )
            db.insert_attack(sess, a)
            
        # 10.0.0.2 no follow-ups (Label 0)
        for i in range(6):
            a = db.Attack(
                source_ip="10.0.0.2",
                source_mac="00:11:22:33:44:66",
                scan_type="ping_sweep",
                scan_confidence=0.7,
                risk_score=2.0,
                risk_level="low",
                packet_count=10,
                target_ports_json=json.dumps([22]),
                target_hosts_json='["192.168.1.2"]',
                technique_signals_json='["signal"]',
                started_at=base_time + timedelta(hours=i * 2),
                ended_at=base_time + timedelta(hours=i * 2 + 1)
            )
            db.insert_attack(sess, a)
            
    try:
        # Force train
        train_models()
        
        # Test prediction for high-risk follow-up IP
        with db.session_scope() as sess:
            from sqlalchemy import select
            high_risk = sess.scalars(select(db.Attack).where(db.Attack.source_ip == "10.0.0.1").limit(1)).one()
            low_risk = sess.scalars(select(db.Attack).where(db.Attack.source_ip == "10.0.0.2").limit(1)).one()
            
        pred_high = predict_attack_behavior(high_risk)
        pred_low = predict_attack_behavior(low_risk)
        
        # Verify ML follow-up probabilities
        assert pred_high["follow_up_probability"] > pred_low["follow_up_probability"]
        assert pred_high["follow_up_probability"] > 0.5
        assert pred_low["follow_up_probability"] < 0.5
        
        # Verify next port association recommendation
        # Port 80, 443, 8080 were always hit together for 10.0.0.1.
        # If we predict on a test attack that has only [80, 443], the association matrix
        # should recommend 8080 as a likely next target!
        test_attack = db.Attack(
            source_ip="10.0.0.99",
            source_mac="00:11:22:33:44:99",
            scan_type="syn_scan",
            scan_confidence=0.8,
            risk_score=9.0,
            risk_level="critical",
            packet_count=50,
            target_ports_json=json.dumps([80, 443]),
            target_hosts_json='["192.168.1.1"]',
            technique_signals_json='["signal"]',
            started_at=datetime.now(),
            ended_at=datetime.now()
        )
        pred_assoc = predict_attack_behavior(test_attack)
        assert 8080 in pred_assoc["predicted_next_ports"]
        
    finally:
        db.close_db()
        get_settings().db_url = original_db_url
        reset_settings()
