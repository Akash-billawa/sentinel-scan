"""Tests for the Flask application / REST API.

Verifies authentication flow, health check, API endpoints, engine controls,
and report generation/downloads under both guest and authenticated states.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest

from backend import config, database as db


@pytest.fixture
def test_app(tmp_path, monkeypatch):
    """Initialise an isolated database and Flask app for testing."""
    original_db_url = config.get_settings().db_url
    original_auth_enabled = config.get_settings().auth_enabled
    original_admin_password = config.get_settings().auth_admin_password
    original_secret_key = config.get_settings().secret_key

    db_file = tmp_path / "test.db"
    config.get_settings().db_url = f"sqlite:///{db_file}"
    config.get_settings().auth_enabled = True
    config.get_settings().auth_admin_password = "testadminpassword"
    config.get_settings().secret_key = "test-secret-key-not-default"
    
    # Mock the read-only reports_dir property
    monkeypatch.setattr(config.Settings, "reports_dir", property(lambda self: tmp_path / "reports"))

    from backend.app import create_app
    app = create_app(config.get_settings())
    app.config["TESTING"] = True

    yield app

    # Cleanup connections and restore settings
    db.close_db()
    config.get_settings().db_url = original_db_url
    config.get_settings().auth_enabled = original_auth_enabled
    config.get_settings().auth_admin_password = original_admin_password
    config.get_settings().secret_key = original_secret_key
    config.reset_settings()


@pytest.fixture
def client(test_app):
    return test_app.test_client()


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "ok"
    assert "ts" in data


def test_auth_guest(client):
    # me endpoint for guest
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    data = r.get_json()
    assert data["auth_enabled"] is True
    assert data["user"] is None


def test_login_invalid(client):
    # bad credentials
    r = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert r.status_code == 401
    assert r.get_json()["ok"] is False


def test_login_rate_limiting(client):
    # Exhaust the rate limit (5 attempts in 60 seconds window simulated)
    from backend.app import _get_login_rate_limiter, _MAX_LOGIN_RPS
    limiter = _get_login_rate_limiter()
    limiter.reset("127.0.0.1")
    # Simulate multiple failures from the same IP
    for _ in range(_MAX_LOGIN_RPS):
        r = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401
    # Next attempt should be rate limited
    r = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 429
    assert "too many attempts" in r.get_json()["error"].lower()


def test_login_success_and_logout(client):
    # Reset the limiter so the successful login isn't blocked by the
    # rate-limit test above.
    from backend.app import _get_login_rate_limiter
    _get_login_rate_limiter().reset("127.0.0.1")
    # successful login
    r = client.post("/api/auth/login", json={"username": "admin", "password": "testadminpassword"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["user"]["username"] == "admin"

    # user is now authenticated
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.get_json()["user"]["username"] == "admin"

    # logout
    r = client.post("/api/auth/logout")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True

    # back to guest
    r = client.get("/api/auth/me")
    assert r.get_json()["user"] is None


def test_api_require_auth(client):
    # Hitting a protected endpoint without auth should redirect (for page/non-API)
    # or return 401 (for API)
    r = client.get("/api/status")
    assert r.status_code == 401
    assert r.get_json()["ok"] is False


def test_ack_endpoint_requires_token(client):
    """GET to /ack without ts+token should be rejected (403)."""
    # Insert a dummy attack first
    from backend import database as db
    with db.session_scope() as sess:
        a = db.Attack(
            source_ip="10.0.0.1", source_mac="aa:bb:cc:dd:ee:ff",
            scan_type="port_scan", scan_confidence=0.8,
            risk_score=7.0, risk_level="high",
            packet_count=50, target_ports_json="[22,80,443]",
        )
        db.insert_attack(sess, a)
        attack_id = a.id

    # GET without token → 403
    r = client.get(f"/api/attacks/{attack_id}/ack?by=slack&format=html")
    assert r.status_code == 403

    # POST without auth → 401
    r = client.post(f"/api/attacks/{attack_id}/ack", json={"by": "dashboard"})
    assert r.status_code == 401

    # Login first, then POST should work
    r = client.post("/api/auth/login", json={"username": "admin", "password": "testadminpassword"})
    assert r.status_code == 200
    r = client.post(f"/api/attacks/{attack_id}/ack", json={"by": "dashboard"})
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_ack_endpoint_with_valid_token(client):
    """GET to /ack with a valid HMAC token should succeed."""
    from backend import database as db
    from backend.crypto import generate_ack_token
    from backend.config import get_settings
    s = get_settings()
    with db.session_scope() as sess:
        a = db.Attack(
            source_ip="10.0.0.2", source_mac="aa:bb:cc:dd:ee:ff",
            scan_type="port_scan", scan_confidence=0.8,
            risk_score=7.0, risk_level="high",
            packet_count=50, target_ports_json="[22,80,443]",
        )
        db.insert_attack(sess, a)
        attack_id = a.id

    ts, token = generate_ack_token(attack_id, s.secret_key)
    r = client.get(f"/api/attacks/{attack_id}/ack?by=slack&format=html&ts={ts}&token={token}")
    assert r.status_code == 200
    assert b"Acknowledged" in r.data


def test_authenticated_endpoints(client):
    # 1. Login
    client.post("/api/auth/login", json={"username": "admin", "password": "testadminpassword"})

    # 2. Status
    r = client.get("/api/status")
    assert r.status_code == 200
    data = r.get_json()
    assert "summary" in data
    assert "settings" in data

    # 3. Stats
    r = client.get("/api/stats")
    assert r.status_code == 200
    data = r.get_json()
    assert "total_attacks" in data
    assert "active_threats" in data

    # 4. Empty Attacks list
    r = client.get("/api/attacks")
    assert r.status_code == 200
    assert len(r.get_json()) == 0


def test_engine_controls(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "testadminpassword"})

    # Start engine (sim mode)
    r = client.post("/api/engine/start", json={"mode": "sim"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["mode"] == "sim"

    # Check status
    r = client.get("/api/status")
    assert r.get_json()["summary"]["running"] is True

    # Inject test packet
    r = client.post("/api/engine/inject", json={
        "source_ip": "1.2.3.4",
        "protocol": "TCP",
        "flags": {"SYN": True},
        "destination_port": 80
    })
    assert r.status_code == 200
    assert r.get_json()["ok"] is True

    # Stop engine
    r = client.post("/api/engine/stop")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True

    # Check status again
    r = client.get("/api/status")
    assert r.get_json()["summary"]["running"] is False


def test_inject_validation_invalid_ip(client):
    from backend.app import _get_login_rate_limiter
    _get_login_rate_limiter().reset("127.0.0.1")
    client.post("/api/auth/login", json={"username": "admin", "password": "testadminpassword"})
    r = client.post("/api/engine/inject", json={"source_ip": "not-an-ip"})
    assert r.status_code == 400


def test_inject_validation_invalid_port(client):
    from backend.app import _get_login_rate_limiter
    _get_login_rate_limiter().reset("127.0.0.1")
    client.post("/api/auth/login", json={"username": "admin", "password": "testadminpassword"})
    r = client.post("/api/engine/inject", json={"destination_port": 99999})
    assert r.status_code == 400


def test_inject_validation_invalid_protocol(client):
    from backend.app import _get_login_rate_limiter
    _get_login_rate_limiter().reset("127.0.0.1")
    client.post("/api/auth/login", json={"username": "admin", "password": "testadminpassword"})
    r = client.post("/api/engine/inject", json={"protocol": "INVALID"})
    assert r.status_code == 400


def test_inject_validation_invalid_length(client):
    from backend.app import _get_login_rate_limiter
    _get_login_rate_limiter().reset("127.0.0.1")
    client.post("/api/auth/login", json={"username": "admin", "password": "testadminpassword"})
    r = client.post("/api/engine/inject", json={"length": 5})
    assert r.status_code == 400


def test_report_downloads(client):
    from backend.app import _get_login_rate_limiter
    _get_login_rate_limiter().reset("127.0.0.1")
    client.post("/api/auth/login", json={"username": "admin", "password": "testadminpassword"})

    # Download CSV
    with client.get("/api/reports/csv") as r:
        assert r.status_code == 200
        assert r.mimetype == "text/csv"
        assert len(r.data) > 0

    # Download PDF
    with client.get("/api/reports/pdf") as r:
        assert r.status_code == 200
        assert r.mimetype == "application/pdf"
        assert len(r.data) > 0


def test_password_change_invalidates_session(client):
    from backend.app import _get_login_rate_limiter
    _get_login_rate_limiter().reset("127.0.0.1")

    # Login
    r = client.post("/api/auth/login", json={"username": "admin", "password": "testadminpassword"})
    assert r.status_code == 200

    # Session works
    r = client.get("/api/auth/me")
    assert r.status_code == 200

    # Change password (to a new valid one)
    r = client.post("/api/auth/change-password", json={
        "current_password": "testadminpassword",
        "new_password": "newsecurepassword123",
    })
    assert r.status_code == 200
    assert r.get_json()["ok"] is True

    # Old session should now be rejected (me returns user=None, not 401,
    # because /api/auth/me is unauthenticated and just reports session state)
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.get_json()["user"] is None

    # Protected endpoints should also reject the stale session
    r = client.get("/api/stats")
    assert r.status_code == 401

    # Login with new password works
    _get_login_rate_limiter().reset("127.0.0.1")
    r = client.post("/api/auth/login", json={"username": "admin", "password": "newsecurepassword123"})
    assert r.status_code == 200
    assert r.get_json()["ok"] is True

    # Restore original password for other tests
    _get_login_rate_limiter().reset("127.0.0.1")
    r = client.post("/api/auth/login", json={"username": "admin", "password": "newsecurepassword123"})
    r = client.post("/api/auth/change-password", json={
        "current_password": "newsecurepassword123",
        "new_password": "testadminpassword",
    })


def test_telegram_webhook_blueprint(monkeypatch, tmp_path):
    """Test that Telegram webhook blueprint is registered when enabled."""
    from unittest.mock import patch
    db_file = tmp_path / "test_webhook.db"
    
    # Save original settings
    original_webhook_enabled = config.get_settings().telegram_webhook_enabled
    original_db_url = config.get_settings().db_url
    
    try:
        config.get_settings().telegram_webhook_enabled = True
        config.get_settings().db_url = f"sqlite:///{db_file}"
        
        from backend.app import create_app
        app = create_app(config.get_settings())
        
        # Verify the route is registered
        routes = [rule.rule for rule in app.url_map.iter_rules()]
        assert "/api/telegram/webhook" in routes
        
        # Test posting to the webhook
        client = app.test_client()
        with patch("backend.telegram_ips.handle_telegram_update") as mock_handle:
            payload = {"update_id": 12345, "message": {"text": "/status", "chat": {"id": 123}}}
            r = client.post("/api/telegram/webhook", json=payload)
            assert r.status_code == 200
            assert r.get_json() == {"ok": True}
            mock_handle.assert_called_once_with(payload)
            
    finally:
        config.get_settings().telegram_webhook_enabled = original_webhook_enabled
        config.get_settings().db_url = original_db_url
        config.reset_settings()
