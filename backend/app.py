"""SentinelScan AI — Flask application factory.

This module creates and configures the Flask app, registers all API
routes, and exposes the ``main()`` entry point used by ``run.py``.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import secrets
import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

from flask import Flask, Response, jsonify, redirect, request, send_file, session, url_for

from . import database as db
from . import alerts as alert_manager
from .auth import (
    bootstrap_default_admin,
    change_password,
    current_user,
    login_required,
    verify_credentials,
)
from .capture import LiveCapture, SimulatorCapture
from .config import Settings, get_settings
from .crypto import generate_ack_token, verify_ack_token
from .detector import DetectionEngine, PacketRecord, get_engine
from .firewall_manager import BlockResult

log = logging.getLogger("sentinelscan.app")

# ---------------------------------------------------------------------------
# Rate limiter (login brute-force protection)
# ---------------------------------------------------------------------------

_MAX_LOGIN_RPS = 5  # max attempts per IP within the sliding window
_LOGIN_WINDOW = 60  # seconds


class _RateLimiter:
    """Simple per-IP sliding-window counter."""

    def __init__(self, max_hits: int = _MAX_LOGIN_RPS, window: int = _LOGIN_WINDOW):
        self._max = max_hits
        self._window = window
        self._buckets: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

    def is_limited(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            hits = self._buckets[key]
            self._buckets[key] = [t for t in hits if t > cutoff]
            if len(self._buckets[key]) >= self._max:
                return True
            self._buckets[key].append(now)
            return False

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)


_rate_limiter = _RateLimiter()


def _get_login_rate_limiter() -> _RateLimiter:
    return _rate_limiter


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

_capture = None  # module-level for engine stop-on-shutdown


def create_app(settings: Optional[Settings] = None) -> Flask:
    """Create and configure the Flask application."""
    s = settings or get_settings()

    app = Flask(
        __name__,
        static_folder=str(s.frontend_dir / "static"),
        static_url_path="/static",
    )
    if s.proxy_fix_count > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=s.proxy_fix_count,
            x_proto=s.proxy_fix_count,
            x_host=s.proxy_fix_count,
            x_port=s.proxy_fix_count,
        )
    app.secret_key = s.secret_key
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_SECURE"] = s.public_url.startswith("https://")
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=s.auth_session_hours)
    app.config["TESTING"] = False

    # Initialise database
    db.init_db()
    bootstrap_default_admin(s)

    # Wire up the alert manager as a listener on the detection engine
    from .alerts import AlertManager
    from .detector import get_engine
    _alert_mgr = AlertManager(s)
    _engine = get_engine()
    _engine.add_listener(_alert_mgr.on_attack)

    # Wire up the SSE event broadcaster (real-time dashboard updates).
    from .events import get_broadcaster
    _broadcaster = get_broadcaster()
    _engine.add_listener(_broadcaster.on_attack)
    _engine.add_packet_callback(_broadcaster.on_packet)

    # Start the IPS approval manager expiry checker
    from .approval_manager import get_approval_manager
    _approval_mgr = get_approval_manager()
    _approval_mgr.start()

    # Start the scheduled report runner
    from .scheduler import start_scheduler
    start_scheduler()

    # Application-level IP blocking middleware.
    # Rejects HTTP requests from IPs that are in the firewall block list.
    # This protects the SentinelScan web interface (port 5000) even when
    # the OS firewall cannot be used (not admin / Windows Firewall off).
    # Other ports on the host (21, 80, 443, etc.) are NOT covered by this
    # middleware — they require the OS firewall (run as admin + firewall ON).
    from .firewall_manager import get_firewall_manager

    _blocked_check_skip_paths = {
        "/api/auth/login", "/api/healthz", "/static/",
    }

    @app.before_request
    def _reject_blocked_ips():
        if request.method == "OPTIONS":
            return None
        path = request.path.rstrip("/") or "/"
        if any(path.startswith(p) for p in _blocked_check_skip_paths):
            return None

        remote = request.remote_addr or ""
        if not remote:
            return None

        # IPv4-mapped IPv6 → plain IPv4
        if remote.startswith("::ffff:"):
            remote = remote[7:]

        try:
            fw = get_firewall_manager()
            if fw.is_blocked(remote):
                log.info("Application-layer block: rejected request from blocked IP %s %s",
                         remote, path)
                return jsonify({
                    "ok": False, "error": "Your IP is blocked by SentinelScan",
                }), 403
        except Exception:
            pass
        return None

    # Register routes
    _register_routes(app, s)

    # Wire up the Telegram webhook blueprint if enabled
    if s.telegram_webhook_enabled:
        from .telegram_ips import create_webhook_blueprint
        app.register_blueprint(create_webhook_blueprint())

    return app


def _register_routes(app: Flask, settings: Settings) -> None:
    """Register all HTTP routes on the Flask app."""

    # ---- Health ----------------------------------------------------------

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok", "ts": datetime.now(timezone.utc).isoformat()})

    # ---- Real-time events (SSE) ------------------------------------------

    @app.route("/api/events/stream")
    def sse_events():
        from .events import get_broadcaster
        broadcaster = get_broadcaster()
        try:
            q = broadcaster.subscribe()
        except RuntimeError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 503
        return Response(
            broadcaster.generate(q),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    # ---- Auth ------------------------------------------------------------

    @app.route("/api/auth/me")
    def auth_me():
        user = current_user()
        return jsonify({
            "auth_enabled": settings.auth_enabled,
            "user": user,
        })

    @app.route("/api/auth/login", methods=["POST"])
    def auth_login():
        if not settings.auth_enabled:
            return jsonify({"ok": True, "user": {"username": "guest"}})

        ip = request.remote_addr or "unknown"
        if _rate_limiter.is_limited(ip):
            return jsonify({"ok": False, "error": "too many attempts, try again later"}), 429

        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
        user = verify_credentials(username, password)
        if user is None:
            return jsonify({"ok": False, "error": "invalid credentials"}), 401

        _rate_limiter.reset(ip)
        session.permanent = True
        session["user"] = {"id": user.id, "username": user.username, "session_version": getattr(user, "session_version", 0)}
        return jsonify({"ok": True, "user": {"id": user.id, "username": user.username}})

    @app.route("/api/auth/logout", methods=["POST"])
    def auth_logout():
        session.pop("user", None)
        return jsonify({"ok": True})

    @app.route("/api/auth/change-password", methods=["POST"])
    @login_required
    def auth_change_password():
        data = request.get_json(silent=True) or {}
        current_pw = data.get("current_password", "")
        new_pw = data.get("new_password", "")
        user_data = current_user()
        if not user_data:
            return jsonify({"ok": False, "error": "not authenticated"}), 401

        # Verify current password
        from sqlalchemy import select as sa_select
        with db.session_scope() as sess:
            user = sess.scalar(sa_select(db.User).where(db.User.id == user_data["id"]))
            if not user or not user.is_active:
                return jsonify({"ok": False, "error": "user not found"}), 401
            from werkzeug.security import check_password_hash
            if not check_password_hash(user.password_hash, current_pw):
                return jsonify({"ok": False, "error": "current password incorrect"}), 403

        ok = change_password(user_data["username"], new_pw)
        if not ok:
            return jsonify({"ok": False, "error": "new password too short (min 8 chars)"}), 400

        session.pop("user", None)
        return jsonify({"ok": True})

    # ---- Dashboard / Status ----------------------------------------------

    @app.route("/api/status")
    @login_required
    def api_status():
        engine = get_engine()
        # ponytail: surface packet-buffer health so persistent DB failures
        # don't silently grow memory or drop events unnoticed.
        packet_buffer_stats: Dict[str, int] = {}
        try:
            buf = getattr(engine, "_packet_buffer", None)
            if buf is not None and hasattr(buf, "stats"):
                packet_buffer_stats = buf.stats()
        except Exception:
            pass
        from .firewall_manager import get_firewall_manager, get_backend, EnforcementStatus
        from sqlalchemy import func, select
        mgr = get_firewall_manager()
        with db.session_scope() as s:
            status_counts = dict(s.execute(
                select(db.BlockedIP.status, func.count(db.BlockedIP.id))
                .where(db.BlockedIP.removed_at.is_(None))
                .group_by(db.BlockedIP.status)
            ).all())
        firewall_status = {
            "backend": get_backend().name,
            "verified": status_counts.get("verified", 0),
            "failed": status_counts.get("failed", 0),
            "pending": status_counts.get("pending", 0),
            "applied": status_counts.get("applied", 0),
            "total": sum(status_counts.values()),
            "blocked_in_memory": len(mgr.list_blocked()),
        }
        return jsonify({
            "summary": engine.summary(),
            "packet_buffer": packet_buffer_stats,
            "settings": {
                "capture_mode": settings.capture_mode,
                "interface": settings.interface,
                "auth_enabled": settings.auth_enabled,
                "ips_enabled": settings.ips_enabled,
                "ips_mode": settings.ips_mode,
            },
            "alert_channels": alert_manager.channel_status(settings),
            "firewall": firewall_status,
        })

    @app.route("/api/stats")
    @login_required
    def api_stats():
        return jsonify(db.dashboard_stats())

    # ---- Attacks ---------------------------------------------------------

    @app.route("/api/attacks")
    @login_required
    def api_attacks():
        limit = request.args.get("limit", 100, type=int)
        offset = request.args.get("offset", 0, type=int)
        limit = min(500, max(1, limit))
        attacks = db.list_attacks(limit=limit, offset=offset)
        return jsonify([a.to_dict() for a in attacks])

    @app.route("/api/attacks/<int:attack_id>", methods=["GET"])
    @login_required
    def api_attack_detail(attack_id: int):
        attack = db.get_attack(attack_id)
        if attack is None:
            return jsonify({"ok": False, "error": "attack not found"}), 404
        from .predictor import predict_attack_behavior
        data = attack.to_dict()
        data["predictions"] = predict_attack_behavior(attack)
        return jsonify(data)

    @app.route("/api/attacks/<int:attack_id>/ack", methods=["GET", "POST"])
    def api_ack_attack(attack_id: int):
        from html import escape as html_escape
        # GET requires HMAC token; POST (dashboard) is session-authenticated.
        if request.method == "GET":
            ts_str = request.args.get("ts", "")
            token = request.args.get("token", "")
            by = request.args.get("by", "email")
            fmt = request.args.get("format", "json")
            if not ts_str or not token:
                return jsonify({"ok": False, "error": "missing ts/token"}), 403
            if not verify_ack_token(attack_id, settings.secret_key, ts_str, token):
                return jsonify({"ok": False, "error": "invalid or expired token"}), 403
            attack = db.acknowledge_attack(attack_id, by)
            if attack is None:
                return jsonify({"ok": False, "error": "attack not found"}), 404
            if fmt == "html":
                safe_by = html_escape(by, quote=True)
                return Response(
                    f"<html><body><h2>Acknowledged</h2><p>Attack #{attack_id} acknowledged by {safe_by}.</p></body></html>",
                    mimetype="text/html",
                )
            return jsonify({"ok": True, "attack_id": attack_id, "by": by})

        # POST — dashboard session-authenticated ack
        if not current_user():
            return jsonify({"ok": False, "error": "authentication required"}), 401
        data = request.get_json(silent=True) or {}
        by = data.get("by", "dashboard")
        attack = db.acknowledge_attack(attack_id, by)
        if attack is None:
            return jsonify({"ok": False, "error": "attack not found"}), 404
        return jsonify({"ok": True, "attack_id": attack_id, "by": by})

    # ---- Engine controls -------------------------------------------------

    @app.route("/api/engine/start", methods=["POST"])
    @login_required
    def api_engine_start():
        global _capture
        data = request.get_json(silent=True) or {}
        mode = data.get("mode", settings.capture_mode)
        engine = get_engine()

        if engine.running:
            return jsonify({"ok": True, "mode": engine.mode, "message": "already running"})

        if mode == "auto":
            from .capture import start_capture
            capture, actual_mode = start_capture(engine, mode="auto")
            _capture = capture
            engine.start(mode=actual_mode, session_name=f"api-{actual_mode}")
            return jsonify({"ok": True, "mode": actual_mode})

        engine.start(mode=mode, session_name=f"api-{mode}")

        if mode == "live":
            _capture = LiveCapture(engine, settings)
            _capture.start()
        elif mode == "sim":
            _capture = SimulatorCapture(engine, settings)
            _capture.start()
        else:
            return jsonify({"ok": False, "error": f"unknown mode: {mode}"}), 400

        return jsonify({"ok": True, "mode": mode})

    @app.route("/api/engine/stop", methods=["POST"])
    @login_required
    def api_engine_stop():
        global _capture
        engine = get_engine()
        if not engine.running:
            return jsonify({"ok": True, "message": "already stopped"})
        if _capture:
            _capture.stop()
            _capture = None
        engine.stop()
        return jsonify({"ok": True})

    @app.route("/api/engine/inject", methods=["POST"])
    @login_required
    def api_engine_inject():
        data = request.get_json(silent=True) or {}
        source_ip = data.get("source_ip", "")
        if not source_ip:
            return jsonify({"ok": False, "error": "source_ip required"}), 400
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            return jsonify({"ok": False, "error": "invalid IP address"}), 400

        dest_port = data.get("destination_port", 80)
        if not isinstance(dest_port, int) or dest_port < 0 or dest_port > 65535:
            return jsonify({"ok": False, "error": "invalid destination_port (0-65535)"}), 400

        protocol = data.get("protocol", "TCP").upper()
        if protocol not in ("TCP", "UDP", "ICMP"):
            return jsonify({"ok": False, "error": "protocol must be TCP, UDP, or ICMP"}), 400

        length = data.get("length", 64)
        if not isinstance(length, int) or length < 64:
            return jsonify({"ok": False, "error": "length must be >= 64 bytes"}), 400

        flags = data.get("flags", {"SYN": True})
        if not isinstance(flags, dict):
            return jsonify({"ok": False, "error": "flags must be an object"}), 400
        valid_flag_keys = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
        bad_keys = [k for k in flags if k not in valid_flag_keys]
        if bad_keys:
            return jsonify({
                "ok": False,
                "error": f"invalid flag keys: {bad_keys}; allowed: {sorted(valid_flag_keys)}",
            }), 400
        if not any(bool(v) for v in flags.values()):
            return jsonify({"ok": False, "error": "at least one flag must be true"}), 400
        engine = get_engine()
        if not engine.running:
            return jsonify({"ok": False, "error": "engine not running"}), 400

        pkt = PacketRecord(
            timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
            source_ip=source_ip,
            destination_ip=data.get("destination_ip", "10.0.0.1"),
            source_port=data.get("source_port", 12345),
            destination_port=dest_port,
            protocol=protocol,
            flags=flags,
            length=length,
        )
        engine.feed_packet(pkt)
        return jsonify({"ok": True})

    # ---- Reports ---------------------------------------------------------

    @app.route("/api/reports/csv")
    @login_required
    def api_reports_csv():
        try:
            from .reports import generate_csv
            path, count = generate_csv()
        except OSError as exc:
            log.error("CSV report failed: %s (path=%s)", exc, getattr(exc, "filename", "?"))
            return jsonify({"ok": False, "error": f"could not write CSV: {exc}"}), 500
        except Exception as exc:
            log.exception("CSV report unexpected error: %s", exc)
            return jsonify({"ok": False, "error": "report generation failed"}), 500
        return send_file(path, mimetype="text/csv", as_attachment=True,
                         download_name=path.name)

    @app.route("/api/reports/pdf")
    @login_required
    def api_reports_pdf():
        try:
            from .reports import generate_pdf
            path, count = generate_pdf()
            return send_file(path, mimetype="application/pdf", as_attachment=True,
                             download_name=path.name)
        except ImportError:
            return jsonify({"ok": False, "error": "PDF generation requires the 'reportlab' package. Install it with: pip install reportlab"}), 501

    # ---- Alerts & Packets ------------------------------------------------

    @app.route("/api/alerts")
    @login_required
    def api_alerts():
        limit = request.args.get("limit", 50, type=int)
        alerts = db.list_alerts(limit=limit)
        return jsonify([a.to_dict() for a in alerts])

    @app.route("/api/packets")
    @login_required
    def api_packets():
        limit = request.args.get("limit", 40, type=int)
        engine = get_engine()
        packets = engine.recent_packets(limit=limit)
        return jsonify(packets)

    # ---- IPS -------------------------------------------------------------

    @app.route("/api/ips/status")
    @login_required
    def api_ips_status():
        from .config import get_settings as _gs
        from .firewall_manager import get_firewall_manager
        s = _gs()
        fw = get_firewall_manager()
        return jsonify({
            "enabled": s.ips_enabled,
            "mode": s.ips_mode,
            "approval_timeout": s.ips_approval_timeout,
            "block_expiry": s.ips_block_expiry,
            "firewall": fw.health(),
        })

    @app.route("/api/ips/pending")
    @login_required
    def api_ips_pending():
        from .approval_manager import get_approval_manager
        mgr = get_approval_manager()
        actions = mgr.list_pending()
        return jsonify([a.to_dict() for a in actions])

    @app.route("/api/ips/blocked")
    @login_required
    def api_ips_blocked():
        # Source of truth is the DB (spec #5). The in-memory map only
        # tracks IPs the manager currently knows about — it has no
        # status / backend / verified_at / apply_* diagnostics, so
        # returning from there would leave the dashboard showing every
        # row as "Pending" (because status is missing → frontend defaults).
        from .firewall_manager import get_firewall_manager, get_backend
        from sqlalchemy import select
        mgr = get_firewall_manager()
        with db.session_scope() as s:
            rows = list(s.scalars(
                select(db.BlockedIP)
                .where(db.BlockedIP.removed_at.is_(None))
                .order_by(db.BlockedIP.created_at.desc())
            ))
        return jsonify({
            "ok": True,
            "backend": get_backend().name,
            "count": len(rows),
            "rules": [{
                "ip": r.ip,
                "direction": r.direction,
                "action": r.action,
                "rule_name": r.rule_name,
                "reason": r.reason,
                "created_at": r.created_at.isoformat() + "Z" if r.created_at else None,
                "status": r.status or "pending",
                "backend": r.backend,
                "verified_at": r.verified_at.isoformat() + "Z" if r.verified_at else None,
                "failure_reason": r.failure_reason,
                "in_memory": mgr.is_blocked(r.ip),
                "apply_exit_code": r.apply_exit_code,
                "apply_stdout": r.apply_stdout,
                "apply_stderr": r.apply_stderr,
                "apply_exception": r.apply_exception,
                "apply_command": r.apply_command,
                # Dual-path diagnostics (Phase 6).
                "direct_apply_command": r.direct_apply_command,
                "direct_apply_exit_code": r.direct_apply_exit_code,
                "direct_apply_stdout": r.direct_apply_stdout,
                "direct_apply_stderr": r.direct_apply_stderr,
                "direct_apply_exception": r.direct_apply_exception,
                "fallback_apply_command": r.fallback_apply_command,
                "fallback_apply_exit_code": r.fallback_apply_exit_code,
                "fallback_apply_stdout": r.fallback_apply_stdout,
                "fallback_apply_stderr": r.fallback_apply_stderr,
                "fallback_apply_exception": r.fallback_apply_exception,
                "last_attempt_path": r.last_attempt_path,
            } for r in rows],
        })

    @app.route("/api/ips/block", methods=["POST"])
    @login_required
    def api_ips_block():
        from .config import get_settings as _gs
        s = _gs()
        if not s.ips_enabled:
            return jsonify({
                "ok": False,
                "error": "IPS is disabled (set SENTINEL_IPS_ENABLED=true to enable blocking)",
                "result": "disabled",
            }), 409

        data = request.get_json(silent=True) or {}
        ip = data.get("ip", "")
        reason = data.get("reason", "Manual block via dashboard")
        if not ip:
            return jsonify({"ok": False, "error": "ip required"}), 400
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"ok": False, "error": "invalid IP address"}), 400
        from .firewall_manager import get_firewall_manager
        mgr = get_firewall_manager()
        result = mgr.block_ip(ip, reason=reason)
        # Surface the tri-state so the dashboard doesn't say "ok" when
        # the OS rule never actually applied (no admin / unsupported).
        return jsonify({
            "ok": result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED),
            "result": result.value,
            "firewall_applied": result == BlockResult.APPLIED,
            "ip": ip,
        }), (200 if result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED) else 502)

    @app.route("/api/ips/unblock", methods=["POST"])
    @login_required
    def api_ips_unblock():
        from .config import get_settings as _gs
        s = _gs()
        if not s.ips_enabled:
            return jsonify({
                "ok": False,
                "error": "IPS is disabled (set SENTINEL_IPS_ENABLED=true)",
                "result": "disabled",
            }), 409

        data = request.get_json(silent=True) or {}
        ip = data.get("ip", "")
        if not ip:
            return jsonify({"ok": False, "error": "ip required"}), 400
        from .firewall_manager import get_firewall_manager
        mgr = get_firewall_manager()
        result = mgr.unblock_ip(ip)
        return jsonify({
            "ok": result in (BlockResult.UNAPPLIED, BlockResult.ALREADY_ABSENT, BlockResult.PARTIAL),
            "result": result.value,
            "ip": ip,
        }), (200 if result != BlockResult.FAILED else 502)

    # ---- /api/firewall/* (spec-compliant enforcement endpoints) ----------
    # Spec #8: GET /api/firewall/rules + POST /api/firewall/unblock/<ip>.
    # Older /api/ips/blocked and /api/ips/unblock still work for back-compat.

    @app.route("/api/firewall/rules", methods=["GET"])
    @login_required
    def api_firewall_rules():
        # Spec #5: include status / backend / verified_at / failure_reason.
        # Source of truth is the database (every block/unblock writes there),
        # not the in-memory map — that way the dashboard reflects what was
        # actually enforced, not just what the manager currently knows about.
        from .firewall_manager import get_firewall_manager, get_backend
        from sqlalchemy import select
        mgr = get_firewall_manager()
        with db.session_scope() as s:
            rows = list(s.scalars(
                select(db.BlockedIP)
                .where(db.BlockedIP.removed_at.is_(None))
                .order_by(db.BlockedIP.created_at.desc())
            ))
        return jsonify({
            "ok": True,
            "backend": get_backend().name,
            "count": len(rows),
            "rules": [{
                "id": r.id,
                "ip": r.ip,
                "direction": r.direction,
                "action": r.action,
                "rule_name": r.rule_name,
                "reason": r.reason,
                "created_at": r.created_at.isoformat() + "Z" if r.created_at else None,
                "status": r.status or "pending",
                "backend": r.backend,
                "verified_at": r.verified_at.isoformat() + "Z" if r.verified_at else None,
                "failure_reason": r.failure_reason,
                "in_memory": mgr.is_blocked(r.ip),
                # Apply-block diagnostic surface. Only populated when
                # apply_block actually ran; for legacy FAILED rows from
                # before this column existed these are null/empty.
                "apply_exit_code": r.apply_exit_code,
                "apply_stdout": r.apply_stdout,
                "apply_stderr": r.apply_stderr,
                "apply_exception": r.apply_exception,
                "apply_command": r.apply_command,
                # Dual-path diagnostics (Phase 6). apply_* above reflects the
                # last attempt (= source of final status); direct_* /
                # fallback_* preserve the forensic record of each path
                # independently, so a failed direct call doesn't erase the
                # reason it failed when the fallback overwrites apply_*.
                "direct_apply_command": r.direct_apply_command,
                "direct_apply_exit_code": r.direct_apply_exit_code,
                "direct_apply_stdout": r.direct_apply_stdout,
                "direct_apply_stderr": r.direct_apply_stderr,
                "direct_apply_exception": r.direct_apply_exception,
                "fallback_apply_command": r.fallback_apply_command,
                "fallback_apply_exit_code": r.fallback_apply_exit_code,
                "fallback_apply_stdout": r.fallback_apply_stdout,
                "fallback_apply_stderr": r.fallback_apply_stderr,
                "fallback_apply_exception": r.fallback_apply_exception,
                "last_attempt_path": r.last_attempt_path,
            } for r in rows],
        })

    @app.route("/api/firewall/unblock/<ip>", methods=["POST"])
    @login_required
    def api_firewall_unblock(ip):
        from .firewall_manager import get_firewall_manager, BlockResult
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"ok": False, "error": "invalid IP"}), 400
        mgr = get_firewall_manager()
        result = mgr.unblock_ip(ip, decision_source="dashboard")
        ok = result in (BlockResult.UNAPPLIED, BlockResult.ALREADY_ABSENT, BlockResult.PARTIAL)
        return jsonify({
            "ok": ok,
            "result": result.value,
            "ip": ip,
        }), (200 if ok and result != BlockResult.FAILED else 502)

    # ---- /api/firewall/rediagnose/<ip> ------------------------------------
    # Re-runs apply_block for an existing row and captures the full
    # diagnostic surface (command / rc / stdout / stderr / exception)
    # without modifying enforcement state. Used to capture forensic data
    # for FAILED rows created before the apply_* columns existed.

    @app.route("/api/firewall/rediagnose/<ip>", methods=["POST"])
    @login_required
    def api_firewall_rediagnose(ip):
        from .firewall_manager import get_firewall_manager, get_backend
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"ok": False, "error": "invalid IP"}), 400
        mgr = get_firewall_manager()
        backend = get_backend()
        rule_name = f"SentinelScan Block {ip}"
        try:
            ok, diag = backend.apply_block(ip, rule_name, "inbound")
        except Exception as exc:
            import traceback as _tb
            diag = {
                "apply_command": "",
                "apply_exit_code": None,
                "apply_stdout": "",
                "apply_stderr": "",
                "apply_exception": _tb.format_exc(),
            }
            ok = False
        # Persist diag onto the most-recent live row (do NOT change status
        # unless verify_block disagrees; this is a read-only diagnostic run).
        from .firewall_manager import _update_db_status
        _update_db_status(
            ip,
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
        return jsonify({
            "ok": True,
            "ip": ip,
            "apply_ok": ok,
            "backend": backend.name,
            **diag,
        })

    # ---- /api/firewall/selftest -------------------------------------------
    # Operator-facing end-to-end probe. Creates a real Windows Defender
    # firewall rule (or iptables / nftables on Linux), confirms it appears,
    # then removes it. The full diagnostic — every command, exit code,
    # stdout, stderr — is returned so a failing run tells the operator
    # exactly which step broke.

    @app.route("/api/firewall/selftest", methods=["POST"])
    @login_required
    def api_firewall_selftest():
        from .firewall_manager import (
            get_firewall_manager, get_backend, _powershell_run,
            _verify_windows, _is_elevated, _block_windows, _unblock_windows,
            BlockResult,
        )
        ip = "192.168.56.250"   # RFC 5737 doc range — guaranteed harmless
        rule_name = "SentinelScan SelfTest"
        backend = get_backend()
        diag: Dict[str, object] = {
            "backend": backend.name,
            "elevated": _is_elevated() if backend.name == "windows_defender" else None,
            "steps": [],
        }

        def _step(label: str, ok: bool, detail: str, extra: Optional[Dict] = None) -> bool:
            entry = {"label": label, "ok": ok, "detail": detail}
            if extra:
                entry.update(extra)
            diag["steps"].append(entry)
            return ok

        # 1. Create. apply_block now returns (ok, diag) — surface the
        # full diagnostic on failure so /api/firewall/selftest tells the
        # operator exactly which command failed.
        apply_ret = (_block_windows(ip, rule_name, "inbound")
                     if backend.name == "windows_defender"
                     else backend.apply_block(ip, rule_name, "inbound"))
        applied, apply_diag = (apply_ret if isinstance(apply_ret, tuple)
                               else (bool(apply_ret), {}))
        _step(
            "create", applied,
            f"apply_block returned {applied}",
            {"ip": ip, "rule_name": rule_name, **apply_diag},
        )

        # 2. Verify
        ok, detail = _verify_windows(rule_name, ip) if backend.name == "windows_defender" else backend.verify_block(ip, rule_name)
        _step("verify", ok, detail)

        # 3. Inspect address filter (Windows-only; otherwise skip)
        if backend.name == "windows_defender":
            rc, out, err = _powershell_run(
                "Get-NetFirewallRule -DisplayName '" + rule_name.replace("'", "''") + "' "
                "| Get-NetFirewallAddressFilter | Format-List RemoteAddress",
                timeout=15,
            )
            _step("address_filter", rc == 0 and ip in out,
                  f"powershell rc={rc} stdout={out.strip()[:200]} stderr={err.strip()[:200]}")

        # 4. Remove
        removed = _unblock_windows(rule_name) if backend.name == "windows_defender" else backend.remove_block(ip, rule_name)
        _step("remove", removed in (BlockResult.UNAPPLIED, BlockResult.ALREADY_ABSENT),
              f"unblock returned {removed}")

        # 5. Re-verify it's gone
        ok2, detail2 = _verify_windows(rule_name, ip) if backend.name == "windows_defender" else backend.verify_block(ip, rule_name)
        _step("verify_after_remove", not ok2,
              detail2 if not ok2 else "rule still present (unexpected)")

        diag["ok"] = all(s["ok"] for s in diag["steps"])
        diag["ip"] = ip
        diag["rule_name"] = rule_name
        # Cap stdout/stderr length so the response stays readable.
        for s in diag["steps"]:
            if isinstance(s.get("detail"), str) and len(s["detail"]) > 400:
                s["detail"] = s["detail"][:400] + "...(truncated)"
        return jsonify(diag), (200 if diag["ok"] else 500)

    @app.route("/api/ips/approve/<action_id>", methods=["POST"])
    @login_required
    def api_ips_approve(action_id):
        from .approval_manager import get_approval_manager
        from .whitelist_manager import get_whitelist_manager
        from .pending_rate_limiter import get_pending_rate_limiter
        mgr = get_approval_manager()
        action = mgr.approve(action_id, by="dashboard")
        if action is None:
            return jsonify({"ok": False, "error": "action not found or already decided"}), 404
        wl = get_whitelist_manager()
        ttl = (request.get_json(silent=True) or {}).get("ttl_seconds")
        wl.add(
            ip=action.source_ip,
            ttl_seconds=ttl,
            added_by="dashboard",
            reason=f"Approved via IPS: {action.threat_type} (risk={action.risk_score:.1f})",
            action_id=action.id,
        )
        get_pending_rate_limiter().unmark_pending(action.source_ip)
        return jsonify({"ok": True, "ip": action.source_ip})

    @app.route("/api/ips/deny/<action_id>", methods=["POST"])
    @login_required
    def api_ips_deny(action_id):
        from .approval_manager import get_approval_manager
        from .firewall_manager import get_firewall_manager
        mgr = get_approval_manager()
        action = mgr.deny(action_id, by="dashboard")
        if action is None:
            return jsonify({"ok": False, "error": "action not found or already decided"}), 404
        fw = get_firewall_manager()
        result = fw.block_ip(
            action.source_ip,
            reason=f"Blocked via IPS deny: {action.threat_type} (risk={action.risk_score:.1f})",
        )
        # Only mark executed when OS firewall actually applied.
        if result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED):
            mgr.mark_executed(action_id)
        message = {
            BlockResult.APPLIED: f"IP {action.source_ip} blocked (firewall applied)",
            BlockResult.ALREADY_BLOCKED: f"IP {action.source_ip} was already blocked",
            BlockResult.RECORDED_ONLY: (
                f"IP {action.source_ip} recorded in app only — "
                f"OS firewall not applied (run as admin)"
            ),
        }.get(result, f"IP {action.source_ip} block failed ({result.value})")
        return jsonify({
            "ok": result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED),
            "result": result.value,
            "firewall_applied": result == BlockResult.APPLIED,
            "message": message,
        }), (200 if result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED) else 502)

    # ---- Spec-compliant /allow and /block endpoints --------------------
    # These are the Human-in-the-Loop IPS endpoints the spec calls for.
    # They share the existing approve/deny approval manager underneath and
    # add: whitelist for Allow, decision audit logging, and idempotent
    # duplicate-decision rejection.

    def _log_ips_decision(action, decision: str, by: str, extra=None) -> None:
        """Thin wrapper around the audit module — keeps imports local."""
        from .audit import log_decision as _log
        _log(action, decision, by, extra)

    @app.route("/api/ips/allow/<action_id>", methods=["POST"])
    @login_required
    def api_ips_allow(action_id):
        from .approval_manager import get_approval_manager
        from .whitelist_manager import get_whitelist_manager
        from .pending_rate_limiter import get_pending_rate_limiter
        mgr = get_approval_manager()
        action = mgr.approve(action_id, by="dashboard")
        if action is None:
            # Duplicate or unknown — never re-apply an existing decision.
            return jsonify({
                "ok": False,
                "error": "duplicate decision or unknown action",
            }), 409
        wl = get_whitelist_manager()
        ttl = (request.get_json(silent=True) or {}).get("ttl_seconds")
        entry = wl.add(
            ip=action.source_ip,
            ttl_seconds=ttl,
            added_by="dashboard",
            reason=f"Allowed via IPS: {action.threat_type} (risk={action.risk_score:.1f})",
            action_id=action.id,
        )
        # Stop throttling — the operator just said this IP is OK.
        get_pending_rate_limiter().unmark_pending(action.source_ip)
        _log_ips_decision(action, "allow", "dashboard", extra={
            "whitelist_expires_at": entry.expires_at.isoformat() + "Z",
        })
        return jsonify({
            "ok": True,
            "ip": action.source_ip,
            "whitelist_ttl_seconds": int((entry.expires_at - entry.added_at).total_seconds()),
            "whitelist_expires_at": entry.expires_at.isoformat() + "Z",
        })

    @app.route("/api/ips/block/<action_id>", methods=["POST"])
    @login_required
    def api_ips_block_pending(action_id):
        from .approval_manager import get_approval_manager
        from .firewall_manager import get_firewall_manager
        from .pending_rate_limiter import get_pending_rate_limiter
        mgr = get_approval_manager()
        # deny() is atomic on status check — returns None if already decided.
        action = mgr.deny(action_id, by="dashboard")
        if action is None:
            return jsonify({
                "ok": False,
                "error": "duplicate decision or unknown action",
            }), 409
        fw = get_firewall_manager()
        result = fw.block_ip(
            action.source_ip,
            reason=f"Blocked via IPS: {action.threat_type} (risk={action.risk_score:.1f})",
        )
        if result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED):
            mgr.mark_executed(action_id)
        # Stop throttling — decision is in either way.
        get_pending_rate_limiter().unmark_pending(action.source_ip)
        _log_ips_decision(action, "block", "dashboard", extra={
            "firewall_result": result.value,
            "firewall_applied": result == BlockResult.APPLIED,
        })
        return jsonify({
            "ok": result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED),
            "result": result.value,
            "firewall_applied": result == BlockResult.APPLIED,
            "ip": action.source_ip,
        }), (200 if result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED) else 502)

    @app.route("/api/ips/whitelist", methods=["GET"])
    @login_required
    def api_ips_whitelist_list():
        from .whitelist_manager import get_whitelist_manager
        from .pending_rate_limiter import get_pending_rate_limiter
        wl = get_whitelist_manager()
        return jsonify({
            "entries": [e.to_dict() for e in wl.list_entries()],
            "size": wl.size(),
            "rate_limiter": get_pending_rate_limiter().stats(),
        })

    @app.route("/api/ips/whitelist/<ip>", methods=["DELETE"])
    @login_required
    def api_ips_whitelist_remove(ip):
        from .whitelist_manager import get_whitelist_manager
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"ok": False, "error": "invalid IP"}), 400
        wl = get_whitelist_manager()
        removed = wl.remove(ip)
        return jsonify({"ok": removed, "ip": ip})

    @app.route("/api/ips/whitelist/<ip>/block", methods=["POST"])
    @login_required
    def api_ips_whitelist_block(ip):
        from .whitelist_manager import get_whitelist_manager
        from .firewall_manager import get_firewall_manager
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"ok": False, "error": "invalid IP"}), 400
        wl = get_whitelist_manager()
        entry = wl.remove(ip)
        if not entry:
            return jsonify({"ok": False, "error": "IP not in whitelist"}), 404
        fw = get_firewall_manager()
        result = fw.block_ip(ip, reason="Blocked from approved list")
        return jsonify({
            "ok": result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED),
            "result": result.value,
            "firewall_applied": result == BlockResult.APPLIED,
            "ip": ip,
        }), (200 if result in (BlockResult.APPLIED, BlockResult.ALREADY_BLOCKED) else 502)

    @app.route("/api/ips/settings", methods=["POST"])
    @login_required
    def api_ips_settings():
        data = request.get_json(silent=True) or {}
        from . import config as cfg
        s = cfg.get_settings()
        if "enabled" in data:
            s.ips_enabled = bool(data["enabled"])
        if "mode" in data:
            valid_modes = {"approve", "auto_block", "alert_only"}
            if data["mode"] not in valid_modes:
                return jsonify({"ok": False, "error": f"Invalid mode; must be one of: {', '.join(sorted(valid_modes))}"}), 400
            s.ips_mode = data["mode"]
        if "approval_timeout" in data:
            s.ips_approval_timeout = int(data["approval_timeout"])
        if "block_expiry" in data:
            s.ips_block_expiry = int(data["block_expiry"])
        return jsonify({"ok": True})

    # ---- Scheduled Reports -----------------------------------------------

    @app.route("/api/reports/schedules", methods=["GET"])
    @login_required
    def list_schedules():
        with db.session_scope() as s:
            schedules = s.query(db.ReportSchedule).order_by(db.ReportSchedule.created_at.desc()).all()
            return jsonify([sc.to_dict() for sc in schedules])

    @app.route("/api/reports/schedules", methods=["POST"])
    @login_required
    def create_schedule():
        data = request.get_json(silent=True) or {}
        name = data.get("name", "").strip()
        if not name:
            return jsonify({"ok": False, "error": "name is required"}), 400
        frequency = data.get("frequency", "daily")
        if frequency not in ("daily", "weekly"):
            return jsonify({"ok": False, "error": "frequency must be daily or weekly"}), 400
        recipients = data.get("recipients", "")
        now = datetime.now(timezone.utc)
        delta = timedelta(days=7 if frequency == "weekly" else 1)
        sched = db.ReportSchedule(
            name=name,
            frequency=frequency,
            recipients=recipients,
            is_active=True,
            next_run_at=now + delta,
        )
        with db.session_scope() as s:
            s.add(sched)
            s.flush()
            result = sched.to_dict()
        return jsonify({"ok": True, "schedule": result}), 201

    @app.route("/api/reports/schedules/<int:schedule_id>", methods=["PATCH"])
    @login_required
    def update_schedule(schedule_id):
        data = request.get_json(silent=True) or {}
        with db.session_scope() as s:
            sched = s.query(db.ReportSchedule).get(schedule_id)
            if sched is None:
                return jsonify({"ok": False, "error": "not found"}), 404
            if "name" in data:
                sched.name = str(data["name"]).strip() or sched.name
            if "frequency" in data:
                if data["frequency"] in ("daily", "weekly"):
                    sched.frequency = data["frequency"]
            if "recipients" in data:
                sched.recipients = str(data["recipients"])
            if "is_active" in data:
                sched.is_active = bool(data["is_active"])
            # Recalculate next_run if frequency changed
            now = datetime.now(timezone.utc)
            delta = timedelta(days=7 if sched.frequency == "weekly" else 1)
            sched.next_run_at = now + delta
            result = sched.to_dict()
        return jsonify({"ok": True, "schedule": result})

    @app.route("/api/reports/schedules/<int:schedule_id>", methods=["DELETE"])
    @login_required
    def delete_schedule(schedule_id):
        with db.session_scope() as s:
            sched = s.query(db.ReportSchedule).get(schedule_id)
            if sched is None:
                return jsonify({"ok": False, "error": "not found"}), 404
            s.delete(sched)
        return jsonify({"ok": True})

    @app.route("/api/reports/schedules/<int:schedule_id>/run", methods=["POST"])
    @login_required
    def run_schedule_now(schedule_id):
        """Trigger an immediate report for a given schedule."""
        from .reports import generate_pdf
        with db.session_scope() as s:
            sched = s.query(db.ReportSchedule).get(schedule_id)
            if sched is None:
                return jsonify({"ok": False, "error": "not found"}), 404
            recipients = sched.recipients
        since = datetime.now(timezone.utc) - timedelta(days=7 if sched.frequency == "weekly" else 1)
        path, count = generate_pdf(since=since)
        if count == 0:
            return jsonify({"ok": True, "message": "No attacks in reporting window"})
        from .scheduler import _send_report_email
        sent = _send_report_email(recipients, path, path.name)
        return jsonify({"ok": True, "attacks": count, "emailed": sent})

    # ---- Per-Source Timeline ---------------------------------------------

    @app.route("/api/sources/<ip>/timeline")
    @login_required
    def source_timeline(ip):
        """Return attack + packet activity for a single source IP, bucketed by time."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"ok": False, "error": "invalid IP"}), 400
        since_str = request.args.get("since")
        if since_str:
            try:
                since = datetime.fromisoformat(since_str.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                return jsonify({"ok": False, "error": "invalid since datetime"}), 400
        else:
            since = datetime.now(timezone.utc) - timedelta(hours=24)

        # Aggregate attacks per time bucket (5-minute intervals)
        bucket_seconds = 300
        with db.session_scope() as sess:
            attacks = (
                sess.query(db.Attack)
                .filter(db.Attack.source_ip == ip)
                .filter(db.Attack.started_at >= since)
                .order_by(db.Attack.started_at)
                .all()
            )
            attack_timeline = []
            for a in attacks:
                bucket = a.started_at.replace(second=0, microsecond=0)
                bucket = bucket.replace(minute=(bucket.minute // 5) * 5)
                attack_timeline.append({
                    "time": bucket.isoformat() + "Z",
                    "attack_id": a.id,
                    "scan_type": a.scan_type,
                    "risk_score": a.risk_score,
                    "risk_level": a.risk_level,
                })

            packets = (
                sess.query(db.PacketEvent)
                .filter(db.PacketEvent.source_ip == ip)
                .filter(db.PacketEvent.timestamp >= since)
                .order_by(db.PacketEvent.timestamp)
                .all()
            )
            packet_timeline = []
            for p in packets:
                bucket = p.timestamp.replace(second=0, microsecond=0)
                bucket = bucket.replace(minute=(bucket.minute // 5) * 5)
                packet_timeline.append({
                    "time": bucket.isoformat() + "Z",
                    "protocol": p.protocol,
                    "destination_port": p.destination_port,
                    "flags": p.flags,
                })

        return jsonify({
            "ok": True,
            "ip": ip,
            "attacks": attack_timeline,
            "packets": packet_timeline,
            "attack_count": len(attack_timeline),
            "packet_count": len(packet_timeline),
        })

    # ---- Network Topology ------------------------------------------------

    @app.route("/api/topology")
    @login_required
    def network_topology():
        """Derive a source -> target topology from attacks and packets."""
        since_str = request.args.get("since")
        if since_str:
            try:
                since = datetime.fromisoformat(since_str.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                return jsonify({"ok": False, "error": "invalid since datetime"}), 400
        else:
            since = datetime.now(timezone.utc) - timedelta(hours=24)

        nodes = {}   # ip -> {id, label, type, size, risk}
        edges = {}   # (src, dst) -> {weight, scan_types}

        with db.session_scope() as sess:
            attacks = (
                sess.query(db.Attack)
                .filter(db.Attack.started_at >= since)
                .all()
            )
            for a in attacks:
                src = a.source_ip
                # Target IP is the first target in target_hosts_json or source_ip fallback
                tgt = src
                try:
                    hosts = json.loads(a.target_hosts_json) if a.target_hosts_json else []
                    if hosts:
                        tgt = hosts[0]
                except (json.JSONDecodeError, TypeError):
                    pass

                # Source node
                if src not in nodes:
                    nodes[src] = {
                        "id": src, "label": src, "type": "source",
                        "size": 0, "risk": 0.0,
                        "hostname": a.source_hostname or "",
                        "country": a.source_country or "",
                        "tool": a.source_tool_guess or "",
                    }
                nodes[src]["size"] += a.packet_count or 1
                nodes[src]["risk"] = max(nodes[src]["risk"], a.risk_score or 0)

                # Target node
                if tgt not in nodes:
                    nodes[tgt] = {
                        "id": tgt, "label": tgt, "type": "target",
                        "size": 0, "risk": 0.0,
                        "hostname": "", "country": "", "tool": "",
                    }

                # Edge
                key = (src, tgt)
                if key not in edges:
                    edges[key] = {"weight": 0, "scan_types": set()}
                edges[key]["weight"] += 1
                edges[key]["scan_types"].add(a.scan_type or "unknown")

            # Also pull direct packet-level edges for finer granularity
            packets = (
                sess.query(db.PacketEvent)
                .filter(db.PacketEvent.timestamp >= since)
                .all()
            )
            for p in packets:
                src = p.source_ip
                dst = p.destination_ip
                if src == dst:
                    continue
                if src not in nodes:
                    nodes[src] = {
                        "id": src, "label": src, "type": "source",
                        "size": 0, "risk": 0.0,
                        "hostname": "", "country": "", "tool": "",
                    }
                nodes[src]["size"] += 1
                if dst not in nodes:
                    nodes[dst] = {
                        "id": dst, "label": dst, "type": "target",
                        "size": 0, "risk": 0.0,
                        "hostname": "", "country": "", "tool": "",
                    }
                key = (src, dst)
                if key not in edges:
                    edges[key] = {"weight": 0, "scan_types": set()}
                edges[key]["weight"] += 1

        edge_list = [
            {
                "source": s, "target": t,
                "weight": e["weight"],
                "scan_types": sorted(e["scan_types"]),
            }
            for (s, t), e in edges.items()
        ]

        return jsonify({
            "ok": True,
            "nodes": list(nodes.values()),
            "edges": edge_list,
        })

    # ---- Dashboard SPA (serves index.html for non-API, non-static) -------

    @app.route("/")
    @app.route("/login")
    def login_page():
        return send_file(str(settings.frontend_dir / "login.html"))

    @app.route("/dashboard")
    @login_required
    def dashboard_page():
        return send_file(str(settings.frontend_dir / "index.html"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the SentinelScan server."""
    s = get_settings()
    app = create_app(s)

    # Print a one-shot alert-channel readiness summary so operators see
    # in the log exactly which channels will fire (and what is missing).
    # The same data is exposed at GET /api/status → alert_channels for the
    # dashboard's "Alert Channels" panel.
    log.info("Alert channels:")
    for ch in alert_manager.channel_status(s):
        marker = "READY" if ch["ready"] else "OFF   "
        detail = ch["reason"] or ("ok" if ch["ready"] else "disabled")
        log.info("  [%s] %-28s  %s", marker, ch["name"], detail)

    log.info("Starting SentinelScan on %s:%s", s.host, s.port)
    app.run(host=s.host, port=s.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
