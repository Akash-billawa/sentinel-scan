"""Database layer for SentinelScan AI.

Uses SQLAlchemy 2.x with the bundled SQLite engine.  The schema covers the
entities needed by the dashboard, alert manager, and report generator:

* ``Attack`` — one row per detected reconnaissance event.
* ``PacketEvent`` — raw per-packet summary used for traceability.
* ``Alert`` — record of every alert dispatched (one per channel).
* ``Session`` — a logical capture / monitoring session.

The module also exposes small, focused query helpers that the API layer
uses, so HTTP handlers stay slim and the SQL stays in one place.
"""

from __future__ import annotations

import logging


import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Generator, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    desc,
    func,
    select,
)
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import DeclarativeBase, Session as ORMSession, sessionmaker

from .config import get_settings
from .crypto import EncryptedStr


def _now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    """SQLAlchemy 2.x declarative base."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Attack(Base):
    """A single detected reconnaissance attempt by one source IP."""

    __tablename__ = "attacks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, default=_now_naive, nullable=False, index=True)
    ended_at = Column(DateTime, default=_now_naive, nullable=False)
    duration_seconds = Column(Float, default=0.0)

    # Sensitive fields — encrypted on disk when SENTINEL_ENCRYPT_LOGS=true.
    # The SQL schema stays TEXT/STRING; encryption happens at the Python
    # boundary via the EncryptedStr type decorator.
    source_ip = Column(EncryptedStr(64), nullable=False, index=True)
    source_mac = Column(EncryptedStr(32), index=True)
    source_vendor = Column(String(128), nullable=True)
    source_hostname = Column(EncryptedStr(255))
    source_country = Column(EncryptedStr(64))
    source_isp = Column(EncryptedStr(128))
    source_asn = Column(EncryptedStr(64))
    source_os_guess = Column(EncryptedStr(64))
    source_os_confidence = Column(Float, default=0.0)
    source_tool_guess = Column(EncryptedStr(64))
    source_tool_confidence = Column(Float, default=0.0)
    source_tool_reasons_json = Column(EncryptedStr(2000))  # JSON list[str] ([+] evidence)
    source_tool_negative_reasons_json = Column(EncryptedStr(2000))  # JSON list[str] ([-] evidence)

    scan_type = Column(EncryptedStr(64), nullable=False, index=True)
    scan_confidence = Column(Float, default=0.0)

    packet_count = Column(Integer, default=0)
    unique_ports = Column(Integer, default=0)
    unique_targets = Column(Integer, default=0)
    target_ports_json = Column(EncryptedStr(2000))  # JSON list[int]
    target_hosts_json = Column(EncryptedStr(2000))  # JSON list[str]

    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(16), default="low", index=True)

    technique_signals_json = Column(EncryptedStr(2000))  # JSON list[str]

    # Threat-intel enrichment — JSON blob with AbuseIPDB data.
    threat_intel_json = Column(Text, nullable=True)

    # Explanation Engine — ranked Likely Reason, classification, confidence,
    # evidence bullets, and the full top-10 ranked list for debugging.
    explanation_name = Column(String(255), nullable=True)
    explanation_category = Column(String(64), nullable=True, index=True)
    explanation_confidence = Column(Float, default=0.0)
    explanation_evidence_json = Column(Text)  # JSON list[str]
    explanation_all_reasons_json = Column(Text)  # JSON list[Dict]

    # Triage state — set when an operator (via Slack button, dashboard, or API)
    # acknowledges the alert.  ``acknowledged_at`` is the first-ack time and is
    # never overwritten; ``acknowledged_by`` is updated on subsequent acks.
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(64), nullable=True)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "started_at": self.started_at.isoformat() + "Z",
            "ended_at": self.ended_at.isoformat() + "Z",
            "duration_seconds": self.duration_seconds,
            "source": {
                "ip": self.source_ip,
                "mac": self.source_mac,
                "vendor": self.source_vendor,
                "hostname": self.source_hostname,
                "country": self.source_country,
                "isp": self.source_isp,
                "asn": self.source_asn,
                "os_guess": self.source_os_guess,
                "os_confidence": self.source_os_confidence,
                "tool_guess": self.source_tool_guess,
                "tool_confidence": self.source_tool_confidence,
                "tool_reasons": json.loads(self.source_tool_reasons_json or "[]"),
                "tool_negative_reasons": json.loads(self.source_tool_negative_reasons_json or "[]"),
            },
            "scan_type": self.scan_type,
            "scan_confidence": self.scan_confidence,
            "packet_count": self.packet_count,
            "unique_ports": self.unique_ports,
            "unique_targets": self.unique_targets,
            "target_ports": json.loads(self.target_ports_json or "[]"),
            "target_hosts": json.loads(self.target_hosts_json or "[]"),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "technique_signals": json.loads(self.technique_signals_json or "[]"),
            "threat_intel": json.loads(self.threat_intel_json) if self.threat_intel_json else None,
            "explanation": {
                "name": self.explanation_name,
                "category": self.explanation_category,
                "confidence": self.explanation_confidence,
                "evidence": json.loads(self.explanation_evidence_json or "[]"),
                "all_reasons": json.loads(self.explanation_all_reasons_json or "[]"),
            },
            "acknowledged_at": self.acknowledged_at.isoformat() + "Z" if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
        }


class Alert(Base):
    """Record of an alert dispatched through one or more channels."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=_now_naive, nullable=False, index=True)
    attack_id = Column(Integer, index=True)
    channel = Column(String(32), nullable=False)  # telegram | email | desktop
    success = Column(Boolean, default=True)
    message = Column(Text)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() + "Z",
            "attack_id": self.attack_id,
            "channel": self.channel,
            "success": self.success,
            "message": self.message,
        }


class PacketEvent(Base):
    """Compact summary of a single observed packet — useful for forensics."""

    __tablename__ = "packet_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=_now_naive, nullable=False, index=True)
    source_ip = Column(String(64), index=True)
    destination_ip = Column(String(64), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(16))
    flags = Column(String(32))
    length = Column(Integer)
    summary = Column(String(255))

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() + "Z",
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "flags": self.flags,
            "length": self.length,
            "summary": self.summary,
        }


class Session(Base):
    """A monitoring session (live capture run, or simulation)."""

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128))
    mode = Column(String(16))  # live | sim
    started_at = Column(DateTime, default=_now_naive, nullable=False)
    ended_at = Column(DateTime)
    packet_count = Column(Integer, default=0)
    attack_count = Column(Integer, default=0)
    notes = Column(Text)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "mode": self.mode,
            "started_at": self.started_at.isoformat() + "Z",
            "ended_at": self.ended_at.isoformat() + "Z" if self.ended_at else None,
            "packet_count": self.packet_count,
            "attack_count": self.attack_count,
            "notes": self.notes,
        }


class User(Base):
    """Dashboard / API user.  Passwords are stored as Werkzeug PBKDF2 hashes."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=_now_naive, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    session_version = Column(Integer, default=0, nullable=False)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "username": self.username,
            "created_at": self.created_at.isoformat() + "Z",
            "last_login_at": self.last_login_at.isoformat() + "Z" if self.last_login_at else None,
            "is_active": self.is_active,
        }


class BlockedIP(Base):
    """IP address blocked by the IPS firewall manager."""

    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), nullable=False, index=True)
    direction = Column(String(16), default="inbound")  # inbound | outbound | both
    action = Column(String(16), default="block")  # block | allow
    rule_name = Column(String(128), nullable=False)
    reason = Column(Text)
    created_at = Column(DateTime, default=_now_naive, nullable=False)
    removed_at = Column(DateTime, nullable=True)

    # Enforcement verification (Phase 4 firewall-verification work).
    # status: pending | applied | verified | failed
    # backend: which FirewallBackend.last applied this rule.
    # verified_at: timestamp of the most recent successful OS verification.
    # failure_reason: human-readable explanation when status == 'failed'.
    status = Column(String(16), default="pending", nullable=False, index=True)
    backend = Column(String(32), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    failure_reason = Column(Text, nullable=True)

    # apply_block diagnostic capture (Phase 5 apply-diagnostic work).
    # Every fields populated on a block attempt so a FAILED row tells the
    # operator exactly which command ran, what it returned, and what blew up.
    apply_exit_code = Column(Integer, nullable=True)
    apply_stdout = Column(Text, nullable=True)
    apply_stderr = Column(Text, nullable=True)
    apply_exception = Column(Text, nullable=True)
    apply_command = Column(Text, nullable=True)

    # Dual-path diagnostics (Phase 6 — Windows direct + schtasks fallback).
    # ``apply_*`` above reflects the LAST attempt that ran (= final status
    # source). ``direct_apply_*`` captures the direct New-NetFirewallRule
    # call; ``fallback_apply_*`` captures the schtasks SYSTEM call (empty
    # when fallback didn't run). ``last_attempt_path`` is "direct" or
    # "fallback" so the operator can tell which path produced apply_*.
    direct_apply_command = Column(Text, nullable=True)
    direct_apply_exit_code = Column(Integer, nullable=True)
    direct_apply_stdout = Column(Text, nullable=True)
    direct_apply_stderr = Column(Text, nullable=True)
    direct_apply_exception = Column(Text, nullable=True)
    fallback_apply_command = Column(Text, nullable=True)
    fallback_apply_exit_code = Column(Integer, nullable=True)
    fallback_apply_stdout = Column(Text, nullable=True)
    fallback_apply_stderr = Column(Text, nullable=True)
    fallback_apply_exception = Column(Text, nullable=True)
    last_attempt_path = Column(String(16), nullable=True)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "ip": self.ip,
            "direction": self.direction,
            "action": self.action,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() + "Z",
            "removed_at": self.removed_at.isoformat() + "Z" if self.removed_at else None,
            "status": self.status,
            "backend": self.backend,
            "verified_at": self.verified_at.isoformat() + "Z" if self.verified_at else None,
            "failure_reason": self.failure_reason,
            # apply_* = last attempt (= source of final status).
            "apply_exit_code": self.apply_exit_code,
            "apply_stdout": self.apply_stdout,
            "apply_stderr": self.apply_stderr,
            "apply_exception": self.apply_exception,
            "apply_command": self.apply_command,
            # Dual-path: preserved across both execution paths.
            "direct_apply_command": self.direct_apply_command,
            "direct_apply_exit_code": self.direct_apply_exit_code,
            "direct_apply_stdout": self.direct_apply_stdout,
            "direct_apply_stderr": self.direct_apply_stderr,
            "direct_apply_exception": self.direct_apply_exception,
            "fallback_apply_command": self.fallback_apply_command,
            "fallback_apply_exit_code": self.fallback_apply_exit_code,
            "fallback_apply_stdout": self.fallback_apply_stdout,
            "fallback_apply_stderr": self.fallback_apply_stderr,
            "fallback_apply_exception": self.fallback_apply_exception,
            "last_attempt_path": self.last_attempt_path,
        }


class ReportSchedule(Base):
    """Scheduled report configuration — drives automated daily / weekly
    PDF generation and delivery via email."""

    __tablename__ = "report_schedules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False)
    frequency = Column(String(16), default="daily")  # daily | weekly
    recipients = Column(Text, default="")  # comma-separated email list
    is_active = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_now_naive, nullable=False)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "frequency": self.frequency,
            "recipients": self.recipients,
            "is_active": self.is_active,
            "last_run_at": self.last_run_at.isoformat() + "Z" if self.last_run_at else None,
            "next_run_at": self.next_run_at.isoformat() + "Z" if self.next_run_at else None,
            "created_at": self.created_at.isoformat() + "Z",
        }


# ---------------------------------------------------------------------------
# Engine & session helpers
# ---------------------------------------------------------------------------


_engine = None
_SessionLocal: Optional[sessionmaker] = None


def _ensure_sqlite_dir(url: str) -> None:
    """Make sure the SQLite parent directory exists for a ``sqlite:///`` URL."""

    if url.startswith("sqlite:///"):
        path = Path(url.replace("sqlite:///", "", 1))
        path.parent.mkdir(parents=True, exist_ok=True)


def init_db() -> None:
    """Create the engine, ensure tables exist, and seed a default session."""

    global _engine, _SessionLocal

    settings = get_settings()
    _ensure_sqlite_dir(settings.db_url)

    _engine = create_engine(
        settings.db_url,
        echo=False,
        future=True,
        connect_args={"check_same_thread": False} if settings.db_url.startswith("sqlite") else {},
    )
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    Base.metadata.create_all(_engine)

    # Idempotent schema migration: add columns that were introduced after the
    # initial release.  ``Base.metadata.create_all`` is a no-op for existing
    # tables, so we use ``PRAGMA table_info`` to detect missing columns and
    # ``ALTER TABLE`` to add them.  Safe to run on every startup.
    _migrate_attacks_table(_engine)
    _migrate_blocked_ips_table(_engine)
    _ensure_report_schedules(_engine)

    # Seed a default session if none exists.
    with session_scope() as s:
        existing = s.scalar(select(func.count(Session.id)))
        if not existing:
            s.add(Session(name="default", mode="sim", notes="Auto-created on first launch"))

    # Idempotent encryption migration: if SENTINEL_ENCRYPT_LOGS=true and
    # the on-disk rows are still plaintext, encrypt them in place.  Safe
    # to call on every startup — already-encrypted rows are skipped.
    if settings.encrypt_logs:
        try:
            from .crypto import migrate_plaintext_to_encrypted
            migrate_plaintext_to_encrypted(limit=5000)
        except Exception as exc:  # pragma: no cover - never block boot
            logging.getLogger("sentinelscan.database").warning(
                "encryption migration skipped: %s", exc
            )


def _migrate_attacks_table(engine) -> None:
    """Add columns to ``attacks`` that were introduced after the initial release.

    Currently adds:
      * ``acknowledged_at``    (DATETIME, nullable)
      * ``acknowledged_by``    (VARCHAR(64), nullable)
      * ``source_os_confidence`` (FLOAT, default 0.0)
      * ``threat_intel_json``  (TEXT)
      * ``source_tool_reasons_json`` (TEXT)
      * ``source_tool_negative_reasons_json`` (TEXT)
      * ``session_version``    (INTEGER, default 0) — on ``users`` table
    """

    from sqlalchemy import text

    if not engine.dialect.name.startswith("sqlite"):
        # Skip the SQLite-specific migration for other backends; the production
        # path is to manage schema with Alembic instead.
        return

    with engine.begin() as conn:
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(attacks)")).fetchall()}
        if "acknowledged_at" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN acknowledged_at DATETIME"))
        if "acknowledged_by" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN acknowledged_by VARCHAR(64)"))
        if "source_os_confidence" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN source_os_confidence FLOAT"))
        if "threat_intel_json" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN threat_intel_json TEXT"))
        if "source_tool_reasons_json" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN source_tool_reasons_json TEXT"))
        if "source_tool_negative_reasons_json" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN source_tool_negative_reasons_json TEXT"))
        if "source_vendor" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN source_vendor VARCHAR(128)"))
        if "explanation_name" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN explanation_name VARCHAR(255)"))
        if "explanation_category" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN explanation_category VARCHAR(64)"))
        if "explanation_confidence" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN explanation_confidence FLOAT"))
        if "explanation_evidence_json" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN explanation_evidence_json TEXT"))
        if "explanation_all_reasons_json" not in cols:
            conn.execute(text("ALTER TABLE attacks ADD COLUMN explanation_all_reasons_json TEXT"))

        # Users table migration
        user_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(users)")).fetchall()}
        if "session_version" not in user_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN session_version INTEGER DEFAULT 0"))


def _migrate_blocked_ips_table(engine) -> None:
    """Add verification columns to ``blocked_ips`` for the firewall
    enforcement work. Idempotent — safe to run on every startup.
    """
    from sqlalchemy import text

    if not engine.dialect.name.startswith("sqlite"):
        return

    with engine.begin() as conn:
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(blocked_ips)")).fetchall()}
        if "status" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN status VARCHAR(16) DEFAULT 'pending' NOT NULL"))
        if "backend" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN backend VARCHAR(32)"))
        if "verified_at" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN verified_at DATETIME"))
        if "failure_reason" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN failure_reason TEXT"))
        # Phase 5: apply_block diagnostic capture so a FAILED row tells the
        # operator exactly what command ran and what went wrong.
        if "apply_exit_code" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN apply_exit_code INTEGER"))
        if "apply_stdout" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN apply_stdout TEXT"))
        if "apply_stderr" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN apply_stderr TEXT"))
        if "apply_exception" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN apply_exception TEXT"))
        if "apply_command" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN apply_command TEXT"))
        # Phase 6: dual-path diagnostics — direct New-NetFirewallRule vs
        # schtasks SYSTEM fallback. Both are preserved so the operator can
        # see why the primary path failed AND what the fallback produced.
        if "direct_apply_command" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN direct_apply_command TEXT"))
        if "direct_apply_exit_code" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN direct_apply_exit_code INTEGER"))
        if "direct_apply_stdout" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN direct_apply_stdout TEXT"))
        if "direct_apply_stderr" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN direct_apply_stderr TEXT"))
        if "direct_apply_exception" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN direct_apply_exception TEXT"))
        if "fallback_apply_command" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN fallback_apply_command TEXT"))
        if "fallback_apply_exit_code" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN fallback_apply_exit_code INTEGER"))
        if "fallback_apply_stdout" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN fallback_apply_stdout TEXT"))
        if "fallback_apply_stderr" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN fallback_apply_stderr TEXT"))
        if "fallback_apply_exception" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN fallback_apply_exception TEXT"))
        if "last_attempt_path" not in cols:
            conn.execute(text("ALTER TABLE blocked_ips ADD COLUMN last_attempt_path VARCHAR(16)"))
        # Backfill: any existing un-removed rows are presumed verified
        # (they were persisted under the old "we trust the OS" contract).
        conn.execute(text(
            "UPDATE blocked_ips SET status='verified', verified_at=created_at "
            "WHERE removed_at IS NULL AND (status IS NULL OR status='pending')"
        ))


def _ensure_report_schedules(engine) -> None:
    """Create the ``report_schedules`` table if it does not already exist.

    ``Base.metadata.create_all`` handles fresh databases, but an existing
    database that was created before the ``ReportSchedule`` model existed
    will miss the table.  This idempotent helper creates it via raw SQL.
    """
    from sqlalchemy import text as sql_text

    if not engine.dialect.name.startswith("sqlite"):
        return

    with engine.begin() as conn:
        tables = {row[0] for row in conn.execute(sql_text(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )).fetchall()}
        if "report_schedules" not in tables:
            conn.execute(sql_text("""
                CREATE TABLE report_schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(128) NOT NULL,
                    frequency VARCHAR(16) DEFAULT 'daily',
                    recipients TEXT DEFAULT '',
                    is_active BOOLEAN DEFAULT 1 NOT NULL,
                    last_run_at DATETIME,
                    next_run_at DATETIME,
                    created_at DATETIME NOT NULL
                )
            """))


def get_engine():
    if _engine is None:
        init_db()
    return _engine


def close_db() -> None:
    """Dispose of the engine and close the sessionmaker."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
        _engine = None
    _SessionLocal = None


@contextmanager
def session_scope() -> Generator[ORMSession, None, None]:
    """Provide a transactional scope around a series of operations."""

    if _SessionLocal is None:
        init_db()
    s = _SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def insert_attack(s: ORMSession, attack: Attack) -> Attack:
    s.add(attack)
    s.flush()
    return attack


def insert_packet(s: ORMSession, pkt: PacketEvent) -> None:
    s.add(pkt)


def insert_alert(s: ORMSession, alert: Alert) -> None:
    s.add(alert)


def acknowledge_attack(attack_id: int, by: str) -> Optional[Attack]:
    """Mark an attack as triaged.  Idempotent — first call stamps the time;
    subsequent calls update ``by`` but preserve the original timestamp.
    Returns the refreshed attack, or ``None`` if the id is unknown.

    Uses an atomic ``UPDATE … WHERE acknowledged_at IS NULL`` to prevent
    two concurrent requests from both stamping the timestamp.
    """

    with session_scope() as s:
        # Atomic first-ack: only one concurrent request can win this UPDATE.
        now = _now_naive()
        from sqlalchemy import update
        stmt = (
            update(Attack)
            .where(Attack.id == attack_id, Attack.acknowledged_at.is_(None))
            .values(acknowledged_at=now)
        )
        result = s.execute(stmt)
        # Always set acknowledged_by (even if already acked).
        attack = s.get(Attack, attack_id)
        if not attack:
            return None
        if by:
            attack.acknowledged_by = by
        s.flush()
        s.refresh(attack)
        # Detach so the caller can read fields after the session closes.
        s.expunge(attack)
        return attack


def list_attacks(limit: int = 100, offset: int = 0) -> List[Attack]:
    with session_scope() as s:
        stmt = select(Attack).order_by(desc(Attack.started_at)).limit(limit).offset(offset)
        results = list(s.scalars(stmt))
        for r in results:
            s.expunge(r)
        return results


def get_attack(attack_id: int) -> Optional[Attack]:
    with session_scope() as s:
        obj = s.get(Attack, attack_id)
        if obj is not None:
            s.expunge(obj)
        return obj


def list_alerts(limit: int = 50) -> List[Alert]:
    with session_scope() as s:
        stmt = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
        results = list(s.scalars(stmt))
        for r in results:
            s.expunge(r)
        return results


def list_packets_for_attack(attack_id: int, limit: int = 5) -> List[PacketEvent]:
    """Return raw packet samples for an attack's source/time window.

    Used to build the 'Raw Evidence' and 'Timeline' sections of alerts.
    Ordered chronologically.
    """
    with session_scope() as s:
        attack = s.get(Attack, attack_id)
        if attack is None:
            return []
        stmt = (
            select(PacketEvent)
            .where(
                PacketEvent.source_ip == attack.source_ip,
                PacketEvent.timestamp >= attack.started_at,
                PacketEvent.timestamp <= attack.ended_at,
            )
            .order_by(PacketEvent.timestamp)
            .limit(limit)
        )
        results = list(s.scalars(stmt).all())
        for r in results:
            s.expunge(r)
        return results


# ---- Aggregations used by the dashboard -------------------------------------


def dashboard_stats() -> Dict:
    """Return a single payload of all numbers the dashboard renders."""

    with session_scope() as s:
        now = _now_naive()
        day_ago = now - timedelta(hours=24)
        hour_ago = now - timedelta(hours=1)

        total_attacks = s.scalar(select(func.count(Attack.id))) or 0
        last_24h = s.scalar(
            select(func.count(Attack.id)).where(Attack.started_at >= day_ago)
        ) or 0
        last_1h = s.scalar(
            select(func.count(Attack.id)).where(Attack.started_at >= hour_ago)
        ) or 0
        critical = s.scalar(
            select(func.count(Attack.id)).where(Attack.risk_level == "critical")
        ) or 0

        # Risk distribution
        risk_rows = s.execute(
            select(Attack.risk_level, func.count(Attack.id)).group_by(Attack.risk_level)
        ).all()
        risk_distribution = {level: 0 for level in ("low", "medium", "high", "critical")}
        for level, count in risk_rows:
            risk_distribution[level] = count

        # Scan type distribution
        scan_rows = s.execute(
            select(Attack.scan_type, func.count(Attack.id)).group_by(Attack.scan_type)
        ).all()
        scan_distribution = {st: c for st, c in scan_rows}

        # Top source IPs
        top_rows = s.execute(
            select(
                Attack.source_ip,
                func.count(Attack.id).label("hits"),
                func.max(Attack.risk_score).label("worst_risk"),
            )
            .group_by(Attack.source_ip)
            .order_by(desc("hits"))
            .limit(10)
        ).all()
        top_sources = [
            {"ip": ip, "hits": hits, "worst_risk": float(worst_risk or 0.0)}
            for ip, hits, worst_risk in top_rows
        ]

        # Tool guess distribution
        tool_rows = s.execute(
            select(Attack.source_tool_guess, func.count(Attack.id))
            .where(Attack.source_tool_guess.is_not(None))
            .group_by(Attack.source_tool_guess)
        ).all()
        tool_distribution = {t: c for t, c in tool_rows if t}

        # Country distribution
        country_rows = s.execute(
            select(Attack.source_country, func.count(Attack.id))
            .where(Attack.source_country.is_not(None))
            .group_by(Attack.source_country)
        ).all()
        country_distribution = {c: n for c, n in country_rows if c}

        # Timeline (last 24h bucketed by hour).  Single grouped query
        # instead of 24 separate COUNTs — the previous loop showed up
        # as a noticeable per-poll lag on dashboards with >10k attack
        # rows.  ``strftime`` is the canonical SQLite bucket function;
        # on other dialects the ``func`` import picks up the equivalent
        # (``date_trunc`` / ``EXTRACT``), so the SQLAlchemy expression
        # is dialect-agnostic.  Empty buckets are filled in client-side
        # so the chart stays continuous.
        timeline: List[Dict] = []
        bucket_labels: List[str] = []
        for hour in range(23, -1, -1):
            bucket_start = now - timedelta(hours=hour + 1)
            bucket_labels.append(bucket_start.strftime("%H:00"))
        counts_by_label: Dict[str, int] = {label: 0 for label in bucket_labels}
        try:
            from sqlalchemy import func as sql_func
            rows = s.execute(
                select(
                    sql_func.strftime("%H:00", Attack.started_at).label("bucket"),
                    sql_func.count(Attack.id).label("count"),
                )
                .where(Attack.started_at >= day_ago)
                .group_by("bucket")
            ).all()
            for label, count in rows:
                if label and label in counts_by_label:
                    counts_by_label[label] = int(count or 0)
        except Exception:
            # Non-SQLite backend (or odd dialect) — fall back to the
            # 24-loop so the dashboard never goes blank.
            for hour in range(23, -1, -1):
                bucket_start = now - timedelta(hours=hour + 1)
                bucket_end = now - timedelta(hours=hour)
                count = s.scalar(
                    select(func.count(Attack.id)).where(
                        Attack.started_at >= bucket_start,
                        Attack.started_at < bucket_end,
                    )
                ) or 0
                counts_by_label[bucket_labels[23 - hour]] = int(count)
        for label in bucket_labels:
            timeline.append({"hour": label, "count": counts_by_label[label]})

    return {
        "total_attacks": total_attacks,
        "attacks_last_24h": last_24h,
        "attacks_last_hour": last_1h,
        "critical_attacks": critical,
        "risk_distribution": risk_distribution,
        "scan_distribution": scan_distribution,
        "tool_distribution": tool_distribution,
        "country_distribution": country_distribution,
        "top_sources": top_sources,
        "timeline": timeline,
        "active_threats": last_1h,  # heuristic: anything in the last hour
    }


def list_sessions(limit: int = 20) -> List[Session]:
    with session_scope() as s:
        stmt = select(Session).order_by(desc(Session.started_at)).limit(limit)
        results = list(s.scalars(stmt))
        for r in results:
            s.expunge(r)
        return results


def get_or_create_session(name: str, mode: str) -> Session:
    with session_scope() as s:
        existing = s.scalar(select(Session).order_by(desc(Session.id)).limit(1))
        if existing and existing.ended_at is None:
            s.expunge(existing)
            return existing
        sess = Session(name=name, mode=mode)
        s.add(sess)
        s.flush()
        s.expunge(sess)
        return sess


def end_session(session_id: int, packet_count: int, attack_count: int) -> None:
    with session_scope() as s:
        sess = s.get(Session, session_id)
        if sess:
            sess.ended_at = _now_naive()
            sess.packet_count = packet_count
            sess.attack_count = attack_count
