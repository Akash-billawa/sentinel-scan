"""Lightweight scheduled report runner.

Runs in a daemon thread, checks the ``ReportSchedule`` table every 60 s,
and triggers PDF generation + email delivery when a schedule's
``next_run_at`` has passed.

No external scheduler (APScheduler, Celery, etc.) is required; all state
lives in the database so the scheduler is stateless across restarts.
"""

from __future__ import annotations

import logging
import smtplib
import threading
from datetime import datetime, timedelta, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from . import database as db
from .config import get_settings


logger = logging.getLogger("sentinelscan.scheduler")


# ---------------------------------------------------------------------------
#  Job execution
# ---------------------------------------------------------------------------

def _send_report_email(
    recipients: str, report_path: Path, attachment_name: str
) -> bool:
    """Send the generated PDF report via SMTP to the comma-separated recipient list."""
    settings = get_settings()
    if not settings.email_enabled:
        logger.warning("Email is disabled; scheduled report will be saved but not sent.")
        return False

    to_addrs = [r.strip() for r in recipients.split(",") if r.strip()]
    if not to_addrs:
        logger.warning("No recipients configured for scheduled report.")
        return False

    msg = MIMEMultipart()
    msg["Subject"] = f"SentinelScan Scheduled Report — {datetime.now().strftime('%Y-%m-%d')}"
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(to_addrs)
    msg.attach(
        MIMEText(
            "Please find attached the latest SentinelScan detection report.",
            "plain",
        )
    )

    with open(report_path, "rb") as f:
        pdf_part = MIMEApplication(f.read(), _subType="pdf")
    pdf_part.add_header(
        "Content-Disposition", f"attachment; filename={attachment_name}"
    )
    msg.attach(pdf_part)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.sendmail(settings.smtp_from, to_addrs, msg.as_string())
        logger.info("Scheduled report emailed to %s", ", ".join(to_addrs))
        return True
    except Exception as exc:  # pragma: no cover
        logger.error("Failed to email scheduled report: %s", exc)
        return False


def _generate_and_email(schedule: db.ReportSchedule) -> bool:
    """Generate a PDF report for the window since the last successful run
    (or 24 h ago) and email it to the configured recipients."""
    from .reports import generate_pdf  # lazy to avoid circular import

    since = schedule.last_run_at or (datetime.now(timezone.utc) - timedelta(days=1))
    try:
        path, count = generate_pdf(since=since)
        if count == 0:
            logger.info("No attacks since last run; skipping scheduled report.")
            return True

        ok = _send_report_email(schedule.recipients, path, path.name)
        return ok
    except Exception as exc:  # pragma: no cover
        logger.error("Scheduled report generation failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
#  Scheduler loop
# ---------------------------------------------------------------------------

_POLL_INTERVAL: int = 60  # seconds
_stop_event = threading.Event()
_worker: Optional[threading.Thread] = None


def _scheduler_loop() -> None:
    while not _stop_event.is_set():
        _tick()
        _stop_event.wait(_POLL_INTERVAL)


def _tick() -> None:
    now = datetime.now(timezone.utc)
    with db.session_scope() as s:
        schedules = (
            s.query(db.ReportSchedule)
            .filter(db.ReportSchedule.is_active == True)
            .all()
        )
        for sched in schedules:
            if sched.next_run_at is None or sched.next_run_at <= now:
                # Trigger report
                success = _generate_and_email(sched)
                # Update schedule
                sched.last_run_at = now
                delta = timedelta(days=7 if sched.frequency == "weekly" else 1)
                sched.next_run_at = now + delta
                logger.info(
                    "Ran scheduled report '%s' (next run: %s)",
                    sched.name,
                    sched.next_run_at.isoformat(),
                )


# ---------------------------------------------------------------------------
#  Public API
# ---------------------------------------------------------------------------

def start_scheduler() -> None:
    """Start the background scheduler thread if not already running."""
    global _worker
    if _worker is not None and _worker.is_alive():
        return
    _stop_event.clear()
    _worker = threading.Thread(target=_scheduler_loop, name="report-scheduler", daemon=True)
    _worker.start()
    logger.info("Report scheduler thread started (poll interval=%ds)", _POLL_INTERVAL)


def stop_scheduler() -> None:
    """Signal the scheduler thread to stop and wait for it."""
    _stop_event.set()
    if _worker is not None:
        _worker.join(timeout=5)
        logger.info("Report scheduler stopped.")
