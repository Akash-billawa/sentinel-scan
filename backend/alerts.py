"""Alert manager.

Subscribes to the detection engine and dispatches alerts through one or
more channels: desktop notifications, email (SMTP), and Telegram.  Each
dispatch is logged to the database regardless of outcome so the dashboard
can show a full audit trail.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import threading
import time
from datetime import datetime
from email.message import EmailMessage
from typing import Dict, List, Optional

from . import database as db
from .config import Settings, get_settings
from .crypto import generate_ack_token
from .mitre import format_line as _mitre_line

log = logging.getLogger("sentinelscan.alerts")

# Only fire alerts at this level or above (low < medium < high < critical).
_LEVEL_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def _rate_line(attack: db.Attack) -> str:
    duration = max(attack.duration_seconds or 1.0, 1.0)
    return f"{attack.packet_count / duration:.1f} packets/sec"


def _scan_speed(rate: float) -> str:
    if rate >= 1000:
        return "Very High"
    if rate >= 100:
        return "High"
    if rate >= 15:
        return "Moderate"
    return "Low"


def _target_list(attack: db.Attack) -> str:
    hosts = json.loads(attack.target_hosts_json or "[]")
    if not hosts:
        return "  No targets detected"
    lines = "\n".join(f"  • {h}" for h in hosts[:10])
    if len(hosts) > 10:
        lines += f"\n  … and {len(hosts) - 10} more"
    return lines


def _reason_lines(attack: db.Attack) -> str:
    signals = json.loads(attack.technique_signals_json or "[]")
    reasons = [s for s in signals if s.startswith("signal: ")]
    if not reasons:
        return "  • Reconnaissance pattern detected"
    return "\n".join(f"  ✓ {s.replace('signal: ', '')}" for s in reasons[:6])


def _raw_evidence(packets: List[db.PacketEvent]) -> str:
    if not packets:
        return "  No raw packet data captured"
    p = packets[0]
    return (
        f"  Protocol : {p.protocol or 'Not found'}\n"
        f"  TCP Flags: {p.flags or 'Not found'}"
    )


def _tool_evidence(attack: db.Attack) -> str:
    pos = json.loads(attack.source_tool_reasons_json or "[]")
    neg = json.loads(attack.source_tool_negative_reasons_json or "[]")
    lines = []
    for p in pos:
        lines.append(f"  [+] {p}")
    for n in neg:
        lines.append(f"  [-] {n}")
    if not lines:
        return "  No tool evidence available"
    return "\n".join(lines)



def _timeline(attack: db.Attack, packets: List[db.PacketEvent]) -> str:
    fmt = "%H:%M:%S"
    lines = [f"{attack.started_at.strftime(fmt)}  First packet detected"]
    if packets:
        mid = packets[len(packets) // 2]
        lines.append(f"{mid.timestamp.strftime(fmt)}  Active scanning observed")
    lines.append(f"{attack.ended_at.strftime(fmt)}  Alert generated")
    return "\n".join(lines)


def _recommendations(risk_level: str) -> str:
    base = [
        "[!] Verify device owner",
        "[!] Check recent login activity",
        "[!] Monitor further scanning",
    ]
    if risk_level in ("high", "critical"):
        base.append("[!] Consider blocking the source IP")
    else:
        base.append("[!] Block IP if activity continues")
    return "\n".join(f"  {r}" for r in base)


def format_alert(attack: db.Attack) -> Dict[str, str]:
    """Return the formatted alert in both plain and HTML."""

    port_list = json.loads(attack.target_ports_json or "[]")
    ports = ", ".join(str(p) for p in port_list[:10])
    if len(port_list) > 10:
        ports += ", …"

    # Coalesce absent fields to "Unknown" so a missing value (e.g. after a
    # failed decryption or an unprofiled source) reads cleanly to the
    # operator instead of printing the literal string "None".
    tool_guess = attack.source_tool_guess or "Unknown"
    os_guess = attack.source_os_guess or "Unknown"
    os_conf = int(getattr(attack, "source_os_confidence", 0) or 0)
    os_line = f"{os_guess} ({os_conf}%)" if os_conf else os_guess
    country = attack.source_country or "Unknown"
    isp = attack.source_isp or "Unknown"
    asn = attack.source_asn or "Unknown"
    hostname = attack.source_hostname or "Unknown"

    duration = attack.duration_seconds or 1.0
    rate = attack.packet_count / max(duration, 1.0)
    packets = db.list_packets_for_attack(attack.id, limit=5)

    if attack.explanation_name:
        explanation_block = (
            f"  Name      : {attack.explanation_name}\n"
            f"  Category  : {attack.explanation_category or 'Not found'}\n"
            f"  Confidence: {int(getattr(attack, 'explanation_confidence', 0) or 0)}%"
        )
    else:
        explanation_block = "  Not available"

    subject = f"[SentinelScan] {attack.risk_level.upper()} — {attack.scan_type} from {attack.source_ip}"
    body = (
        f"🚨 Reconnaissance Activity Detected\n\n"
        f"Severity: {attack.risk_level.upper()} ({attack.risk_score:.1f}/10)\n\n"
        f"Source:\n"
        f"  IP       : {attack.source_ip}\n"
        f"  MAC      : {attack.source_mac or 'Not found'}\n"
        f"  Vendor   : {attack.source_vendor or 'Not found'}\n"
        f"  Hostname : {hostname}\n"
        f"  Country  : {country}\n"
        f"  ISP      : {isp}\n"
        f"  ASN      : {asn}\n\n"
        f"Detection:\n"
        f"  Type     : {attack.scan_type}\n"
        f"  MITRE    : {_mitre_line(attack.scan_type)}\n"
        f"  Tool     : {tool_guess} ({attack.source_tool_confidence:.0f}%)\n"
        f"  OS Guess : {os_line}\n\n"
        f"Tool Evidence:\n"
        f"{_tool_evidence(attack)}\n\n"
        f"Evidence:\n"
        f"  Packets  : {attack.packet_count}\n"
        f"  Duration : {duration:.1f} sec\n"
        f"  Rate     : {_rate_line(attack)}\n"
        f"  Speed    : {_scan_speed(rate)}\n"
        f"  Targets  : {attack.unique_targets}\n"
        f"{_target_list(attack)}\n"
        f"  Ports    : {ports or 'Not found'}\n\n"
        f"Reason:\n"
        f"{_reason_lines(attack)}\n\n"
        f"Timeline:\n"
        f"{_timeline(attack, packets)}\n\n"
        f"Raw Evidence:\n"
        f"{_raw_evidence(packets)}\n\n"
        f"Likely Reason / Explanation:\n"
        f"{explanation_block}\n\n"
        f"Action:\n"
        f"{_recommendations(attack.risk_level)}\n"
    )
    return {"subject": subject, "body": body}


# ---------------------------------------------------------------------------
# Channel implementations
# ---------------------------------------------------------------------------


def _send_desktop(settings: Settings, attack: db.Attack, formatted: Dict[str, str]) -> Optional[str]:
    """Best-effort desktop notification.  Never raises."""

    if not settings.desktop_alerts:
        return "desktop alerts disabled"

    title = f"SentinelScan — {attack.risk_level.upper()}"
    message = f"{attack.scan_type} from {attack.source_ip}  •  risk {attack.risk_score}/10"

    import platform
    if platform.system() == "Windows":
        import subprocess
        try:
            # Escape single quotes for PowerShell
            title_escaped = title.replace("'", "''")
            message_escaped = message.replace("'", "''")
            
            ps_script = f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$AppId = '{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\WindowsPowerShell\\v1.0\\powershell.exe'
$ToastXml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$ToastXml.SelectSingleNode("//text[@id='1']").InnerText = '{title_escaped}'
$ToastXml.SelectSingleNode("//text[@id='2']").InnerText = '{message_escaped}'
$Toast = [Windows.UI.Notifications.ToastNotification]::new($ToastXml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($Toast)
"""
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=5
            )
            if res.returncode == 0:
                return None
            log.warning("Windows PowerShell notification failed: %s", res.stderr)
        except Exception as e:
            log.warning("Failed to dispatch Windows PowerShell notification: %s", e)

    try:
        from plyer import notification
    except Exception:
        return "plyer not installed"
    try:
        notification.notify(
            title=title,
            message=message,
            timeout=6,
        )
        return None
    except Exception as exc:
        return str(exc)


def _send_email(settings: Settings, attack: db.Attack, formatted: Dict[str, str]) -> Optional[str]:
    if not settings.email_enabled:
        return "email disabled"
    if not (settings.smtp_user and settings.smtp_password and settings.smtp_to):
        return "email not configured"

    msg = EmailMessage()
    msg["Subject"] = formatted["subject"]
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = ", ".join(settings.smtp_to)
    msg.set_content(formatted["body"])

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            smtp.starttls(context=ctx)
            smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
        return None
    except Exception as exc:
        return str(exc)


def _send_telegram(settings: Settings, attack: db.Attack, formatted: Dict[str, str]) -> Optional[str]:
    if not settings.telegram_enabled:
        return "telegram disabled"
    if not (settings.telegram_bot_token and settings.telegram_chat_id):
        return "telegram not configured"

    try:
        import requests
    except Exception:
        return "requests not installed"

    base_url = getattr(settings, "telegram_base_url", "https://api.telegram.org").rstrip("/")
    url = f"{base_url}/bot{settings.telegram_bot_token}/sendMessage"
    try:
        r = requests.post(
            url,
            json={
                "chat_id": settings.telegram_chat_id,
                "text": f"*{formatted['subject']}*\n\n```\n{formatted['body']}\n```",
                "parse_mode": "Markdown",
            },
            timeout=8,
        )
        if r.status_code >= 300:
            return f"telegram http {r.status_code}: {r.text[:200]}"
        return None
    except Exception as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# IPS Alert Formatting
# ---------------------------------------------------------------------------

def format_ips_alert(action_type: str, source_ip: str, threat_type: str, risk_score: float, action_id: str = "", decision: str = "") -> Dict[str, str]:
    """Format an IPS alert for email channel."""
    # Match the thresholds used in backend/risk.py
    risk_level = "CRITICAL" if risk_score >= 8.0 else "HIGH" if risk_score >= 6.0 else "MEDIUM" if risk_score >= 3.5 else "LOW"

    if action_type == "pending":
        subject = f"[SentinelScan IPS] Approval Required — {threat_type} from {source_ip}"
        body = (
            f"IPS APPROVAL REQUIRED\n\n"
            f"Action ID      : {action_id}\n"
            f"Source IP      : {source_ip}\n"
            f"Threat Type    : {threat_type}\n"
            f"Risk Score     : {risk_score}/10 — {risk_level}\n\n"
            f"Action required: Approve or deny this action via the dashboard or Telegram.\n"
        )
    elif action_type == "approved":
        subject = f"[SentinelScan IPS] Approved — {threat_type} from {source_ip}"
        body = (
            f"IPS ACTION APPROVED\n\n"
            f"Source IP      : {source_ip}\n"
            f"Threat Type    : {threat_type}\n"
            f"Decision       : {decision}\n"
        )
    elif action_type == "denied":
        subject = f"[SentinelScan IPS] Blocked — {threat_type} from {source_ip}"
        body = (
            f"IPS ACTION DENIED\n\n"
            f"Source IP      : {source_ip}\n"
            f"Threat Type    : {threat_type}\n"
            f"Risk Score     : {risk_score}/10 — {risk_level}\n"
            f"Firewall rule  : Applied\n"
        )
    elif action_type == "auto_blocked":
        subject = f"[SentinelScan IPS] Auto-Blocked — {threat_type} from {source_ip}"
        body = (
            f"IPS AUTO-BLOCKED\n\n"
            f"Source IP      : {source_ip}\n"
            f"Threat Type    : {threat_type}\n"
            f"Risk Score     : {risk_score}/10 — {risk_level}\n"
            f"Firewall rule  : Auto-applied (critical threat)\n"
        )
    else:
        return {"subject": "", "body": ""}

    return {"subject": subject, "body": body}


def send_ips_alert_email(settings: Settings, action_type: str, source_ip: str, threat_type: str, risk_score: float, action_id: str = "", decision: str = "") -> Optional[str]:
    """Send an IPS alert via email."""
    if not settings.email_enabled:
        return "email disabled"
    if not (settings.smtp_user and settings.smtp_password and settings.smtp_to):
        return "email not configured"

    formatted = format_ips_alert(action_type, source_ip, threat_type, risk_score, action_id, decision)

    msg = EmailMessage()
    msg["Subject"] = formatted["subject"]
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = ", ".join(settings.smtp_to)
    msg.set_content(formatted["body"])

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            smtp.starttls(context=ctx)
            smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
        return None
    except Exception as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# Channel readiness diagnostics
# ---------------------------------------------------------------------------


def channel_status(settings: Settings) -> List[Dict]:
    """Return per-channel readiness for the dashboard / startup logs.

    Each entry has ``name`` (display), ``key`` (channel id), ``enabled`` (the
    matching ``*_ENABLED`` flag), ``configured`` (the credentials/URL are
    present), ``ready`` (will actually fire when an attack arrives), and
    ``reason`` (human-readable explanation if not ready).  This is what
    surfaces in the "Alert Channels" panel of the dashboard so operators
    immediately see *why* a channel isn't delivering (rather than guessing
    from a silent failure in the alerts table).
    """

    desktop_ready = settings.desktop_alerts
    desktop_reason = None if desktop_ready else "Set SENTINEL_DESKTOP_ALERTS=true"

    email_ok = settings.email_enabled and bool(
        settings.smtp_host and settings.smtp_user and settings.smtp_password and settings.smtp_to
    )
    if not settings.email_enabled:
        email_reason = "Set SENTINEL_EMAIL_ENABLED=true"
    elif not (settings.smtp_host and settings.smtp_user and settings.smtp_password):
        email_reason = "Missing SENTINEL_SMTP_HOST/USER/PASSWORD"
    elif not settings.smtp_to:
        email_reason = "Missing SENTINEL_SMTP_TO (recipient list)"
    else:
        email_reason = None

    tg_enabled = settings.telegram_enabled
    tg_has_creds = bool(settings.telegram_bot_token and settings.telegram_chat_id)
    if not tg_enabled:
        tg_reason = "Set SENTINEL_TELEGRAM_ENABLED=true"
    elif not tg_has_creds:
        tg_reason = "Missing SENTINEL_TELEGRAM_BOT_TOKEN and/or SENTINEL_TELEGRAM_CHAT_ID"
    else:
        tg_reason = None

    master = settings.alerts_enabled
    master_reason = None if master else "Set SENTINEL_ALERTS_ENABLED=true (master switch is OFF)"

    return [
        {"key": "master", "name": "Alerts (master switch)", "enabled": master,
         "configured": master, "ready": master, "reason": master_reason},
        {"key": "in_app", "name": "In-app feed", "enabled": True,
         "configured": True, "ready": True, "reason": None},
        {"key": "desktop", "name": "Desktop notification", "enabled": settings.desktop_alerts,
         "configured": settings.desktop_alerts, "ready": desktop_ready, "reason": desktop_reason},
        {"key": "email", "name": "Email (SMTP)", "enabled": settings.email_enabled,
         "configured": bool(settings.smtp_host and settings.smtp_user and settings.smtp_password and settings.smtp_to),
         "ready": email_ok, "reason": email_reason},
        {"key": "telegram", "name": "Telegram", "enabled": tg_enabled,
         "configured": tg_has_creds, "ready": master and tg_enabled and tg_has_creds,
         "reason": tg_reason or master_reason},
    ]


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class AlertManager:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self._last_sent: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._min_level: str = self.settings.alert_min_level

    def set_min_level(self, level: str) -> None:
        if level in _LEVEL_RANK:
            self._min_level = level

    def on_attack(self, attack: db.Attack, _signals: Dict) -> None:
        """Callback registered with the detection engine."""

        if not self.settings.alerts_enabled:
            return
        if _LEVEL_RANK.get(attack.risk_level, 0) < _LEVEL_RANK.get(self._min_level, 0):
            return
        # Per-source cooldown.
        cooldown_key = f"{attack.source_ip}:{attack.scan_type}"
        with self._lock:
            last = self._last_sent.get(cooldown_key, 0.0)
            if time.time() - last < self.settings.alert_cooldown:
                return
            self._last_sent[cooldown_key] = time.time()

        formatted = format_alert(attack)

        # Run each channel in its own thread to keep the engine snappy.
        for ch, fn, args in (
            ("desktop", _send_desktop, (self.settings, attack, formatted)),
            ("email", _send_email, (self.settings, attack, formatted)),
            ("telegram", _send_telegram, (self.settings, attack, formatted)),
        ):
            t = threading.Thread(
                target=self._dispatch,
                args=(attack.id, ch, fn, args),
                daemon=True,
                name=f"alert-{ch}",
            )
            t.start()

    def _dispatch(self, attack_id: int, channel: str, fn, args) -> None:
        try:
            err = fn(*args)
        except Exception as exc:
            log.warning("alert channel %s crashed for attack_id=%s: %s", channel, attack_id, exc)
            err = str(exc)
        success = err is None
        # Always log the outcome to the alerts table so the dashboard's
        # audit feed is complete.  A DB hiccup here must not silently kill
        # the alert thread — log loudly and move on.
        try:
            with db.session_scope() as s:
                db.insert_alert(
                    s,
                    db.Alert(
                        attack_id=attack_id,
                        channel=channel,
                        success=success,
                        message=err or "delivered",
                    ),
                )
        except Exception as exc:  # pragma: no cover - DB unavailable
            log.warning(
                "failed to record %s alert for attack_id=%s: %s",
                channel, attack_id, exc,
            )
        if err:
            log.warning("alert channel %s failed for attack_id=%s: %s", channel, attack_id, err)
        else:
            log.info("alert delivered via %s (attack_id=%s)", channel, attack_id)
