"""Telegram IPS Bot — allows operators to approve/deny IPS actions via Telegram.

This module provides a Telegram bot that listens for IPS-related commands
and interacts with the ApprovalManager and FirewallManager.

Commands:
  /status  - Show IPS status
  /pending - List pending actions
  /allow <id> - Approve an action (allow IP)
  /deny <id> - Deny an action (block IP)
  /block <ip> - Manually block an IP
  /unblock <ip> - Unblock an IP
  /blocks - List blocked IPs
  /help - Show help
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Optional

from .config import get_settings
from .approval_manager import get_approval_manager, ActionStatus
from .firewall_manager import get_firewall_manager, BlockResult

log = logging.getLogger("sentinelscan.ips.telegram")

# Module-level bot instance for polling
_bot_instance: Optional["TelegramIPSBot"] = None


def _format_pending_action(action) -> str:
    """Format a pending action for Telegram display."""
    return (
        f"*Alert #{action.id}*\n"
        f"Source: `{action.source_ip}`\n"
        f"Type: {action.threat_type}\n"
        f"Risk: {action.risk_score:.1f}/10 ({action.risk_level.upper()})\n"
        f"Confidence: {action.confidence:.0f}%\n"
        f"Expires: {action.expires_at.strftime('%H:%M:%S UTC')}"
    )


def _send_telegram_message(chat_id: str, text: str, reply_markup=None) -> bool:
    """Send a message via Telegram Bot API."""
    settings = get_settings()
    if not settings.telegram_enabled or not settings.telegram_bot_token:
        return False

    try:
        import requests
    except ImportError:
        log.warning("requests library not installed")
        return False

    base_url = getattr(settings, "telegram_base_url", "https://api.telegram.org").rstrip("/")
    url = f"{base_url}/bot{settings.telegram_bot_token}/sendMessage"

    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup

    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code >= 300:
            log.error("Telegram API error %d: %s", r.status_code, r.text[:200])
            return False
        return True
    except Exception as exc:
        log.error("Failed to send Telegram message: %s", exc)
        return False


def _build_inline_keyboard(actions):
    """Build inline keyboard for pending actions."""
    buttons = []
    for action in actions[:5]:  # Limit to 5 to avoid message too long
        buttons.append([
            {
                "text": f"Allow {action.source_ip}",
                "callback_data": f"ips_allow:{action.id}",
            },
            {
                "text": f"Block {action.source_ip}",
                "callback_data": f"ips_deny:{action.id}",
            },
        ])
    return {"inline_keyboard": buttons} if buttons else None


def handle_telegram_update(update: dict) -> None:
    """Process a Telegram update (message or callback query)."""
    settings = get_settings()
    chat_id = str(settings.telegram_chat_id)

    # Handle callback queries (inline button presses)
    if "callback_query" in update:
        query = update["callback_query"]
        data = query.get("data", "")
        from_chat_id = str(query["message"]["chat"]["id"])

        if from_chat_id != chat_id:
            return

        if data.startswith("ips_allow:"):
            action_id = data.split(":", 1)[1]
            _handle_allow(action_id, from_chat_id)
        elif data.startswith("ips_deny:"):
            action_id = data.split(":", 1)[1]
            _handle_deny(action_id, from_chat_id)
        return

    # Handle text messages
    message = update.get("message", {})
    text = message.get("text", "")
    from_chat_id = str(message.get("chat", {}).get("id", ""))

    if from_chat_id != chat_id:
        return

    if not text.startswith("/"):
        return

    parts = text.split(maxsplit=1)
    command = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""

    if command == "/status":
        _handle_status(from_chat_id)
    elif command == "/pending":
        _handle_pending(from_chat_id)
    elif command in ("/allow", "/approve"):
        _handle_allow(args.strip(), from_chat_id)
    elif command in ("/deny", "/block"):
        if command == "/deny" and args.strip():
            _handle_deny(args.strip(), from_chat_id)
        elif command == "/block" and args.strip():
            _handle_manual_block(args.strip(), from_chat_id)
    elif command == "/unblock":
        _handle_unblock(args.strip(), from_chat_id)
    elif command == "/blocks":
        _handle_blocks(from_chat_id)
    elif command == "/help":
        _handle_help(from_chat_id)


def _handle_status(chat_id: str) -> None:
    """Show IPS status."""
    settings = get_settings()
    approval_mgr = get_approval_manager()
    firewall_mgr = get_firewall_manager()

    pending = approval_mgr.list_pending()
    blocked = firewall_mgr.list_blocked()

    text = (
        f"*IPS Status*\n"
        f"Enabled: {'Yes' if settings.ips_enabled else 'No'}\n"
        f"Mode: {settings.ips_mode}\n"
        f"Pending approvals: {len(pending)}\n"
        f"Blocked IPs: {len(blocked)}"
    )
    _send_telegram_message(chat_id, text)


def _handle_pending(chat_id: str) -> None:
    """List pending actions."""
    approval_mgr = get_approval_manager()
    pending = approval_mgr.list_pending()

    if not pending:
        _send_telegram_message(chat_id, "No pending actions.")
        return

    for action in pending[:5]:
        text = _format_pending_action(action)
        keyboard = {
            "inline_keyboard": [[
                {"text": "Allow", "callback_data": f"ips_allow:{action.id}"},
                {"text": "Block", "callback_data": f"ips_deny:{action.id}"},
            ]]
        }
        _send_telegram_message(chat_id, text, reply_markup=keyboard)


def _handle_allow(action_id: str, chat_id: str) -> None:
    """Approve an action (allow the IP)."""
    if not action_id:
        _send_telegram_message(chat_id, "Usage: /allow <action_id>")
        return

    approval_mgr = get_approval_manager()
    action = approval_mgr.approve(action_id, by="telegram")
    if not action:
        _send_telegram_message(chat_id, f"Action `{action_id}` not found or already decided.")
        return

    # Whitelist the source so the detector ignores it during the TTL window.
    from .whitelist_manager import get_whitelist_manager
    from .pending_rate_limiter import get_pending_rate_limiter
    wl = get_whitelist_manager()
    entry = wl.add(
        ip=action.source_ip,
        added_by="telegram",
        reason=f"Allowed via Telegram: {action.threat_type} (risk={action.risk_score:.1f})",
        action_id=action.id,
    )
    get_pending_rate_limiter().unmark_pending(action.source_ip)
    approval_mgr.mark_executed(action_id)

    # Audit log
    from .audit import log_decision as _audit_log
    _audit_log(action, "allow", "telegram", extra={
        "whitelist_expires_at": entry.expires_at.isoformat() + "Z",
    })

    _send_telegram_message(
        chat_id,
        f"✓ *Allowed*\n`{action.source_ip}` ({action.threat_type})"
    )


def _handle_deny(action_id: str, chat_id: str) -> None:
    """Deny an action (block the IP)."""
    if not action_id:
        _send_telegram_message(chat_id, "Usage: /deny <action_id>")
        return

    approval_mgr = get_approval_manager()
    firewall_mgr = get_firewall_manager()

    action = approval_mgr.deny(action_id, by="telegram")
    if not action:
        _send_telegram_message(chat_id, f"Action `{action_id}` not found or already decided.")
        return

    result = firewall_mgr.block_ip(
        action.source_ip,
        reason=f"Blocked via Telegram: {action.threat_type} (risk={action.risk_score:.1f})",
    )
    if result == BlockResult.APPLIED:
        approval_mgr.mark_executed(action_id)
        status = "✓ Blocked"
    elif result == BlockResult.ALREADY_BLOCKED:
        approval_mgr.mark_executed(action_id)
        status = "✓ Already blocked"
    elif result == firewall_mgr.BlockResult.RECORDED_ONLY:
        status = "⚠ Recorded in app only — OS firewall not applied (needs admin)"
    else:
        status = "✗ Failed to apply firewall rule"

    # Stop throttling — decision is final either way.
    from .pending_rate_limiter import get_pending_rate_limiter
    get_pending_rate_limiter().unmark_pending(action.source_ip)

    # Audit log
    from .audit import log_decision as _audit_log
    _audit_log(action, "block", "telegram", extra={
        "firewall_result": result.value,
    })

    _send_telegram_message(
        chat_id,
        f"{status}\n`{action.source_ip}` ({action.threat_type})"
    )


def _handle_manual_block(ip: str, chat_id: str) -> None:
    """Manually block an IP."""
    if not ip:
        _send_telegram_message(chat_id, "Usage: /block <ip>")
        return

    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        _send_telegram_message(chat_id, f"Invalid IP address: `{ip}`")
        return

    firewall_mgr = get_firewall_manager()
    result = firewall_mgr.block_ip(ip, reason="Manual block via Telegram")

    if result == BlockResult.APPLIED:
        status = "✓ Blocked"
    elif result == BlockResult.ALREADY_BLOCKED:
        status = "✓ Already blocked"
    elif result == BlockResult.RECORDED_ONLY:
        status = "⚠ Recorded in app only — OS firewall not applied (needs admin)"
    else:
        status = "✗ Failed"
    _send_telegram_message(chat_id, f"{status}\n`{ip}`")


def _handle_unblock(ip: str, chat_id: str) -> None:
    """Unblock an IP."""
    if not ip:
        _send_telegram_message(chat_id, "Usage: /unblock <ip>")
        return

    firewall_mgr = get_firewall_manager()
    result = firewall_mgr.unblock_ip(ip)

    if result == BlockResult.UNAPPLIED:
        status = "✓ Unblocked"
    elif result == BlockResult.PARTIAL:
        status = "⚠ Partially unblocked (one chain only)"
    elif result == BlockResult.ALREADY_ABSENT:
        status = "✓ Already not blocked"
    else:
        status = "✗ Failed"
    _send_telegram_message(chat_id, f"{status}\n`{ip}`")


def _handle_blocks(chat_id: str) -> None:
    """List blocked IPs."""
    firewall_mgr = get_firewall_manager()
    blocked = firewall_mgr.list_blocked()

    if not blocked:
        _send_telegram_message(chat_id, "No IPs currently blocked.")
        return

    lines = ["*Blocked IPs:*"]
    for rule in blocked[:10]:
        lines.append(f"• `{rule.ip}` — {rule.reason or 'No reason'}")
    if len(blocked) > 10:
        lines.append(f"… and {len(blocked) - 10} more")

    _send_telegram_message(chat_id, "\n".join(lines))


def _handle_help(chat_id: str) -> None:
    """Show help message."""
    text = (
        "*SentinelScan IPS Commands*\n\n"
        "/status — Show IPS status\n"
        "/pending — List pending approvals\n"
        "/allow <id> — Approve action (allow IP)\n"
        "/deny <id> — Deny action (block IP)\n"
        "/block <ip> — Manually block IP\n"
        "/unblock <ip> — Unblock IP\n"
        "/blocks — List blocked IPs\n"
        "/help — Show this help"
    )
    _send_telegram_message(chat_id, text)


# ---------------------------------------------------------------------------
# Telegram Bot Polling
# ---------------------------------------------------------------------------

class TelegramIPSBot:
    """Background bot that polls Telegram for IPS commands."""

    def __init__(self) -> None:
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._offset: int = 0
        self._poll_interval: float = 2.0  # seconds

    def start(self) -> None:
        """Start the polling thread."""
        if self._running:
            return
        settings = get_settings()
        if not settings.telegram_enabled or not settings.telegram_bot_token:
            log.info("Telegram IPS bot not started (disabled or not configured)")
            return
        if settings.telegram_webhook_enabled:
            log.info("Telegram IPS bot polling disabled (webhook mode enabled)")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="telegram-ips-bot",
            daemon=True,
        )
        self._thread.start()
        log.info("Telegram IPS bot started")

    def stop(self) -> None:
        """Stop the polling thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None
        log.info("Telegram IPS bot stopped")

    def _poll_loop(self) -> None:
        """Main polling loop."""
        import requests

        settings = get_settings()
        base_url = getattr(settings, "telegram_base_url", "https://api.telegram.org").rstrip("/")
        url = f"{base_url}/bot{settings.telegram_bot_token}/getUpdates"

        while self._running:
            try:
                params = {
                    "offset": self._offset,
                    "timeout": 5,  # Long polling
                    "allowed_updates": json.dumps(["message", "callback_query"]),
                }
                r = requests.get(url, params=params, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("ok"):
                        for update in data.get("result", []):
                            self._offset = update["update_id"] + 1
                            try:
                                handle_telegram_update(update)
                            except Exception as exc:
                                log.error("Failed to handle update: %s", exc)
            except Exception as exc:
                log.warning("Telegram poll error: %s", exc)
                time.sleep(5)  # Back off on error
                continue

            time.sleep(self._poll_interval)


def get_telegram_bot() -> TelegramIPSBot:
    """Get or create the singleton bot instance."""
    global _bot_instance
    if _bot_instance is None:
        _bot_instance = TelegramIPSBot()
    return _bot_instance


# ---------------------------------------------------------------------------
# Alert integration — send IPS alerts via Telegram
# ---------------------------------------------------------------------------

def send_ips_alert(
    action_type: str,
    source_ip: str,
    threat_type: str,
    risk_score: float,
    action_id: str = "",
    decision: str = "",
) -> Dict[str, Tuple[bool, str]]:
    """Send an IPS alert via all enabled channels (Telegram, email).

    Args:
        action_type: "pending" | "approved" | "denied" | "auto_blocked"
        source_ip: The IP being acted on
        threat_type: Type of threat detected
        risk_score: Risk score (0-10)
        action_id: The approval action ID
        decision: The decision made (for approved/denied)

    Returns:
        ``{channel_name: (ok, reason)}`` per channel — ponytail: callers
        can now log/surface which channel failed and why. Legacy callers
        can use ``any(ok for ok, _ in result.values())`` for the old bool.
    """
    settings = get_settings()
    result: Dict[str, Tuple[bool, str]] = {}

    # Telegram
    if settings.telegram_enabled and settings.telegram_chat_id:
        try:
            ok = _send_telegram_ips_alert(action_type, source_ip, threat_type, risk_score, action_id, decision)
            result["telegram"] = (ok, "" if ok else "send failed")
        except Exception as exc:
            result["telegram"] = (False, str(exc))
            log.warning("Telegram IPS alert raised: %s", exc)
    else:
        result["telegram"] = (False, "disabled")

    # Email
    if settings.email_enabled:
        try:
            from .alerts import send_ips_alert_email
            sent = send_ips_alert_email(settings, action_type, source_ip, threat_type, risk_score, action_id, decision)
            if sent is None:
                result["email"] = (False, "send returned None")
            else:
                result["email"] = (True, "")
        except Exception as exc:
            result["email"] = (False, str(exc))
            log.warning("Failed to send IPS email alert: %s", exc)
    else:
        result["email"] = (False, "disabled")

    # ponytail: per-channel summary log so operators see which channels actually fired.
    failed = [ch for ch, (ok, _) in result.items() if not ok and result[ch][1] != "disabled"]
    if failed:
        log.warning(
            "IPS alert: %d/%d channels failed for %s (%s): %s",
            len(failed), len(result), source_ip, threat_type,
            {ch: result[ch][1] for ch in failed},
        )
    return result


def _send_telegram_ips_alert(
    action_type: str,
    source_ip: str,
    threat_type: str,
    risk_score: float,
    action_id: str = "",
    decision: str = "",
) -> bool:
    """Send an IPS alert via Telegram."""
    settings = get_settings()
    if not settings.telegram_enabled:
        return False

    chat_id = settings.telegram_chat_id
    if not chat_id:
        return False

    risk_level = "CRITICAL" if risk_score >= 8 else "HIGH" if risk_score >= 6 else "MEDIUM" if risk_score >= 4 else "LOW"

    if action_type == "pending":
        text = (
            f"🔔 *IPS Approval Required*\n\n"
            f"Action ID: `{action_id}`\n"
            f"Source: `{source_ip}`\n"
            f"Threat: {threat_type}\n"
            f"Risk: {risk_score:.1f}/10 ({risk_level})\n\n"
            f"Reply with:\n"
            f"/allow {action_id}\n"
            f"/deny {action_id}"
        )
    elif action_type == "approved":
        text = (
            f"✓ *IPS Approved*\n\n"
            f"Source: `{source_ip}`\n"
            f"Threat: {threat_type}\n"
            f"Decision: {decision}"
        )
    elif action_type == "denied":
        text = (
            f"✗ *IPS Blocked*\n\n"
            f"Source: `{source_ip}`\n"
            f"Threat: {threat_type}\n"
            f"Risk: {risk_score:.1f}/10 ({risk_level})\n"
            f"Firewall rule applied"
        )
    elif action_type == "auto_blocked":
        text = (
            f"🚫 *IPS Auto-Blocked*\n\n"
            f"Source: `{source_ip}`\n"
            f"Threat: {threat_type}\n"
            f"Risk: {risk_score:.1f}/10 ({risk_level})\n"
            f"Auto-blocked (critical threat)"
        )
    else:
        return False

    return _send_telegram_message(chat_id, text)


# ---------------------------------------------------------------------------
# Webhook receiver (optional)
# ---------------------------------------------------------------------------

def create_webhook_blueprint():
    """Create a Flask blueprint for Telegram webhook (optional)."""
    from flask import Blueprint, request, jsonify

    bp = Blueprint("telegram_ips", __name__)

    @bp.route("/api/telegram/webhook", methods=["POST"])
    def telegram_webhook():
        """Receive Telegram updates via webhook."""
        update = request.get_json(silent=True)
        if update:
            handle_telegram_update(update)
        return jsonify({"ok": True})

    return bp
