"""Helper script to test SentinelScan alert dispatching.

Generates a dummy attack, inserts it into the database, and routes it
to the active AlertManager. Useful for verifying Telegram, Email,
and Desktop notifications without running a real scan.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Insert project root into path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from backend.alerts import AlertManager
from backend.config import get_settings
from backend.database import Attack, init_db, session_scope


def main() -> None:
    print("=== SENTINELSCAN ALERT CONFIGURATION TESTER ===")
    init_db()
    
    settings = get_settings()
    print("Active Configuration:")
    print(f"  Alerts Enabled : {settings.alerts_enabled}")
    print(f"  Desktop Alerts : {settings.desktop_alerts}")
    print(f"  Email Enabled  : {settings.email_enabled} (To: {settings.smtp_to})")
    print(f"  Telegram       : {settings.telegram_enabled} (Chat ID: {settings.telegram_chat_id})")
    print(f"  Telegram Base  : {settings.telegram_base_url}")

    # Create dummy attack record
    dummy_attack = Attack(
        source_ip="198.51.100.42",
        source_country="Testland",
        source_isp="Security Testing Corp",
        source_asn="AS65536",
        source_hostname="attacker-sim.local",
        source_tool_guess="Nmap",
        source_tool_confidence=98,
        source_os_guess="Linux Kernel 5.x",
        source_os_confidence=85,
        scan_type="TCP SYN Sweep",
        scan_confidence=95,
        risk_score=8.5,
        risk_level="high",
        packet_count=180,
        unique_ports=32,
        unique_targets=1,
        started_at=datetime.now(timezone.utc).replace(tzinfo=None),
        target_ports_json=json.dumps([21, 22, 23, 80, 443, 8080]),
        technique_signals_json=json.dumps(["port_sweep"])
    )

    print("\nInserting mock attack into database...")
    with session_scope() as session:
        session.add(dummy_attack)
        session.flush()
        session.expunge(dummy_attack)

    print(f"Mock attack created with ID: {dummy_attack.id}")
    print("Dispatching test alert to channels (spawning threads)...")
    
    alert_mgr = AlertManager(settings)
    alert_mgr.on_attack(dummy_attack, {})
    
    print("\nAlert threads launched.")
    print("Waiting 12 seconds for dispatches to complete...")
    time.sleep(12)
    
    print("\nChecking alert logs from database:")
    with session_scope() as session:
        from backend.database import Alert
        logs = session.query(Alert).filter(Alert.attack_id == dummy_attack.id).all()
        if not logs:
            print("  No alert logs found in database. Check application logs for errors.")
        for log in logs:
            status = "SUCCESS" if log.success else "FAILED"
            msg = log.message or "delivered"
            print(f"  - [{log.channel.upper()}] Status: {status} | Message: {msg}")

    print("\nTest finished. Please check your notification apps!")


if __name__ == "__main__":
    main()
