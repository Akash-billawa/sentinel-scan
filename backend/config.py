"""SentinelScan AI — application configuration loader.

Loads values from environment variables (and a local `.env` file when
present).  Centralised here so the rest of the codebase can import a
single, well-typed settings object.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional at runtime
    pass


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_str_stripped(name: str, default: str = "") -> str:
    """Env-var string with leading/trailing whitespace stripped and any
    trailing slash removed.  Used for URLs that get concatenated with paths
    (e.g. ``SENTINEL_PUBLIC_URL`` + ``/api/attacks/...``)."""

    return (os.environ.get(name) or default).strip().rstrip("/")


def _env_list(name: str, default: List[str]) -> List[str]:
    raw = os.environ.get(name)
    if not raw:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    # --- Server ----------------------------------------------------------
    host: str = field(default_factory=lambda: _env_str("SENTINEL_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("SENTINEL_PORT", 5000))
    secret_key: str = field(
        default_factory=lambda: _env_str(
            "SENTINEL_SECRET_KEY", "sentinelscan-dev-secret-change-me"
        )
    )
    proxy_fix_count: int = field(
        default_factory=lambda: _env_int("SENTINEL_PROXY_FIX_COUNT", 0)
    )
    # Public URL the operator's browser reaches the app at.
    # Used to build absolute links (e.g. "open dashboard").
    # Defaults to localhost so the bundled sim + dashboard works out-of-the-box; set this in production.
    public_url: str = field(
        default_factory=lambda: _env_str_stripped(
            "SENTINEL_PUBLIC_URL", "http://localhost:5000"
        )
    )

    # --- Capture mode ----------------------------------------------------
    capture_mode: str = field(
        default_factory=lambda: _env_str("SENTINEL_CAPTURE_MODE", "auto").lower()
    )
    interface: str = field(default_factory=lambda: _env_str("SENTINEL_INTERFACE", ""))

    # --- Database --------------------------------------------------------
    db_url: str = field(
        default_factory=lambda: _env_str(
            "SENTINEL_DB_URL", f"sqlite:///{PROJECT_ROOT / 'data' / 'sentinelscan.db'}"
        )
    )

    # --- Detection tuning ----------------------------------------------
    window_seconds: int = field(
        default_factory=lambda: _env_int("SENTINEL_WINDOW_SECONDS", 15)
    )
    portsweep_threshold: int = field(
        default_factory=lambda: _env_int("SENTINEL_PORTSWEEP_THRESHOLD", 20)
    )
    hostsweep_threshold: int = field(
        default_factory=lambda: _env_int("SENTINEL_HOSTSWEEP_THRESHOLD", 15)
    )
    rate_threshold: int = field(
        default_factory=lambda: _env_int("SENTINEL_RATE_THRESHOLD", 200)
    )
    # Comma-separated list of Suricata rule SIDs to enable, or "all".
    # Only rules listed here will be evaluated by the classifier.
    # Examples: "all", "3400001,3400100,3400101", "3400100"
    scan_rules: str = field(
        default_factory=lambda: _env_str("SENTINEL_SCAN_RULES", "all")
    )

    # --- Alerts ----------------------------------------------------------
    alerts_enabled: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_ALERTS_ENABLED", True)
    )
    alert_cooldown: int = field(
        default_factory=lambda: _env_int("SENTINEL_ALERT_COOLDOWN", 120)
    )
    alert_min_level: str = field(
        default_factory=lambda: _env_str("SENTINEL_ALERT_MIN_LEVEL", "low").lower()
    )

    desktop_alerts: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_DESKTOP_ALERTS", True)
    )

    email_enabled: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_EMAIL_ENABLED", False)
    )
    smtp_host: str = field(default_factory=lambda: _env_str("SENTINEL_SMTP_HOST"))
    smtp_port: int = field(default_factory=lambda: _env_int("SENTINEL_SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: _env_str("SENTINEL_SMTP_USER"))
    smtp_password: str = field(default_factory=lambda: _env_str("SENTINEL_SMTP_PASSWORD"))
    smtp_from: str = field(default_factory=lambda: _env_str("SENTINEL_SMTP_FROM"))
    smtp_to: List[str] = field(
        default_factory=lambda: _env_list("SENTINEL_SMTP_TO", [])
    )

    telegram_enabled: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_TELEGRAM_ENABLED", False)
    )
    telegram_bot_token: str = field(
        default_factory=lambda: _env_str("SENTINEL_TELEGRAM_BOT_TOKEN")
    )
    telegram_chat_id: str = field(
        default_factory=lambda: _env_str("SENTINEL_TELEGRAM_CHAT_ID")
    )
    telegram_base_url: str = field(
        default_factory=lambda: _env_str("SENTINEL_TELEGRAM_BASE_URL", "https://api.telegram.org")
    )
    telegram_webhook_enabled: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_TELEGRAM_WEBHOOK_ENABLED", False)
    )
    telegram_webhook_url: str = field(
        default_factory=lambda: _env_str("SENTINEL_TELEGRAM_WEBHOOK_URL", "")
    )


    # --- Auth -----------------------------------------------------------
    auth_enabled: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_AUTH_ENABLED", True)
    )
    auth_admin_user: str = field(
        default_factory=lambda: _env_str("SENTINEL_ADMIN_USER", "admin")
    )
    auth_admin_password: str = field(
        default_factory=lambda: _env_str("SENTINEL_ADMIN_PASSWORD", "")
    )  # empty -> auto-generate on first run
    auth_session_hours: int = field(
        default_factory=lambda: _env_int("SENTINEL_AUTH_SESSION_HOURS", 12)
    )

    # --- Threat intelligence (AbuseIPDB) ---------------------------------
    threat_intel_enabled: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_THREAT_INTEL_ENABLED", False)
    )
    threat_intel_api_key: str = field(
        default_factory=lambda: _env_str("SENTINEL_THREAT_INTEL_API_KEY", "")
    )
    threat_intel_api_url: str = field(
        default_factory=lambda: _env_str_stripped(
            "SENTINEL_THREAT_INTEL_API_URL", "https://api.abuseipdb.com"
        )
    )
    threat_intel_max_age: int = field(
        default_factory=lambda: _env_int("SENTINEL_THREAT_INTEL_MAX_AGE", 30)
    )

    # --- Encrypted log storage ------------------------------------------
    encrypt_logs: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_ENCRYPT_LOGS", False)
    )
    encryption_salt: str = field(
        default_factory=lambda: _env_str("SENTINEL_ENCRYPTION_SALT", "")
    )  # empty -> derive from secret_key

    # --- IPS (Intrusion Prevention System) ------------------------------
    ips_enabled: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_IPS_ENABLED", False)
    )
    ips_mode: str = field(
        default_factory=lambda: _env_str("SENTINEL_IPS_MODE", "approve").lower()
    )  # approve | auto_block | alert_only
    ips_approval_timeout: int = field(
        default_factory=lambda: _env_int("SENTINEL_IPS_APPROVAL_TIMEOUT", 60)
    )  # seconds to wait for operator response
    ips_auto_block_threshold: float = field(
        default_factory=lambda: float(_env_str("SENTINEL_IPS_AUTO_BLOCK_THRESHOLD", "8.0"))
    )  # risk score >= this triggers auto-block
    ips_approval_threshold: float = field(
        default_factory=lambda: float(_env_str("SENTINEL_IPS_APPROVAL_THRESHOLD", "4.0"))
    )  # risk score >= this requires approval
    ips_block_expiry: int = field(
        default_factory=lambda: _env_int("SENTINEL_IPS_BLOCK_EXPIRY", 0)
    )  # seconds until block expires (0 = never)
    ips_reapply_on_boot: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_IPS_REAPPLY_ON_BOOT", True)
    )
    ips_whitelist_ttl: int = field(
        default_factory=lambda: _env_int("SENTINEL_IPS_WHITELIST_TTL", 300)
    )  # default whitelist duration when operator clicks Allow
    ips_whitelist_max_entries: int = field(
        default_factory=lambda: _env_int("SENTINEL_IPS_WHITELIST_MAX_ENTRIES", 1000)
    )
    # CIDRs the firewall manager must never block (comma-separated).
    # Defaults: loopback + link-local + multicast + RFC1918 management.
    # Operators may extend with SENTINEL_PROTECTED_CIDRS="10.0.0.0/8,..."
    ips_protected_cidrs: List[str] = field(
        default_factory=lambda: _env_list(
            "SENTINEL_PROTECTED_CIDRS",
            [
                "127.0.0.0/8",      # loopback
                "::1/128",          # IPv6 loopback
                "169.254.0.0/16",   # link-local
                "fe80::/10",        # IPv6 link-local
                "224.0.0.0/4",      # IPv4 multicast
                "ff00::/8",         # IPv6 multicast
                "255.255.255.255/32",  # broadcast
            ],
        )
    )
    ips_protected_allow_bypass: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_PROTECTED_ALLOW_BYPASS", False)
    )  # when True, allow blocking protected CIDRs (only for tests / staging)

    # --- Paths -----------------------------------------------------------
    @property
    def project_root(self) -> Path:
        return PROJECT_ROOT

    @property
    def data_dir(self) -> Path:
        return PROJECT_ROOT / "data"

    @property
    def reports_dir(self) -> Path:
        return PROJECT_ROOT / "reports"

    @property
    def logs_dir(self) -> Path:
        return PROJECT_ROOT / "logs"

    @property
    def frontend_dir(self) -> Path:
        return PROJECT_ROOT / "frontend"


# Singleton-style accessor ----------------------------------------------------
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a memoised :class:`Settings` instance."""

    global _settings
    if _settings is None:
        s = Settings()
        s.data_dir.mkdir(parents=True, exist_ok=True)
        s.reports_dir.mkdir(parents=True, exist_ok=True)
        s.logs_dir.mkdir(parents=True, exist_ok=True)
        if s.secret_key == "sentinelscan-dev-secret-change-me":
            import logging as _log
            _log.getLogger("sentinelscan.config").warning(
                "SENTINEL_SECRET_KEY is set to the default value. "
                "Set a unique secret in .env or SENTINEL_SECRET_KEY for production use."
            )
        _settings = s
    return _settings


def reset_settings() -> None:
    """Clear the cached singleton so the next ``get_settings()`` rebuilds.

    Intended for test fixtures that mutate settings in-place — calling
    this in teardown ensures no cross-test pollution.
    """

    global _settings
    _settings = None
