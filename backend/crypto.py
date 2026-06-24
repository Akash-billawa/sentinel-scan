"""Transparent application-level encryption for sensitive log fields.

We use Fernet (AES-128-CBC + HMAC-SHA256) under the hood.  The key is
derived from ``SENTINEL_SECRET_KEY`` (and an optional
``SENTINEL_ENCRYPTION_SALT``) via PBKDF2-HMAC-SHA256 with 200_000
iterations — the iteration count is high enough to slow down a brute
force attack on a stolen SQLite file but low enough that boot is still
sub-second.

Two pieces of glue make this transparent to the rest of the codebase:

* :func:`encrypt_str` / :func:`decrypt_str` — strings in, strings out.
  Encrypted values are stored as ``enc:v1:<base64>`` so we can tell a
  fresh plaintext row from a ciphertext row at migration time.

* :class:`EncryptedStr` — a SQLAlchemy :class:`TypeDecorator` that
  encrypts on flush and decrypts on read.  Model code looks identical
  to a regular ``String`` column; the encryption toggle is
  ``SENTINEL_ENCRYPT_LOGS=true``.

If encryption is disabled (the default), the type decorator is a
no-op pass-through, so existing deployments aren't forced to migrate.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import logging
import time as _time
from typing import Optional, Tuple

from sqlalchemy.types import String, TypeDecorator

from .config import get_settings

log = logging.getLogger("sentinelscan.crypto")

_PREFIX = "enc:v1:"
_PBKDF2_ITERS = 200_000
_KEY_LEN_BYTES = 32  # Fernet expects a 32-byte url-safe-base64 key

# Lazily-loaded cryptography symbols.  Importing ``Fernet`` at module load
# time forces ``cryptography`` to be installed even when the operator has
# SENTINEL_ENCRYPT_LOGS=false (the default).  By deferring the import until
# the first call to ``_get_fernet()`` we keep ``cryptography`` an optional
# runtime dependency — it only becomes required when encryption is on.
_FERNET_IMPL = None  # cached ``Fernet`` class once imported
_INVALID_TOKEN_IMPL = None  # cached ``InvalidToken`` exception class


def _get_fernet() -> Tuple:
    """Return ``(Fernet, InvalidToken)`` from ``cryptography.fernet``.

    Raises ``ImportError`` (caught by the callers) if the package isn't
    installed.  Result is memoised at module scope.
    """

    global _FERNET_IMPL, _INVALID_TOKEN_IMPL
    if _FERNET_IMPL is None:
        from cryptography.fernet import Fernet, InvalidToken
        _FERNET_IMPL = Fernet
        _INVALID_TOKEN_IMPL = InvalidToken
    return _FERNET_IMPL, _INVALID_TOKEN_IMPL


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def _derive_key(secret: str, salt: str) -> bytes:
    """Derive a Fernet-compatible key from the app secret.

    Returns a urlsafe-base64 encoded 32-byte key, which is what
    :class:`cryptography.fernet.Fernet` expects.
    """

    salt_bytes = salt.encode("utf-8") if salt else b"sentinelscan-default-salt"
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8"),
        salt_bytes,
        _PBKDF2_ITERS,
        dklen=_KEY_LEN_BYTES,
    )
    return base64.urlsafe_b64encode(derived)


def _fernet() -> Optional["object"]:
    """Return a :class:`Fernet` instance if encryption is enabled.

    Returns ``None`` when ``SENTINEL_ENCRYPT_LOGS=false`` (the default),
    or when the ``cryptography`` package isn't installed — in the latter
    case the caller should fall back gracefully.  An exception is logged
    at WARNING so missing deps surface in the server log.
    """

    s = get_settings()
    if not s.encrypt_logs:
        return None
    try:
        Fernet, _ = _get_fernet()
    except ImportError as exc:
        log.warning(
            "SENTINEL_ENCRYPT_LOGS=true but 'cryptography' is not installed: %s "
            "(run `pip install cryptography` to enable encrypted log storage)",
            exc,
        )
        return None
    salt = s.encryption_salt or f"sentinelscan::{s.secret_key}"
    return Fernet(_derive_key(s.secret_key, salt))


# ---------------------------------------------------------------------------
# Pass-through helpers
# ---------------------------------------------------------------------------


def encrypt_str(plain):
    """Encrypt a string for storage.  ``None`` passes through unchanged.

    Already-encrypted values (detected by the ``enc:v1:`` prefix) are
    returned untouched so re-encryption is idempotent.
    """

    if plain is None or plain == "":
        return plain
    if isinstance(plain, str) and plain.startswith(_PREFIX):
        return plain
    f = _fernet()
    if f is None:
        return plain
    token = f.encrypt(plain.encode("utf-8"))
    return _PREFIX + token.decode("ascii")


def decrypt_str(value):
    """Reverse of :func:`encrypt_str`.  ``None`` and plaintext pass through."""

    if value is None or value == "":
        return value
    if not (isinstance(value, str) and value.startswith(_PREFIX)):
        return value
    f = _fernet()
    if f is None:
        # Encryption was turned off between write and read — return the
        # cipher blob rather than crash; the dashboard can still render
        # everything else.  ``f is None`` also covers the case where the
        # 'cryptography' package is missing — encrypted rows would not
        # exist in that case anyway, so the same fall-through is correct.
        log.warning("encrypted value read while encryption is disabled or cryptography missing")
        return value
    try:
        _, InvalidToken = _get_fernet()
        token = value[len(_PREFIX):].encode("ascii")
        return f.decrypt(token).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        log.warning("failed to decrypt stored value: %s", exc)
        return None


def is_encrypted(value):
    """Return True if ``value`` looks like an encrypted blob."""

    return isinstance(value, str) and value.startswith(_PREFIX)


# ---------------------------------------------------------------------------
# SQLAlchemy type decorator
# ---------------------------------------------------------------------------


class EncryptedStr(TypeDecorator):
    """A :class:`String` column that encrypts on write and decrypts on read.

    Falls through to a plain ``String(255)`` when
    ``SENTINEL_ENCRYPT_LOGS=false`` so no runtime cost is paid in
    development.
    """

    impl = String
    cache_ok = True

    def __init__(self, length=255, *args, **kwargs):
        super().__init__(length, *args, **kwargs)
        self._length = length

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(String(self._length))

    def process_bind_param(self, value, dialect):  # write
        if value is None:
            return None
        return encrypt_str(str(value))

    def process_result_value(self, value, dialect):  # read
        if value is None:
            return None
        return decrypt_str(value)


# ---------------------------------------------------------------------------
# Migration helper
# ---------------------------------------------------------------------------


def _migrate_attacks_sensitive(transform, label, limit: Optional[int] = None):
    """Apply ``transform`` to each sensitive field of every attacks row.

    ``transform`` is a string-in/string-out function (encrypt_str or
    decrypt_str).  We read raw column values via the SQLAlchemy
    connection — bypassing the EncryptedStr type decorator, which would
    auto-decrypt on load and hide the cipher blob from us.
    """

    f = _fernet()
    if f is None:
        return 0

    from sqlalchemy import text
    from . import database as db

    sensitive_fields = (
        "source_ip", "source_mac", "source_hostname",
        "source_country", "source_isp", "source_asn",
        "source_os_guess", "source_tool_guess",
        "scan_type",
        "target_ports_json", "target_hosts_json",
        "technique_signals_json",
    )

    cols_sql = ", ".join(sensitive_fields)
    sel = f"SELECT id, {cols_sql} FROM attacks"
    upd = (
        "UPDATE attacks SET "
        + ", ".join(f"{c} = :{c}" for c in sensitive_fields)
        + " WHERE id = :id"
    )

    updated = 0
    with db.get_engine().begin() as conn:
        for row in conn.execute(text(sel)).fetchall():
            row_dict = dict(row._mapping)
            rid = row_dict.pop("id")
            new_vals = {}
            changed = False
            for c, v in row_dict.items():
                if v is None or v == "":
                    new_vals[c] = v
                    continue
                tv = transform(v)
                if tv != v:
                    changed = True
                new_vals[c] = tv
            if changed:
                new_vals["id"] = rid
                conn.execute(text(upd), new_vals)
                updated += 1
                if limit is not None and updated >= limit:
                    log.info("Reached migration cap of %d rows; pausing for now", limit)
                    break

    if updated:
        log.info("%s %d existing attack rows", label, updated)
    return updated


def migrate_plaintext_to_encrypted(dry_run=False, limit: Optional[int] = 5000):
    """Encrypt any plaintext rows in the ``attacks`` table.

    Idempotent: rows that are already encrypted (start with ``enc:v1:``)
    are skipped.  Returns the number of rows updated.
    """

    if dry_run:
        # Dry-run path: scan, count, log only.
        from sqlalchemy import text
        from . import database as db
        if _fernet() is None:
            return 0
        sel = (
            "SELECT COUNT(*) FROM attacks WHERE "
            + " OR ".join(f"({c} IS NOT NULL AND {c} != '' AND substr({c}, 1, 7) != 'enc:v1:')"
                          for c in (
                              "source_ip", "source_mac", "source_hostname",
                              "source_country", "source_isp", "source_asn",
                              "source_os_guess", "source_tool_guess",
                              "scan_type",
                              "target_ports_json", "target_hosts_json",
                              "technique_signals_json",
                          ))
        )
        with db.get_engine().connect() as conn:
            return conn.execute(text(sel)).scalar() or 0
    return _migrate_attacks_sensitive(encrypt_str, "encrypted", limit=limit)


def migrate_encrypted_to_plaintext(dry_run=False, limit: Optional[int] = 5000):
    """Decrypt any encrypted rows back to plaintext.

    Useful when the operator wants to turn ``SENTINEL_ENCRYPT_LOGS`` off
    after it was on.  Idempotent — plaintext rows are skipped.
    """

    if dry_run:
        from sqlalchemy import text
        from . import database as db
        if _fernet() is None:
            return 0
        sel = (
            "SELECT COUNT(*) FROM attacks WHERE "
            + " OR ".join(f"substr({c}, 1, 7) = 'enc:v1:'"
                          for c in (
                              "source_ip", "source_mac", "source_hostname",
                              "source_country", "source_isp", "source_asn",
                              "source_os_guess", "source_tool_guess",
                              "scan_type",
                              "target_ports_json", "target_hosts_json",
                              "technique_signals_json",
                          ))
        )
        with db.get_engine().connect() as conn:
            return conn.execute(text(sel)).scalar() or 0
    return _migrate_attacks_sensitive(decrypt_str, "decrypted", limit=limit)


# ---------------------------------------------------------------------------
# HMAC-signed ack tokens  (prevents integer-enumeration abuse on /ack)
# ---------------------------------------------------------------------------

_ACK_TOKEN_MAX_AGE = 86400  # 24 hours


def generate_ack_token(attack_id: int, secret_key: str) -> Tuple[str, str]:
    """Return ``(timestamp_str, hex_token)`` for a signed ack link."""
    ts = str(int(_time.time()))
    msg = f"{attack_id}:{ts}".encode()
    sig = _hmac.new(secret_key.encode(), msg, hashlib.sha256).hexdigest()[:32]
    return ts, sig


def verify_ack_token(
    attack_id: int, secret_key: str, ts_str: str, token: str
) -> bool:
    """Verify an ack token is valid and not expired."""
    try:
        ts = int(ts_str)
    except (ValueError, TypeError):
        return False
    if _time.time() - ts > _ACK_TOKEN_MAX_AGE:
        return False
    msg = f"{attack_id}:{ts_str}".encode()
    expected = _hmac.new(secret_key.encode(), msg, hashlib.sha256).hexdigest()[:32]
    return _hmac.compare_digest(token, expected)
