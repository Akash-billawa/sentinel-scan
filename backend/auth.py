"""Authentication — session login, password hashing, default-admin bootstrap.

This module owns the User model lifecycle and exposes a small set of
helpers used by the Flask app factory:

* :func:`bootstrap_default_admin` — make sure a default admin exists on
  startup.  The password is taken from ``SENTINEL_ADMIN_PASSWORD`` if
  set, otherwise a random one is generated and printed to the server
  log (it is *not* persisted to disk by SentinelScan).
* :func:`login_required` — Flask view decorator that 401s on missing
  / expired sessions.  When ``SENTINEL_AUTH_ENABLED=false`` the decorator
  is a no-op so local development "just works".
* :func:`verify_credentials` — verify a username/password pair against
  the user table.
* :func:`change_password` — set a new password for an existing user.

The session is a signed Flask cookie, so no server-side session store
is required; the lifetime is enforced via ``PERMANENT_SESSION_LIFETIME``
on the Flask app.
"""

from __future__ import annotations

import logging
import secrets
import string
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Optional

from flask import jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from . import database as db
from .config import Settings, get_settings

log = logging.getLogger("sentinelscan.auth")


# ---------------------------------------------------------------------------
# Default-admin bootstrap
# ---------------------------------------------------------------------------


def _random_password(length: int = 18) -> str:
    """Generate a strong random password using only URL-safe characters.

    18 chars of [A-Za-z0-9] gives ~108 bits of entropy — enough to
    survive a dictionary attack against a PBKDF2 hash with 600k rounds.
    """

    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def bootstrap_default_admin(settings: Optional[Settings] = None) -> None:
    """Create the default admin user on first run.

    Behavior:

    * If no users exist at all, create ``settings.auth_admin_user`` with
      a password from ``SENTINEL_ADMIN_PASSWORD`` if set, otherwise a
      random one.  The random password is printed to the server log
      exactly once, at INFO level.
    * If the user already exists *and* ``SENTINEL_ADMIN_PASSWORD`` is
      set in the environment, reset the existing user's password to
      the env-supplied value.  This is the operator's recovery path
      for the "I lost the auto-generated password" problem — set the
      env var, restart, log in, change it from the dashboard.
    * If the user already exists and no env password is set, leave it
      alone (so password changes from a previous run are not reset).
    * If auth is disabled, do nothing.
    """

    s = settings or get_settings()
    if not s.auth_enabled:
        log.info("Auth disabled (SENTINEL_AUTH_ENABLED=false); skipping admin bootstrap")
        return

    # SQLAlchemy imports are deferred to function scope so a missing
    # ``database`` module doesn't crash import of the package.
    from sqlalchemy import select

    with db.session_scope() as sess:
        count = sess.scalar(_count_users_query())
        username = s.auth_admin_user or "admin"
        if count and count > 0:
            # Existing users — apply the env-supplied password if any,
            # and log a clear summary so the operator can see what state
            # the bootstrap left things in.
            if s.auth_admin_password:
                user = sess.scalar(
                    select(db.User).where(db.User.username == username)
                )
                if user is not None:
                    user.password_hash = generate_password_hash(s.auth_admin_password)
                    log.info(
                        "Reset password for default admin user '%s' from "
                        "SENTINEL_ADMIN_PASSWORD (min 8 chars enforced)",
                        username,
                    )
                else:
                    log.warning(
                        "SENTINEL_ADMIN_PASSWORD is set but no admin user "
                        "named '%s' was found (existing users: %d). "
                        "Run `python -m backend.auth_cli reset <new-password>` "
                        "to set a password for an existing account.",
                        username, count,
                    )
            else:
                log.info(
                    "Admin bootstrap: %d user(s) already exist; leaving "
                    "passwords untouched (set SENTINEL_ADMIN_PASSWORD in .env "
                    "and restart to overwrite the admin password).",
                    count,
                )
            _log_admin_summary(sess, s)
            return

        # No users yet — create the admin with the env password, or a
        # random one that we print to stderr (NOT persisted to disk).
        password = s.auth_admin_password or _random_password()
        sess.add(
            db.User(
                username=username,
                password_hash=generate_password_hash(password),
                created_at=datetime.now(timezone.utc).replace(tzinfo=None),
                is_active=True,
            )
        )
        _log_admin_summary(sess, s)

    if not s.auth_admin_password:
        # First-run with a random password — must surface to the
        # operator loudly, in both the log and stderr.
        log.warning(
            "============================================================"
        )
        log.warning(
            "  Default admin user created:  username=%s  password=<printed to stderr>",
            username,
        )
        log.warning(
            "  Save this password — it is NOT persisted to disk."
        )
        log.warning(
            "  Set SENTINEL_ADMIN_PASSWORD in .env to fix it for next run."
        )
        log.warning(
            "  Run `python -m backend.auth_cli reset <new-password>` to "
            "reset it without restarting."
        )
        log.warning(
            "============================================================"
        )
        import sys
        print(f"\n  [SentinelScan] Default admin credentials:\n"
              f"    Username: {username}\n"
              f"    Password: {password}\n", file=sys.stderr)
    else:
        log.info(
            "Default admin user '%s' created from SENTINEL_ADMIN_PASSWORD",
            username,
        )


def _log_admin_summary(sess, s) -> None:
    """Emit a one-line summary of the admin state — useful in startup logs.

    Shows the admin username, how many users exist, whether the
    SENTINEL_ADMIN_PASSWORD env var was honored, and the recovery
    command for the "I forgot the password" case.
    """
    from sqlalchemy import select, func
    count = sess.scalar(select(func.count(db.User.id))) or 0
    admin_user = sess.scalar(
        select(db.User).where(db.User.username == (s.auth_admin_user or "admin"))
    )
    env_used = bool(s.auth_admin_password)
    env_hint = "SENTINEL_ADMIN_PASSWORD applied" if env_used else "SENTINEL_ADMIN_PASSWORD not set"
    log.info(
        "Auth bootstrap: %d user(s); admin username=%s%s; reset with: "
        "python -m backend.auth_cli reset <new-password>",
        count,
        s.auth_admin_user or "admin",
        f" ({env_hint})" if admin_user else "",
    )


def _count_users_query():
    """Return a select statement that counts all users."""
    from sqlalchemy import select, func
    return select(func.count(db.User.id))


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def verify_credentials(username: str, password: str) -> Optional[db.User]:
    """Return the User row on success, ``None`` on failure.

    Failed lookups are deliberately indistinguishable from bad-password
    attempts (returns ``None`` for both) so callers don't leak which
    usernames exist via timing or messages.
    """

    if not username or not password:
        return None
    with db.session_scope() as sess:
        from sqlalchemy import select
        user = sess.scalar(select(db.User).where(db.User.username == username))
        if not user or not user.is_active:
            return None
        if not check_password_hash(user.password_hash, password):
            return None
        user.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
        sess.flush()
        sess.refresh(user)
        sess.expunge(user)
        return user


def change_password(username: str, new_password: str) -> bool:
    """Hash and store a new password.  Returns ``True`` on success.

    Bumps ``session_version`` so existing sessions are invalidated.
    """

    if not new_password or len(new_password) < 8:
        return False
    with db.session_scope() as sess:
        from sqlalchemy import select
        user = sess.scalar(select(db.User).where(db.User.username == username))
        if not user:
            return False
        user.password_hash = generate_password_hash(new_password)
        user.session_version = getattr(user, "session_version", 0) + 1
        sess.flush()
        return True


def current_user() -> Optional[dict]:
    """Return the session's user payload (id + username) or ``None``."""

    user = session.get("user")
    if not user or not isinstance(user, dict):
        return None
    return user


# ---------------------------------------------------------------------------
# View decorator
# ---------------------------------------------------------------------------


def login_required(view: Callable) -> Callable:
    """Reject the request with 401 if the session isn't authenticated.

    A no-op when ``SENTINEL_AUTH_ENABLED=false`` so local development
    still works without juggling credentials.
    """

    @wraps(view)
    def wrapper(*args, **kwargs):
        s = get_settings()
        if not s.auth_enabled:
            return view(*args, **kwargs)
        user_data = current_user()
        if not user_data:
            # Browsers hit both JSON endpoints and the dashboard SPA.  For
            # any *non-API* path (i.e. the dashboard itself, regardless of
            # what the Accept header says — some browsers send ``*/*`` for
            # cached navigations) we redirect to the login page so the
            # user never sees a raw JSON 401 in their browser.  ``/api/*``
            # routes always get the JSON 401 so client JS can react.
            from flask import redirect, url_for
            if not request.path.startswith("/api/"):
                return redirect(url_for("login_page", next=request.path))
            return jsonify({"ok": False, "error": "authentication required"}), 401
        # Verify the session version matches the current user version.
        # A mismatch means the password was changed since this session
        # was created — invalidate it.
        session_ver = user_data.get("session_version", 0)
        from sqlalchemy import select
        with db.session_scope() as sess:
            db_user = sess.scalar(select(db.User).where(db.User.id == user_data["id"]))
            if not db_user or not db_user.is_active:
                session.pop("user", None)
                return jsonify({"ok": False, "error": "authentication required"}), 401
            if session_ver != getattr(db_user, "session_version", 0):
                session.pop("user", None)
                return jsonify({"ok": False, "error": "session expired, please log in again"}), 401
        return view(*args, **kwargs)

    return wrapper
