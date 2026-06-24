"""Admin-password CLI helper.

Tiny command-line tool for the operator "I lost the auto-generated
password" scenario — none of which the dashboard exposes, by design.

Usage::

    python -m backend.auth_cli reset <new-password>           # set the default admin password
    python -m backend.auth_cli reset <new-password> --user me  # set a different user
    python -m backend.auth_cli show                           # list users (no secrets)
    python -m backend.auth_cli show --password                # show the default admin's password hash
                                                            # (printed on first run, see auth.py)

The tool imports :mod:`backend.config` so it picks up the same
``SENTINEL_*`` environment variables the server uses, including
``SENTINEL_DB_URL``.  No background services are started.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

# Make sure ``from .config import ...`` works whether the user runs
# ``python -m backend.auth_cli`` from the project root or directly.
if __package__ in (None, ""):
    import pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from backend import config as _config  # noqa: F401  (forces load_dotenv)
else:
    from . import config as _config  # noqa: F401

from backend import auth, database as db
from werkzeug.security import generate_password_hash


def _cmd_reset(args: argparse.Namespace) -> int:
    """Set the password for the default admin (or a named user)."""

    username = args.user or (_config.get_settings().auth_admin_user or "admin")
    new_pw = args.password
    if len(new_pw) < 8:
        print("error: password must be at least 8 characters", file=sys.stderr)
        return 2

    from sqlalchemy import select
    with db.session_scope() as s:
        user = s.scalar(select(db.User).where(db.User.username == username))
        if user is None:
            # Create the user on demand.  This is the documented recovery
            # path for "I deleted the DB user table by mistake" too.
            user = db.User(
                username=username,
                password_hash=generate_password_hash(new_pw),
                created_at=datetime.now(timezone.utc).replace(tzinfo=None),
                is_active=True,
            )
            s.add(user)
            s.flush()
            print(f"created user '{username}'")
        else:
            user.password_hash = generate_password_hash(new_pw)
            user.is_active = True
            print(f"password reset for user '{username}'")
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    """List users (and optionally their password hashes for debugging)."""

    from sqlalchemy import select
    with db.session_scope() as s:
        users = list(s.scalars(select(db.User).order_by(db.User.id)))
        if not users:
            print("(no users in database — start the server once to bootstrap)")
            return 0
        for u in users:
            line = f"id={u.id}  username={u.username}  active={u.is_active}  created={u.created_at.isoformat()}Z"
            if u.last_login_at:
                line += f"  last_login={u.last_login_at.isoformat()}Z"
            if args.password:
                line += f"  hash={u.password_hash}"
            print(line)
    return 0


def main(argv: list[str] | None = None) -> int:
    # Make sure paths exist and the engine is initialised.
    db.init_db()

    parser = argparse.ArgumentParser(
        prog="auth_cli",
        description="SentinelScan AI — admin password CLI",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_reset = sub.add_parser("reset", help="reset a user's password")
    p_reset.add_argument("password", help="new password (>=8 chars)")
    p_reset.add_argument("--user", "-u", help="username (default: SENTINEL_ADMIN_USER)")
    p_reset.set_defaults(func=_cmd_reset)

    p_show = sub.add_parser("show", help="list users")
    p_show.add_argument("--password", action="store_true", help="also print password hashes")
    p_show.set_defaults(func=_cmd_show)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
