"""Shared pytest config for SentinelScan tests.

Adds the project root to ``sys.path`` so ``import backend.X`` works
without installing the package.  Also silences the chatty
``sentinelscan.*`` loggers during test runs.
"""

import logging
import sys
import warnings
from pathlib import Path

import pytest

# Make ``backend`` importable as a top-level package.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def pytest_configure(config):  # noqa: D401, ARG001
    """Quieten ``sentinelscan.*`` loggers and suppress Scapy warnings."""
    for name in ("sentinelscan", "sentinelscan.fingerprinter",
                 "sentinelscan.profiler", "sentinelscan.detector",
                 "sentinelscan.api", "sentinelscan.capture"):
        logging.getLogger(name).setLevel(logging.WARNING)
    # Scapy's ipsec module uses deprecated cryptography.TripleDES.
    warnings.filterwarnings(
        "ignore",
        message="TripleDES has been moved",
        category=DeprecationWarning,
        module="scapy.layers.ipsec",
    )


def pytest_collection_modifyitems(config, items):  # noqa: ARG001
    """Allow running tests from the project root with ``pytest``."""
    return None


def pytest_sessionstart(session):  # noqa: D401, ARG001
    """Suppress PytestUnraisableExceptionWarning inside the active
    ``catch_warnings`` context (pytest_configure entered one that lives
    until cleanup)."""
    warnings.simplefilter("ignore", pytest.PytestUnraisableExceptionWarning)


@pytest.hookimpl(tryfirst=True)
def pytest_unconfigure(config):  # noqa: ARG001
    """Dispose of any lingering database engines before pytest's
    unraisable-exception handler runs its GC sweep."""
    try:
        from backend import database as db
        db.close_db()
    except Exception:
        pass

