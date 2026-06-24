"""Top-level entry point.

Run with::

    python run.py
"""

import sys
from pathlib import Path

# Make sure the local ``backend`` package is importable.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.app import main  # noqa: E402

if __name__ == "__main__":
    main()
