from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("DWITP_AUDIT_LOG", "/tmp/test_audit.log")  # noqa: S108
os.environ.setdefault("AUDIT_ENCRYPTION_KEY", "3JdjZ9eqAsdkEwnQMWInTEc6ug_V_MI5khNPwNpfSns=")

SRC_DIR = str(Path(__file__).resolve().parents[1] / "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
