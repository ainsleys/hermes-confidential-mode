"""Seam tests import Hermes from the pinned checkout at ~/hermes-agent (commit 84a0301).

Run from inside that checkout so its uv environment is used:
    cd ~/hermes-agent && HERMES_HOME=<temp> uv run pytest ~/hermes-confidential-mode/tests
"""
import os
import sys
from pathlib import Path

HERMES_ROOT = Path(os.environ.get("HERMES_AGENT_ROOT", Path.home() / "hermes-agent"))
if str(HERMES_ROOT) not in sys.path:
    sys.path.insert(0, str(HERMES_ROOT))
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(PLUGIN_ROOT), str(PLUGIN_ROOT.parent)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
