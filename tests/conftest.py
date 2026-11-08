"""Seam tests import Hermes from the pinned checkout (commit 84a0301): ``$HERMES_AGENT_ROOT`` when set, else
whatever Hermes the running environment imports.

Run from inside that checkout so its uv environment is used:
    cd <hermes checkout> && HERMES_HOME=<temp> uv run pytest <plugin checkout>/tests
"""
import os
import sys
from pathlib import Path

_root = os.environ.get("HERMES_AGENT_ROOT")
if _root and Path(_root).is_dir() and _root not in sys.path:
    sys.path.insert(0, _root)
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(PLUGIN_ROOT), str(PLUGIN_ROOT.parent)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest  # noqa: E402

# The tool hooks set this marker in the process environment (gate_tools.mark_tool_process), and
# TerminalAsker refuses while it is set. Every test starts and ends without it.
_TOOL_PROCESS_ENV = "XDG_CONFIDENTIAL_MODE_TOOL_PROCESS"


@pytest.fixture(autouse=True)
def _no_tool_process_marker():
    os.environ.pop(_TOOL_PROCESS_ENV, None)
    yield
    os.environ.pop(_TOOL_PROCESS_ENV, None)


# No test fetches from GitHub: staging and `pins review` see a fetch failure unless the test injects texts.
os.environ["CONFIDENTIAL_MODE_NO_FETCH"] = "1"
