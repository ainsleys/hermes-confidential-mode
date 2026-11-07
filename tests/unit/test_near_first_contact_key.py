"""scripts/near_first_contact.py reads NEAR_AI_API_KEY the way its docstring says: Hermes' env-file loader for
HERMES_HOME, then agent.secret_scope.get_secret (catalog rule 11). No network."""
import importlib.util
import os
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "near_first_contact.py"


def _script():
    spec = importlib.util.spec_from_file_location("near_first_contact_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_key_comes_from_the_env_file_of_hermes_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".env").write_text("NEAR_AI_API_KEY=from-the-env-file\n")
    saved = dict(os.environ)
    try:
        os.environ.pop("NEAR_AI_API_KEY", None)
        os.environ["HERMES_HOME"] = str(home)
        assert _script()._near_key() == "from-the-env-file"
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_no_env_file_and_no_export_reads_as_not_set(tmp_path):
    home = tmp_path / "empty"
    home.mkdir()
    saved = dict(os.environ)
    try:
        os.environ.pop("NEAR_AI_API_KEY", None)
        os.environ["HERMES_HOME"] = str(home)
        assert _script()._near_key() == ""
    finally:
        os.environ.clear()
        os.environ.update(saved)
