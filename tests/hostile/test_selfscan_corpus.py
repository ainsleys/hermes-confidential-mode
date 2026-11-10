"""The adversarial review's tool-gate corpus (Amendment 9, second pass): literal forms the scan refuses,
and mentions it lets through. A command assembled at run time is out of scope and listed in
LIMITATIONS 15 ("Not detectable")."""
from __future__ import annotations

import pytest

from confidential_mode import selfscan as s

PD = "/h/.hermes/plugin-data/confidential-mode"

REFUSED_SHELL = [
    "hermes \\\nconfidential pins approve",                       # line continuation
    "hermes confidential \\\npins approve",
    "cat <(hermes confidential pins approve)",                   # process substitution
    "$(which hermes) confidential pins approve",                 # program by substitution
    "`which hermes` confidential off",
    "find . -maxdepth 0 -exec hermes confidential pins approve ';'",
    "find /tmp -name x -exec hermes confidential pins approve {} +",
    "ssh localhost hermes confidential pins approve",
    "screen -dm hermes confidential pins approve",
    "tmux new -d 'hermes confidential pins approve'",
    "parallel hermes ::: confidential",
    "echo confidential pins approve | xargs hermes",            # xargs from stdin
    "printf 'confidential\\npins\\napprove' | xargs hermes",
    "echo 'hermes confidential pins approve' | at now",
    "ruby -e 'system(\"hermes\", \"confidential\", \"pins\", \"approve\")'",
    "perl -e 'exec \"hermes\", \"confidential\", \"pins\", \"approve\"'",
    "python3 -m runpy hermes_cli.main confidential pins approve",
    "python3 -I -m hermes_cli.main confidential pins approve",
    "python3 -c \"import sys,hermes_cli.main as m; sys.argv=['x','confidential','pins','approve']; m.main()\"",
    "python3 -c \"import runpy; runpy.run_module('hermes_cli.main', run_name='__main__')\" confidential",
    "echo 'import confidential_mode.consent' > /tmp/zz_x.py && python3 /tmp/zz_x.py",   # write then run
    "printf 'hermes confidential pins approve\\n' > /tmp/zz_x.sh; bash /tmp/zz_x.sh",
    f"cp /tmp/pins.yaml {PD}/",                                   # directory targets
    f"cp -t {PD} /tmp/pins.yaml",
    f"tar -xf /tmp/x.tar -C {PD}",
    f"unzip -o /tmp/x.zip -d {PD}",
    f"ln -s {PD} /tmp/d && cp /tmp/x /tmp/d/pins.yaml",            # symlink in the same call
    f"cp /tmp/x {PD}/pins.*",                                      # globs
    f"cat /tmp/x > {PD}/pins.ya?l",
    f"cd {PD} && dd if=/tmp/x of=pins.yaml",                       # dd of=
    f"dd if=/tmp/x of={PD}/ledger.sqlite",
    f"sed -n 'w {PD}/pins.yaml' /tmp/x",                           # sed w
    f"git config -f {PD}/pins.yaml a.b c",                         # git writes
    f"git -C {PD} checkout pins.yaml",
    f"mv {PD}/ledger.sqlite /tmp/",
    f"rm {PD}/ledger.sqlite",
    f"echo x | tee -a {PD}/pins.yaml",
    "env -u XDG_CONFIDENTIAL_MODE_TOOL_PROCESS hermes \\\nconfidential pins approve",
]

ALLOWED_SHELL = [
    "awk '/confidential on/' notes.txt",
    "make confidential status",
    "make confidential on",
    "npm run confidential on",
    f"cp {PD}/pins.yaml /tmp/backup.yaml",
    f"jq . {PD}/pins.yaml",
    f"sqlite3 -readonly {PD}/ledger.sqlite 'select count(*) from events'",
    f"cat {PD}/pins.yaml",
    f"git -C {PD} log --oneline",
    'grep "confidential off" docs/README.md',
    "echo 'mark confidential on purpose'",
    "git diff confidential_mode/",
    "git commit -m 'hermes confidential pins approve docs'",
    "pytest tests/ -q -k confidential",
    "python3 -m pytest tests/test_confidential_on.py",
    "python3 -c \"print('hermes confidential off')\"",
    "vim docs/confidential.md",
    "ls pins.yaml",
    "echo $((1 + 2))",
]

REFUSED_PY = [
    "import subprocess; subprocess.run(['hermes','confidential','pins','approve'])",
    "import os\nos.system('hermes confidential pins approve')",
    "import runpy, sys; sys.argv=['hermes','confidential','pins','approve']; runpy.run_module('hermes_cli.main')",
    "import sys, hermes_cli.main as m; m.main(['confidential', 'off'])",
    "import plugins.confidential_mode",
    f"open('{PD}/pins.yaml', 'w').write('x')",
    f"from pathlib import Path\nPath('{PD}/pins.yaml').write_text('x')",
    f"import sqlite3\nsqlite3.connect('{PD}/ledger.sqlite').execute('delete from events')",
    f"import os\nos.remove('{PD}/ledger.sqlite')",
]

ALLOWED_PY = [
    "print('import confidential_mode')",
    "# confidential_mode is great\nprint(1)",
    "x = 'from confidential_mode import pins'  # a string, not an import\nprint(x)",
    f"print(open('{PD}/pins.yaml').read())",
    f"from pathlib import Path\nprint(Path('{PD}/pins.yaml').read_text())",
    f"import sqlite3\nsqlite3.connect('file:{PD}/ledger.sqlite?mode=ro', uri=True)",
]


@pytest.fixture(autouse=True)
def _home(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))


@pytest.mark.parametrize("cmd", REFUSED_SHELL)
def test_literal_forms_are_refused(cmd):
    assert s.shell_reason(cmd), cmd


@pytest.mark.parametrize("cmd", ALLOWED_SHELL)
def test_mentions_are_allowed(cmd):
    assert s.shell_reason(cmd) is None, (cmd, s.shell_reason(cmd))


@pytest.mark.parametrize("code", REFUSED_PY)
def test_python_forms_are_refused(code):
    assert s.python_reason(code), code


@pytest.mark.parametrize("code", ALLOWED_PY)
def test_python_mentions_are_allowed(code):
    assert s.python_reason(code) is None, code


def test_write_file_into_the_data_directory_is_refused():
    assert s.file_tool_reason({"path": f"{PD}/evidence/blobs/abc", "content": "x"})
    assert s.file_tool_reason({"path": "/Users/x/hermes-confidential-mode/docs/README.md", "content": "x"}) is None


# Amendment 10: the revoke path's state files and every state-file lock. Holding or replacing a lock file
# could stall a revoke (filelock bounds the wait, and the revoke then fails), so a write to one is refused.
REVOKE_STATE = ["allowlist.yaml.lock", "grants_revoked.json", "grants_revoked.json.lock", "pins.yaml.lock"]


@pytest.mark.parametrize("name", REVOKE_STATE)
@pytest.mark.parametrize("form", ["echo x > {p}", "touch {p}", "cp /tmp/x {p}", "flock {p} sleep 999",
                                  "tee {p} < /dev/null"])
def test_writes_to_revoke_state_files_are_refused(name, form):
    assert s.shell_reason(form.format(p=f"{PD}/{name}")), (name, form)


@pytest.mark.parametrize("name", REVOKE_STATE)
def test_file_tools_and_python_writes_to_revoke_state_files_are_refused(name):
    assert s.file_tool_reason({"path": f"{PD}/{name}", "content": "x"}), name
    assert s.python_reason(f"open('{PD}/{name}', 'w').write('x')"), name


@pytest.mark.parametrize("name", REVOKE_STATE)
def test_reading_a_revoke_state_file_is_allowed(name):
    assert s.shell_reason(f"cat {PD}/{name}") is None, name


def test_revoke_from_a_tool_is_refused_while_locked():
    # README (Amendment 10): revoke runs from a terminal the person opened, or from chat.
    assert s.shell_reason("hermes confidential revoke web_search")
    assert s.shell_reason("hermes confidential revoke --all")


def test_revoke_through_the_short_alias_is_refused_while_locked():
    # Issue #63: the alias form is decided by CLI_VERBS, which had no ``revoke``, so ``h confidential
    # revoke`` was not refused while ``hermes confidential revoke`` was.
    assert s.shell_reason("h confidential revoke web_search")
    assert s.shell_reason("h confidential revoke --all")
    assert s.shell_reason("/opt/hermes/bin/h confidential revoke web_search")      # an alias by any path


@pytest.mark.parametrize("verb", sorted(s.CLI_VERBS))
def test_every_cli_verb_through_the_short_alias_is_refused(verb):
    # The alias form keys on this set, so every verb it may be called with must be in it (issue #63).
    assert s.shell_reason(f"h confidential {verb}")
