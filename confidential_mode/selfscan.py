"""Which tool calls reach the plugin's own command line, package or state files (Amendment 9, item 2).

The self-approval guard (gate_tools step 0, Amendment 7) refuses, while locked, a terminal, process_manage
or execute_code call that would run the confidential command, import this package, or write one of the
plugin's state files, and a write_file or patch call that targets a state file. This module decides that
from the literal text of the call, so text that only mentions the word or a path is not refused.
docs/LIMITATIONS.md section 15 lists the forms; this docstring is the same list.

Shell text (terminal ``command``, process_manage ``data``). Before splitting: a backslash-newline is
joined, bash's ``$'...'`` quoting is expanded, heredoc bodies are cut out, and each ``$(...)``, backtick
and ``<(...)``/``>(...)`` substitution is scanned on its own and replaced by one placeholder word. The text
is then split with ``shlex`` into simple commands at ``;``, ``&&``, ``||``, ``|``, ``&``, parentheses and
line ends. Refused:

- a word whose basename is ``hermes`` (or ``hermes.exe``), or a Python interpreter with ``-m
  hermes_cli.main``, ``-m hermes_cli`` or ``-m runpy hermes_cli.main``, followed later in the same simple
  command by ``confidential`` or a word starting with ``/confidential``, unless the command is a text tool
  (echo, grep, cat and the rest of ``TEXT_COMMANDS``). This covers wrappers and launchers (sudo, env, uv
  run, find -exec, ssh, screen, tmux, watch, parallel, ...);
- ``xargs`` or ``parallel`` running hermes in a pipeline where another command prints ``confidential``;
- a command whose first argument is ``confidential`` and whose second is one of ``CLI_VERBS`` (an alias, a
  renamed copy of hermes, or a substitution such as ``$(which hermes)``), unless the program is a text
  tool or a known build or package tool (``OTHER_PROGRAMS``: make, npm, ...);
- a line typed as the slash command ``/confidential`` (top level, heredocs and piped shells);
- a Python invocation (``python -c``, ``python -m confidential_mode...``, a script file that exists or
  that an earlier command of the same call writes, a heredoc, a here-string, or the words piped into it)
  whose code ``python_reason`` refuses;
- a shell started with ``-c`` (including combined flags such as ``-lc``), ``eval``, or a shell reading a
  pipe, a heredoc or a script that an earlier command of the same call writes, whose text holds one of
  the forms above;
- a write to a state file or into the plugin's data directory: a redirection or ``tee`` target; the
  destination of cp, mv, install, rsync and ln (``-t DIR`` included; a source is a read, except for mv);
  any word, or the value of a ``key=value`` word (``dd of=``), of another command that is not read-only;
  a ``w`` file in a sed or awk script. Read-only are the text tools, ``jq``/``yq``, ``sqlite3 -readonly``,
  sed and perl without ``-i``, and the git subcommands that only read (log, diff, show, status, ...).

A state file is ``pins.yaml``, ``ledger.sqlite``, ``allowlist.yaml`` or ``grants_revoked.json`` (with their
lock, journal and backup siblings; Amendment 10 adds the last and the ``.lock`` files of the revoke path), or ``state.json`` inside a ``plugin-data`` directory; a glob that could match one counts.
A state path counts when it is relative (the working directory is not known here), lies inside a
``plugin-data`` directory, or lies inside the Hermes home outside this plugin's source tree. The plugin's
data directory is a ``plugin-data`` directory whose next segment names confidential mode (or a glob), or
the bare ``plugin-data`` directory.

Python code (execute_code ``code``, ``python -c``): imports of ``confidential_mode`` outside string
literals and comments, ``import_module``/``__import__``/``spec_from_file_location``/``run_path``/
``run_module`` naming it, ``hermes_cli`` imported or run (``run_module``) with a literal ``confidential``;
when the code starts processes, a literal list with ``hermes`` then ``confidential``, or a literal that
``shell_reason`` refuses; when the code writes, moves or deletes files (an ``open`` mode with w, a, x or
+, ``write_text``, ``unlink``, ``shutil``, a ``sqlite3`` connection not opened with ``mode=ro``, ...), a
literal naming a state file or the data directory. Code that only reads a state file passes.

Not detectable: a command assembled at run time (variables, ``eval`` of a computed string, base64, brace
expansion), a script that imports the package indirectly, a symlink or directory made in an earlier call,
and a command split across several process_manage writes.
"""
from __future__ import annotations

import fnmatch
import io
import os
import re
import shlex
import tokenize
from pathlib import Path
from typing import Iterable, Optional

PLUGIN_SOURCE_ROOT = Path(__file__).resolve().parents[1]

CLI_VERBS = frozenset({"pins", "allow", "off", "on", "lock", "unlock", "setup", "approve", "retire", "status",
                       "check", "receipts", "replay"})
# Commands that print or search text. Their arguments are data, so the CLI rules and the state-file
# rule do not apply to them (a redirection still does). sed is here only without -i or a w command.
TEXT_COMMANDS = frozenset({"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "cat", "bat", "less",
                           "more", "head", "tail", "sed", "ls", "wc", "man", "which", "type", "whereis",
                           "file", "stat", "diff", "cmp", "sha256sum", "shasum", "md5sum", "md5", "od", "xxd",
                           "hexdump", "strings", "tree", "du", "realpath", "readlink", "basename", "dirname",
                           "jq", "yq", "awk", "gawk", "nl", "sort", "uniq", "cut", "column", "fold", "tr"})
# Build and package tools whose first argument is a target or a script name, never a hermes alias.
OTHER_PROGRAMS = frozenset({"make", "gmake", "npm", "npx", "yarn", "pnpm", "bun", "just", "cargo", "go", "gradle",
                            "mvn", "rake", "task", "pytest", "tox", "nox", "poe", "git", "gh", "docker", "kubectl"})
READ_ONLY_GIT = frozenset({"log", "diff", "show", "status", "blame", "grep", "ls-files", "cat-file", "rev-parse",
                           "describe", "shortlog", "whatchanged", "ls-tree", "branch", "tag"})
COPY_COMMANDS = frozenset({"cp", "mv", "install", "rsync", "ln", "scp"})
SCRIPT_INTERPRETERS = frozenset({"perl", "ruby", "node", "deno", "php", "lua", "tclsh", "rscript", "osascript"})
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "mksh", "busybox"})
WRAPPERS = frozenset({"sudo", "doas", "env", "exec", "command", "builtin", "nohup", "time", "nice", "ionice",
                      "timeout", "stdbuf", "xargs", "caffeinate", "unbuffer", "watch", "script", "strace", "uv",
                      "uvx", "run", "pipx", "poetry", "pdm", "hatch", "rye", "npx", "chronic", "flock", "setsid",
                      "arch", "then", "do", "else", "if", "while", "until"})
SUBST = "__confidential_mode_substitution__"
_RE_PYTHON = re.compile(r"^(python|pypy)(\d+(\.\d+)*)?(\.exe)?$")
_STATE_NAMES = re.compile(r"^(pins\.yaml(\.lock|\.v2\.bak)?|ledger\.sqlite(-wal|-shm|-journal)?|allowlist\.yaml(\.lock)?"
                          r"|grants_revoked\.json(\.lock)?)$")   # Amendment 10: the revoke files and their locks
_STATE_PLAIN = ("pins.yaml", "pins.yaml.lock", "pins.yaml.v2.bak", "ledger.sqlite", "ledger.sqlite-wal",
                "ledger.sqlite-shm", "ledger.sqlite-journal", "allowlist.yaml", "allowlist.yaml.lock",
                "grants_revoked.json", "grants_revoked.json.lock")
_SEPARATORS = frozenset({";", "&&", "||", "|", "&", "|&", "\n", "(", ")", ";;", ";&", "!", "{", "}"})
_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", "<>", ">&"})
_RE_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_RE_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_RE_PY_IMPORT = re.compile(r"\b(?:from|import)\s+(?:[\w.]+(?:\s+as\s+\w+)?\s*,\s*)*[\w.]*\bconfidential_mode\b")
_RE_PY_DYN_IMPORT = re.compile(r"(?:import_module|__import__|spec_from_file_location|run_path|run_module)\s*\("
                               r"[^)]*confidential_mode")
_RE_PY_HERMES_CLI = re.compile(r"\b(?:from\s+hermes_cli\b|import\s+(?:[\w.]+(?:\s+as\s+\w+)?\s*,\s*)*hermes_cli\b)")
_RE_PY_RUNS = re.compile(r"\b(?:subprocess|os\.system|os\.popen|os\.exec\w*|os\.spawn\w*|os\.posix_spawn\w*|pty\.spawn"
                         r"|create_subprocess_\w+|pexpect|plumbum|sh\.Command|commands\.getoutput)\b")
_RE_PY_FILES = re.compile(r"\b(?:open|sqlite3|Path|PurePath|shutil|os\.(?:remove|unlink|rename|replace|truncate|"
                          r"link|symlink)|write_text|write_bytes|unlink|io\.open|codecs\.open|fileinput)\b")
_RE_PY_LITERAL = re.compile(r"(?:[rRbBuUfF]{0,2})('''(?:.|\n)*?'''|\"\"\"(?:.|\n)*?\"\"\"|'(?:[^'\\\n]|\\.)*'"
                            r"|\"(?:[^\"\\\n]|\\.)*\")")
_RE_SED_W = re.compile(r"(?:^|[;{}\s/])[wW]\s*(\S+)")
_MAX_DEPTH = 4
_MAX_SCRIPT_BYTES = 1_000_000


def _ansi_c_text(text: str) -> str:
    """$'\\x63onfidential' -> confidential (the decoded text, unquoted)."""
    def dec(m: "re.Match") -> str:
        try:
            return m.group(1).encode("latin-1", "backslashreplace").decode("unicode_escape")
        except Exception:  # noqa: BLE001
            return m.group(0)
    return _RE_ANSI_C.sub(dec, text)


def _ansi_c_quoted(text: str) -> str:
    """$'...' -> '...' with the escapes decoded, so shlex sees one single-quoted word."""
    def dec(m: "re.Match") -> str:
        try:
            body = m.group(1).encode("latin-1", "backslashreplace").decode("unicode_escape")
        except Exception:  # noqa: BLE001
            return m.group(0)
        return "'" + body.replace("'", "'\\''") + "'"
    return _RE_ANSI_C.sub(dec, text).replace('$"', '"')


def _base(word: str) -> str:
    b = word.rstrip("/").rsplit("/", 1)[-1].casefold()
    return b[:-4] if b.endswith(".exe") else b


def _segs(p: str) -> list[str]:
    return [s for s in p.replace("\\", "/").split("/") if s]


def _glob_could_be_state(name: str) -> bool:
    return any(c in name for c in "*?[") and any(fnmatch.fnmatchcase(n, name) for n in _STATE_PLAIN)


def is_state_path(path: str) -> bool:
    """Whether ``path`` names one of the plugin's state files where the plugin keeps them, or may."""
    p = (path or "").strip()
    if not p:
        return False
    name = _base(p)
    segs = _segs(p)
    if name == "state.json" or (any(c in name for c in "*?[") and fnmatch.fnmatchcase("state.json", name)):
        if "plugin-data" in segs:
            return True
    if not (_STATE_NAMES.match(name) or _glob_could_be_state(name)):
        return False
    if not (p.startswith("/") or p.startswith("~") or p.startswith("$")):
        return True                      # relative: the working directory is not known here
    if "plugin-data" in segs or p.startswith("$"):
        return True
    full = Path(os.path.expanduser(p))
    try:
        full = full.resolve(strict=False)
    except Exception:  # noqa: BLE001
        pass
    if _under(full, PLUGIN_SOURCE_ROOT):
        return False
    home = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
    try:
        return _under(full, Path(home).expanduser().resolve(strict=False))
    except Exception:  # noqa: BLE001
        return True


def in_plugin_data(path: str) -> bool:
    """Whether ``path`` lies in this plugin's data directory (or is the bare plugin-data directory)."""
    segs = _segs(path or "")
    if "plugin-data" not in segs:
        return False
    i = segs.index("plugin-data")
    if i + 1 >= len(segs):
        return True
    nxt = segs[i + 1].casefold()
    return "confidential" in nxt or any(c in nxt for c in "*?[") or nxt.startswith("$")


def _writes(word: str) -> bool:
    """A word, or a key=value word's value, that names a state file or the plugin's data directory."""
    vals = [word]
    if "=" in word:
        vals.append(word.split("=", 1)[1])
    return any(is_state_path(v) or in_plugin_data(v) for v in vals)


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _heredocs(text: str) -> tuple[str, list[tuple[int, str]]]:
    """Cut heredoc bodies out of ``text``. Returns the text without them and (line index, body) pairs, the
    line index naming the line that opened the heredoc."""
    lines = text.split("\n")
    out, bodies, i = [], [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        opened = list(_RE_HEREDOC.finditer(line))
        i += 1
        for m in opened:
            delim, body = m.group(2), []
            while i < len(lines) and lines[i].strip() != delim:
                body.append(lines[i])
                i += 1
            i += 1                       # the delimiter line
            bodies.append((len(out) - 1, "\n".join(body)))
    return "\n".join(out), bodies


def _substitute(text: str) -> tuple[str, list[str]]:
    """Each $(...), <(...), >(...) and `...` cut out: (text with one SUBST word in each place, the inner
    texts). Inner substitutions are found when an inner text is scanned. $((...)) arithmetic is kept."""
    inners, out, i, n = [], [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "`":
            j = text.find("`", i + 1)
            if j < 0:
                out.append(text[i:])
                break
            inners.append(text[i + 1:j])
            out.append(f" {SUBST} ")
            i = j + 1
            continue
        if c in "$<>" and i + 1 < n and text[i + 1] == "(" and not (c == "$" and text[i + 2:i + 3] == "("):
            depth, j = 0, i + 1
            while j < n:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            inners.append(text[i + 2:j])
            out.append(f" {SUBST} ")
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out), inners


def _tokens(text: str) -> list[str]:
    lex = shlex.shlex(text, posix=True, punctuation_chars=";&|<>()\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = "#"
    try:
        return list(lex)
    except ValueError:                   # an unbalanced quote: fall back to a plain split, fail closed
        crude = re.sub(r"['\"\\`]", "", text)
        return re.findall(r"[;&|<>()\n]+|[^\s;&|<>()]+", crude)


def _commands(tokens: list[str]) -> list[tuple[list[str], list[str], list[str]]]:
    """Split tokens into simple commands: (words, redirection targets, here-strings)."""
    out, words, targets, here, i = [], [], [], [], 0
    while i < len(tokens):
        t = tokens[i]
        if t in _SEPARATORS or (set(t) <= set(";&|()\n") and t not in _REDIRECTS):
            if words or targets or here:
                out.append((words, targets, here))
            words, targets, here = [], [], []
        elif t in _REDIRECTS or t.startswith(">") or t.startswith("&>") or t.startswith("<"):
            if i + 1 < len(tokens):
                if t == "<<<":
                    here.append(tokens[i + 1])
                elif t not in ("<", "<<", "<&") and not t.startswith("<<"):
                    targets.append(tokens[i + 1])
            i += 1
        else:
            words.append(t)
        i += 1
    if words or targets or here:
        out.append((words, targets, here))
    return out


def _strip_assignments(words: list[str]) -> list[str]:
    i = 0
    while i < len(words) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[i]):
        i += 1
    return words[i:]


def _command_position(words: list[str], i: int) -> bool:
    """Whether words[i] is the program a command runs: only wrappers (sudo, env, uv run, ...), their
    options and option values, and assignments come before it."""
    prev_opt = False
    for w in words[:i]:
        if _base(w) in WRAPPERS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            prev_opt = False
        elif w.startswith("-"):
            prev_opt = "=" not in w
        elif prev_opt or re.fullmatch(r"[\d.]+[smhd]?", w):
            prev_opt = False               # an option's value (-u NAME, timeout 5, nice -n 10)
        else:
            return False
    return True


def _program_index(words: list[str], test) -> Optional[int]:
    """The index of the first word in command position whose basename passes ``test``."""
    for i, w in enumerate(words):
        if test(_base(w)) and _command_position(words, i):
            return i
    return None


def _is_conf(word: str) -> bool:
    a = word.casefold()
    return a == "confidential" or a.startswith("/confidential")


def _hermes_invocation(words: list[str]) -> bool:
    """A hermes word, or python -m hermes_cli(.main) / -m runpy hermes_cli.main, anywhere in the simple
    command, followed later by the confidential subcommand (launchers such as find -exec, ssh, screen and
    parallel put hermes anywhere in their argument vector)."""
    for i, w in enumerate(words):
        start = None
        b = _base(w)
        if b == "hermes":
            start = i + 1
        elif _RE_PYTHON.match(b):
            for j in range(i + 1, len(words) - 1):
                if words[j] == "-m":
                    mod, nxt = words[j + 1], j + 2
                    if mod == "runpy" and j + 2 < len(words):
                        mod, nxt = words[j + 2], j + 3
                    if mod in ("hermes_cli.main", "hermes_cli"):
                        start = nxt
                    break
        if start is not None and any(_is_conf(a) for a in words[start:]):
            return True
    return False


def _alias_invocation(words: list[str]) -> bool:
    if len(words) < 3:
        return False
    b = _base(words[0])
    return (b not in TEXT_COMMANDS and b not in OTHER_PROGRAMS and words[1].casefold() == "confidential"
            and words[2].casefold() in CLI_VERBS)


def _slash_line(text: str) -> bool:
    return any(re.match(r"^\s*/confidential(\s|$)", line, re.IGNORECASE) for line in text.split("\n"))


def _read_script(word: str) -> Optional[str]:
    for base in (os.environ.get("TERMINAL_CWD") or "", os.getcwd()):
        try:
            p = Path(os.path.expanduser(word))
            if not p.is_absolute():
                if not base:
                    continue
                p = Path(base) / p
            if p.is_file() and p.stat().st_size <= _MAX_SCRIPT_BYTES:
                return p.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
    return None


def _script_arg(words: list[str], k: int) -> Optional[str]:
    """The script a python or shell command at words[k] runs (its first non-option argument), or None."""
    for w in words[k + 1:]:
        if w in ("-c", "-m", "-") or re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", w):
            return None
        if w.startswith("-"):
            continue
        return w
    return None


def _python_command_reason(words: list[str], stdin_code: list[str], written: dict, depth: int) -> Optional[str]:
    """``words`` starts with a Python interpreter."""
    i = 1
    while i < len(words):
        w = words[i]
        if w == "-c" and i + 1 < len(words):
            code = words[i + 1]
            if (_RE_PY_HERMES_CLI.search(_code_only(code)) or re.search(r"run_module\s*\(\s*['\"]hermes_cli", code)) \
                    and any(_is_conf(a) for a in words[i + 2:]):
                return "runs hermes with its confidential command"     # python -c '...hermes_cli...' confidential
            return python_reason(code, depth + 1)
        if w == "-m" and i + 1 < len(words):
            mod = words[i + 1]
            if mod == "runpy" and i + 2 < len(words):
                mod = words[i + 2]
            if mod == "confidential_mode" or mod.startswith("confidential_mode.") or ".confidential_mode" in mod:
                return "runs the confidential_mode package"
            return None
        if w == "-":
            break
        if w.startswith("-"):
            i += 1
            continue
        if w in written:                 # a script an earlier command of this call writes
            return python_reason(written[w], depth + 1) or _loose_cli(written[w])
        text = _read_script(w)           # an interpreter running a script
        return python_reason(text, depth + 1) if text is not None else None
    for code in stdin_code:              # python reading a heredoc or a pipe
        why = python_reason(code, depth + 1)
        if why:
            return why
    return None


def _loose_cli(text: str) -> Optional[str]:
    """The CLI forms anywhere in text a shell will run as data (a pipe, a written script)."""
    loose = [t for t in _tokens(re.sub(r"['\"\\]", "", text)) if t not in _SEPARATORS]
    if _hermes_invocation(loose) or any(_alias_invocation(loose[i:]) for i in range(len(loose))) or _slash_line(text):
        return "pipes the confidential command into a shell"
    return None


def _read_only(words: list[str]) -> bool:
    cmd = _base(words[0])
    if cmd == "git":
        rest = words[1:]
        i = 0
        while i < len(rest) and rest[i].startswith("-"):
            i += 2 if rest[i] in ("-C", "-c", "--git-dir", "--work-tree") else 1
        return i < len(rest) and rest[i] in READ_ONLY_GIT
    if cmd == "sqlite3":
        return "-readonly" in words
    if cmd not in TEXT_COMMANDS:
        return False
    if cmd in ("sed", "perl") and any(w == "-i" or w.startswith("-i") or w.startswith("--in-place") for w in words[1:]):
        return False
    if cmd in ("awk", "gawk") and "-i" in words[1:]:
        return False
    return True


def _copy_reason(words: list[str]) -> Optional[str]:
    """cp, mv, install, rsync, ln, scp: the destination (last operand or -t DIR) is a write; a source is a
    read, except for mv (moving a state file away) and ln (a link to the data directory)."""
    cmd = _base(words[0])
    ops, target = [], None
    i = 1
    while i < len(words):
        w = words[i]
        if w in ("-t", "--target-directory") and i + 1 < len(words):
            target = words[i + 1]
            i += 2
            continue
        if w.startswith("--target-directory="):
            target = w.split("=", 1)[1]
        elif not w.startswith("-"):
            ops.append(w)
        i += 1
    dests = [target] if target is not None else ops[-1:]
    sources = ops if target is not None else ops[:-1]
    if any(_writes(d) for d in dests):
        return "writes a confidential-mode state file"
    if cmd in ("mv", "ln") and any(_writes(s) for s in sources):
        return "moves or links a confidential-mode state file"
    return None


def shell_reason(text: str, depth: int = 0, *, cli_only: bool = False) -> Optional[str]:
    """Why this shell text reaches the confidential command, the package or a state file, or None.
    ``cli_only`` checks only the command forms (for an argument that may be a command line)."""
    if not isinstance(text, str) or not text.strip() or depth > _MAX_DEPTH:
        return None
    text = text.replace("\\\r\n", "").replace("\\\n", "")        # line continuations
    if not cli_only and _slash_line(text):
        return "types the /confidential command"
    body, inners = _substitute(_ansi_c_quoted(text))
    for inner in inners:
        why = shell_reason(inner, depth + 1, cli_only=cli_only)
        if why:
            return why
    body, heredocs = _heredocs(body)
    written: dict[str, str] = {}         # file -> text written to it by an earlier command of this call
    stdin_shell = False
    for line_no, line in enumerate(body.split("\n")):
        line_docs = [b for n, b in heredocs if n == line_no]
        cmds = _commands(_tokens(line))
        line_words = [w for c in cmds for w in c[0]]
        for idx, (raw_words, targets, here) in enumerate(cmds):
            words = _strip_assignments(raw_words)
            for t in ([] if cli_only else targets):
                if is_state_path(t) or in_plugin_data(t):
                    return "writes a confidential-mode state file"
            if not words:
                continue
            cmd = _base(words[0])
            if cmd not in TEXT_COMMANDS and _hermes_invocation(words):
                return "invokes hermes with its confidential command"
            if _alias_invocation(words):
                return "invokes the confidential command"
            if any(_base(w) in ("xargs", "parallel") for w in words) and any(_base(w) == "hermes" for w in words) \
                    and any(re.search(r"(?<![\w-])/?confidential(?![\w-])", w, re.IGNORECASE) for w in line_words):
                return "feeds the confidential command to hermes through xargs or parallel"
            prev = [w for c in cmds[:idx] for w in _strip_assignments(c[0])[1:]]
            k = _program_index(words, lambda b: bool(_RE_PYTHON.match(b)))
            if k is not None:
                stdin = list(line_docs) + list(here) + ([" ".join(prev)] if idx > 0 and prev else [])
                if idx > 0 and _base(cmds[idx - 1][0][0] if cmds[idx - 1][0] else "") == "cat":
                    stdin += [t for t in (_read_script(f) for f in cmds[idx - 1][0][1:] if not f.startswith("-"))
                              if t is not None]       # cat FILE | python
                why = _python_command_reason(words[k:], stdin, written, depth)
                if why:
                    return why
            if cmd in ("at", "batch") and not any(w == "-f" for w in words):
                stdin_shell = True       # at reads the commands it schedules from a pipe
            k = _program_index(words, lambda b: b in SHELLS or b in ("eval", "source", "."))
            if k is not None:
                sh, rest = _base(words[k]), words[k + 1:]
                if sh == "eval":
                    why = shell_reason(" ".join(rest), depth + 1)
                    if why:
                        return why
                flag = next((n for n, w in enumerate(rest) if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", w)), None)
                script = _script_arg(words, k)
                if flag is not None and flag + 1 < len(rest):
                    why = shell_reason(rest[flag + 1], depth + 1)
                    if why:
                        return why
                elif script is not None and script in written:
                    why = shell_reason(written[script], depth + 1) or _loose_cli(written[script])
                    if why:
                        return why
                elif sh in SHELLS and script is None:
                    stdin_shell = True   # reads a pipe or a heredoc
                for doc in list(line_docs) + list(here):
                    why = shell_reason(doc, depth + 1)
                    if why:
                        return why
            if not cli_only:
                if cmd == "tee" and any(_writes(w) for w in words[1:] if not w.startswith("-")):
                    return "writes a confidential-mode state file"
                if cmd in COPY_COMMANDS:
                    why = _copy_reason(words)
                    if why:
                        return why
                elif cmd in ("sed", "awk", "gawk") and any(
                        is_state_path(m.group(1)) or in_plugin_data(m.group(1))
                        for w in words[1:] for m in _RE_SED_W.finditer(w)):
                    return "writes a confidential-mode state file from a sed or awk script"
                elif any(_writes(w) for w in words[1:]) and not _read_only(words):
                    return "names a confidential-mode state file"
            if cmd in SCRIPT_INTERPRETERS:   # perl -e, ruby -e, node -e, ...: strings in the code may be argv
                for n, w in enumerate(words[1:-1], start=1):
                    if w in ("-e", "-E", "-r", "--eval", "-p"):
                        why = _loose_cli(re.sub(r"[,()\[\]{};]", " ", words[n + 1]))
                        if why:
                            return "runs hermes with its confidential command from inline code"
            for w in words[1:]:          # an argument that is itself a command line (ssh, tmux, script -c, ...)
                if " " in w and cmd not in TEXT_COMMANDS and cmd not in OTHER_PROGRAMS:
                    why = shell_reason(w, depth + 1, cli_only=True)
                    if why:
                        return why
            # Record what this command writes, for a later command of the same call that runs it.
            data = "\n".join(list(line_docs) + list(here)
                             + ([" ".join(words[1:])] if cmd in ("echo", "printf") else []))
            for t in targets:
                written[t] = data
    if stdin_shell:                      # the whole text, as data a shell will run
        why = _loose_cli(body)
        if why:
            return why
        for _n, doc in heredocs:
            why = shell_reason(doc, depth + 1)
            if why:
                return why
    return None


def _literals(code: str) -> list[str]:
    out = []
    for m in _RE_PY_LITERAL.finditer(code):
        lit = m.group(1)
        q = 3 if lit[:3] in ("'''", '"""') else 1
        out.append(lit[q:-q])
    return out


def _code_only(code: str) -> str:
    """The code with string literals and comments blanked out, positions kept (tokenize; a regex when the
    code does not tokenize)."""
    try:
        lines = code.splitlines(keepends=True)
        offs, total = [], 0
        for ln in lines:
            offs.append(total)
            total += len(ln)
        chars = list(code)
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            if tok.type in (tokenize.STRING, tokenize.COMMENT) or tok.type == getattr(tokenize, "FSTRING_MIDDLE", -1):
                a = offs[tok.start[0] - 1] + tok.start[1]
                b = offs[tok.end[0] - 1] + tok.end[1]
                for i in range(a, b):
                    if chars[i] != "\n":
                        chars[i] = " "
        return "".join(chars)
    except Exception:  # noqa: BLE001
        return re.sub(r"#[^\n]*", " ", _RE_PY_LITERAL.sub(" ", code))


_RE_PY_WRITE_CALLS = re.compile(r"\b(?:write_text|write_bytes|unlink|touch|rmtree|os\.(?:remove|unlink|rename|replace|"
                                r"truncate|link|symlink|makedirs|mkdir)|shutil\.\w+|sqlite3\.connect|fileinput)\b")
_RE_PY_OPEN_WRITE = re.compile(r"\bopen\s*\([^)]*,\s*(?:mode\s*=\s*)?['\"][rbt]*[wax+]")


def _py_writes(code: str, bare: str) -> bool:
    """Whether the code writes, moves or deletes files (an open() mode with w, a, x or +, write_text,
    unlink, shutil, a sqlite3 connection not opened read-only, ...). Reading a state file is allowed."""
    if _RE_PY_OPEN_WRITE.search(code):
        return True
    m = _RE_PY_WRITE_CALLS.findall(bare)
    if not m:
        return False
    if all(x == "sqlite3.connect" for x in m) and re.search(r"mode=ro\b", code):
        return False
    return True


def python_reason(code: str, depth: int = 0) -> Optional[str]:
    """Why this Python code imports the package, runs the confidential command or names a state file."""
    if not isinstance(code, str) or not code.strip() or depth > _MAX_DEPTH:
        return None
    code = _ansi_c_text(code)
    bare = _code_only(code)
    if _RE_PY_IMPORT.search(bare) or _RE_PY_DYN_IMPORT.search(code):
        return "imports the confidential_mode package"
    lits = _literals(code)
    folded = [x.casefold() for x in lits]
    if (_RE_PY_HERMES_CLI.search(bare) or re.search(r"run_module\s*\(\s*['\"]hermes_cli", code)) and \
            any(_is_conf(x) for x in folded):
        return "runs hermes with its confidential command"
    if _RE_PY_RUNS.search(bare):         # the code starts processes: its strings may be command lines
        for n, lit in enumerate(folded):
            if (_base(lit) == "hermes" or lit in ("hermes_cli.main", "hermes_cli")) and \
                    any(_is_conf(x) for x in folded[n + 1:]):
                return "runs hermes with its confidential command"
        for lit in lits:
            if any(c in lit for c in " ;|&\n") and len(lit) < 20_000:
                why = shell_reason(lit, depth + 1)
                if why:
                    return why
    if _RE_PY_FILES.search(bare) and _py_writes(code, bare):   # writes files: a state-file path is a target
        for lit in lits:
            if is_state_path(lit) or in_plugin_data(lit):
                return "writes a confidential-mode state file"
    return None


def file_tool_paths(args) -> Iterable[str]:
    """The paths a write_file or patch call writes: ``path`` and, for a V4A patch, every file it names."""
    if not isinstance(args, dict):
        return
    p = args.get("path")
    if isinstance(p, str):
        yield p
    patch = args.get("patch")
    if isinstance(patch, str):
        for m in re.finditer(r"^\*\*\*\s*(?:Update|Add|Delete) File:\s*(.+?)\s*$|^\*\*\*\s*Move to:\s*(.+?)\s*$",
                             patch, re.MULTILINE):
            yield m.group(1) or m.group(2)


def file_tool_reason(args) -> Optional[str]:
    if any(is_state_path(p) or in_plugin_data(p) for p in file_tool_paths(args)):
        return "targets a confidential-mode state file"
    return None
