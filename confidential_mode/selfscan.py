"""Which tool calls reach the plugin's own command line, package or state files (Amendment 9, item 2).

The self-approval guard (gate_tools step 0, Amendment 7) refuses, while locked, a terminal, process_manage
or execute_code call that would run the confidential command, import this package, or write one of the
plugin's state files, and a write_file or patch call that targets a state file. This module decides that
from real command forms, so text that only mentions the word or a path is not refused.

Shell text (terminal ``command``, process_manage ``data``) is split into simple commands with ``shlex``
after bash's ``$'...'`` quoting is expanded. A simple command ends at ``;``, ``&&``, ``||``, ``|``, ``&``,
a parenthesis or a newline. Refused:

- a ``hermes`` executable (by name or by path), or ``python -m hermes_cli.main``, with a later argument
  ``confidential`` or one starting with ``/confidential``;
- a command whose first argument is ``confidential`` and whose second is one of the CLI verbs (an alias
  or a renamed copy of hermes), unless the command is a text tool such as echo or grep;
- a line typed as the slash command ``/confidential``;
- a Python invocation (``python -c``, ``python -m confidential_mode...``, a script file that can be read,
  or Python reading a heredoc or a pipe) whose code imports ``confidential_mode`` or runs the forms above;
- a shell started with ``-c``, a command substitution, or a shell reading a pipe or a heredoc, whose text
  holds one of the forms above;
- a redirection or ``tee`` into a state file, and any command other than a read-only one (cat, grep,
  head, ls, sed without ``-i`` and similar) that names a state file.

A state file is ``pins.yaml``, ``ledger.sqlite`` or ``allowlist.yaml`` (with their lock, journal and
backup siblings), or ``state.json`` inside a ``plugin-data`` directory. A path counts when it is
relative (the working directory is not known here), lies inside a ``plugin-data`` directory, or lies
inside the Hermes home outside this plugin's source tree.

Not detectable: a command assembled at run time (variables, ``eval`` of a computed string, base64), a
script that imports the package indirectly, and a command split across several process_manage writes.
"""
from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Iterable, Optional

PLUGIN_SOURCE_ROOT = Path(__file__).resolve().parents[1]

CLI_VERBS = frozenset({"pins", "allow", "off", "on", "lock", "unlock", "setup", "approve", "retire", "status",
                       "check", "receipts", "replay"})
# Commands that print or search text. Their arguments are data, so the alias rule and the state-file
# rule do not apply to them (a redirection still does).
TEXT_COMMANDS = frozenset({"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "cat", "bat", "less",
                           "more", "head", "tail", "sed", "ls", "git", "wc", "man", "which", "type", "whereis",
                           "file", "stat", "diff", "cmp", "sha256sum", "shasum", "md5sum", "md5", "od", "xxd",
                           "hexdump", "strings", "tree", "du", "realpath", "readlink", "basename", "dirname"})
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "mksh", "busybox"})
_RE_PYTHON = re.compile(r"^(python|pypy)(\d+(\.\d+)*)?$")
_STATE_NAMES = re.compile(r"^(pins\.yaml(\.lock|\.v2\.bak)?|ledger\.sqlite(-wal|-shm|-journal)?|allowlist\.yaml)$")
_SEPARATORS = frozenset({";", "&&", "||", "|", "&", "|&", "\n", "(", ")", ";;", ";&", "!", "{", "}"})
_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", "<>", ">&"})
_RE_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_RE_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_RE_SUBST = re.compile(r"`([^`]*)`")
_RE_PY_IMPORT = re.compile(r"\b(?:from|import)\s+(?:[\w.]+\s*,\s*)*[\w.]*\bconfidential_mode\b")
_RE_PY_DYN_IMPORT = re.compile(r"(?:import_module|__import__|spec_from_file_location|run_path|run_module)\s*\("
                               r"[^)]*confidential_mode")
_RE_PY_HERMES_CLI = re.compile(r"\b(?:from|import)\s+hermes_cli\b")
_RE_PY_RUNS = re.compile(r"\b(?:subprocess|os\.system|os\.popen|os\.exec\w*|os\.spawn\w*|os\.posix_spawn\w*|pty\.spawn"
                         r"|create_subprocess_\w+|pexpect|plumbum|sh\.Command|commands\.getoutput)\b")
_RE_PY_FILES = re.compile(r"\b(?:open|sqlite3|Path|PurePath|shutil|os\.(?:remove|unlink|rename|replace|truncate|"
                          r"link|symlink)|write_text|write_bytes|unlink|io\.open|codecs\.open|fileinput)\b")
_RE_PY_LITERAL = re.compile(r"(?:[rRbBuUfF]{0,2})('''(?:.|\n)*?'''|\"\"\"(?:.|\n)*?\"\"\"|'(?:[^'\\\n]|\\.)*'"
                            r"|\"(?:[^\"\\\n]|\\.)*\")")
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
    return word.rstrip("/").rsplit("/", 1)[-1].casefold()


def is_state_path(path: str) -> bool:
    """Whether ``path`` names one of the plugin's state files where the plugin keeps them, or may."""
    p = (path or "").strip()
    if not p:
        return False
    name = _base(p)
    segs = [s for s in p.replace("\\", "/").split("/") if s]
    if name == "state.json":
        return "plugin-data" in segs
    if not _STATE_NAMES.match(name):
        return False
    if not (p.startswith("/") or p.startswith("~")):
        return True                      # relative: the working directory is not known here
    if "plugin-data" in segs:
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


def _substitutions(text: str) -> list[str]:
    """The text inside every $(...) and `...` (nested ones are found when the inner text is scanned)."""
    found = [m.group(1) for m in _RE_SUBST.finditer(text)]
    i = 0
    while True:
        i = text.find("$(", i)
        if i < 0:
            break
        depth, j = 0, i + 1
        while j < len(text):
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        found.append(text[i + 2:j])
        i += 2
    return found


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


WRAPPERS = frozenset({"sudo", "doas", "env", "exec", "command", "builtin", "nohup", "time", "nice", "ionice",
                      "timeout", "stdbuf", "xargs", "caffeinate", "unbuffer", "watch", "script", "strace", "uv",
                      "uvx", "run", "pipx", "poetry", "pdm", "hatch", "rye", "npx", "chronic", "flock", "setsid",
                      "arch", "then", "do", "else", "if", "while", "until"})


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
            prev_opt = False               # an option's value (sudo -u root, timeout 5, nice -n 10)
        else:
            return False
    return True


def _program_index(words: list[str], test) -> Optional[int]:
    """The index of the first word in command position whose basename passes ``test``."""
    for i, w in enumerate(words):
        if test(_base(w)) and _command_position(words, i):
            return i
    return None


def _hermes_invocation(words: list[str], *, anywhere: bool = False) -> bool:
    """A hermes executable, or python -m hermes_cli(.main), followed by the confidential subcommand."""
    for i, w in enumerate(words):
        if not anywhere and not _command_position(words, i):
            continue
        b = _base(w)
        start = None
        if b == "hermes":
            start = i + 1
        elif _RE_PYTHON.match(b):
            for j in range(i + 1, len(words) - 1):
                if words[j] == "-m" and words[j + 1] in ("hermes_cli.main", "hermes_cli"):
                    start = j + 2
                    break
        if start is not None:
            for a in words[start:]:
                a = a.casefold()
                if a == "confidential" or a.startswith("/confidential"):
                    return True
    return False


def _alias_invocation(words: list[str]) -> bool:
    return (len(words) >= 3 and _base(words[0]) not in TEXT_COMMANDS and words[1].casefold() == "confidential"
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


def _python_command_reason(words: list[str], stdin_code: list[str], depth: int) -> Optional[str]:
    """``words`` starts with a Python interpreter."""
    i = 1
    while i < len(words):
        w = words[i]
        if w == "-c" and i + 1 < len(words):
            return python_reason(words[i + 1], depth + 1)
        if w == "-m" and i + 1 < len(words):
            mod = words[i + 1]
            if mod == "confidential_mode" or mod.startswith("confidential_mode.") or ".confidential_mode" in mod:
                return "runs the confidential_mode package"
            return None
        if w == "-":
            break
        if w.startswith("-"):
            i += 1
            continue
        text = _read_script(w)           # an interpreter running a script
        return python_reason(text, depth + 1) if text is not None else None
    for code in stdin_code:              # python reading a heredoc or a pipe
        why = python_reason(code, depth + 1)
        if why:
            return why
    return None


def shell_reason(text: str, depth: int = 0, *, cli_only: bool = False) -> Optional[str]:
    """Why this shell text reaches the confidential command, the package or a state file, or None.
    ``cli_only`` checks only the command forms (for an argument that may be a command line)."""
    if not isinstance(text, str) or not text.strip() or depth > _MAX_DEPTH:
        return None
    if _slash_line(text):
        return "types the /confidential command"
    for inner in _substitutions(text):
        why = shell_reason(inner, depth + 1)
        if why:
            return why
    body, heredocs = _heredocs(_ansi_c_quoted(text))
    lines = body.split("\n")
    stdin_shell = False
    for line_no, line in enumerate(lines):
        line_docs = [b for n, b in heredocs if n == line_no]
        cmds = _commands(_tokens(line))
        for idx, (raw_words, targets, here) in enumerate(cmds):
            words = _strip_assignments(raw_words)
            for t in ([] if cli_only else targets):
                if is_state_path(t):
                    return "writes a confidential-mode state file"
            if not words:
                continue
            cmd = _base(words[0])
            if _hermes_invocation(words) and cmd not in TEXT_COMMANDS:
                return "invokes hermes with its confidential command"
            if _alias_invocation(words):
                return "invokes the confidential command"
            piped = idx > 0
            k = _program_index(words, lambda b: bool(_RE_PYTHON.match(b)))
            if k is not None:
                stdin = list(line_docs) + list(here)
                if piped:
                    stdin.append(line)
                why = _python_command_reason(words[k:], stdin, depth)
                if why:
                    return why
            k = _program_index(words, lambda b: b in SHELLS or b in ("eval", "source", "."))
            if k is not None:
                sh, rest = _base(words[k]), words[k + 1:]
                if sh == "eval":
                    why = shell_reason(" ".join(rest), depth + 1)
                    if why:
                        return why
                if "-c" in rest and rest.index("-c") + 1 < len(rest):
                    why = shell_reason(rest[rest.index("-c") + 1], depth + 1)
                    if why:
                        return why
                elif sh in SHELLS and not [w for w in rest if not w.startswith("-")]:
                    stdin_shell = True   # reads a pipe or a heredoc
                for doc in list(line_docs) + list(here):
                    why = shell_reason(doc, depth + 1)
                    if why:
                        return why
            if not cli_only:
                if "tee" == cmd and any(is_state_path(w) for w in words[1:] if not w.startswith("-")):
                    return "writes a confidential-mode state file"
                if any(is_state_path(w) for w in words[1:]) and not _read_only(words):
                    return "names a confidential-mode state file"
            for w in words[1:]:          # an argument that is itself a command line (find -exec, ssh, ...)
                if " " in w and cmd not in TEXT_COMMANDS:
                    why = shell_reason(w, depth + 1, cli_only=True)
                    if why:
                        return why
    if stdin_shell:                      # the whole text, as data a shell will run
        loose = [t for t in _tokens(re.sub(r"['\"\\]", "", body)) if t not in _SEPARATORS]
        if _hermes_invocation(loose, anywhere=True) or any(_alias_invocation(loose[i:]) for i in range(len(loose))):
            return "pipes the confidential command into a shell"
        for _n, doc in heredocs:
            why = shell_reason(doc, depth + 1)
            if why:
                return why
    return None


def _read_only(words: list[str]) -> bool:
    cmd = _base(words[0])
    if cmd not in TEXT_COMMANDS:
        return False
    if cmd in ("sed", "perl") and any(w == "-i" or w.startswith("-i") or w.startswith("--in-place") for w in words[1:]):
        return False
    return True


def _literals(code: str) -> list[str]:
    out = []
    for m in _RE_PY_LITERAL.finditer(code):
        lit = m.group(1)
        q = 3 if lit[:3] in ("'''", '"""') else 1
        out.append(lit[q:-q])
    return out


def python_reason(code: str, depth: int = 0) -> Optional[str]:
    """Why this Python code imports the package, runs the confidential command or names a state file."""
    if not isinstance(code, str) or not code.strip() or depth > _MAX_DEPTH:
        return None
    code = _ansi_c_text(code)
    if _RE_PY_IMPORT.search(code) or _RE_PY_DYN_IMPORT.search(code):
        return "imports the confidential_mode package"
    lits = _literals(code)
    folded = [x.casefold() for x in lits]
    if _RE_PY_HERMES_CLI.search(code) and "confidential" in folded:
        return "runs hermes with its confidential command"
    if _RE_PY_RUNS.search(code):        # the code starts processes: its strings may be command lines
        for n, lit in enumerate(folded):
            if (_base(lit) == "hermes" or lit in ("hermes_cli.main", "hermes_cli")) and \
                    any(x == "confidential" or x.startswith("/confidential") for x in folded[n + 1:]):
                return "runs hermes with its confidential command"
        for lit in lits:
            if any(c in lit for c in " ;|&\n") and len(lit) < 20_000:
                why = shell_reason(lit, depth + 1)
                if why:
                    return why
    if _RE_PY_FILES.search(code):       # the code opens or moves files: a state-file path is a target
        for lit in lits:
            if is_state_path(lit):
                return "names a confidential-mode state file"
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
    if any(is_state_path(p) for p in file_tool_paths(args)):
        return "targets a confidential-mode state file"
    return None
