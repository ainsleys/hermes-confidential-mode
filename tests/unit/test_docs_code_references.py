"""Every plugin code and test reference in the developer documents resolves to a definition.

docs/CLAIMS.md, docs/ADDING_A_VENDOR.md, docs/ARCHITECTURE.md, docs/INTERFACES.md and SECURITY.md cite code as
``file:name`` (``file:Class.member``) and tests as ``file::test_name``. A path is from the repository root
when it starts with ``tests/`` or ``scripts/`` or is ``__init__.py``; every other path is under
``confidential_mode/``. The name must be defined in the cited file, not only imported there. A bare
``Class.member`` that follows a ``file:name`` reference in the same group (a bullet, a paragraph or a table
cell) must name a member that the class has, in that file or in the plugin module that defines the
class. A reference preceded by the word "Hermes" names Hermes' own code and is not checked.
"""
from __future__ import annotations

import ast
import re
from functools import cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ("docs/CLAIMS.md", "docs/ADDING_A_VENDOR.md", "docs/ARCHITECTURE.md", "docs/INTERFACES.md", "SECURITY.md")

SPAN = re.compile(r"`([^`]+)`", re.S)
CODE_REF = re.compile(r"^(?P<path>[\w./]+\.py):(?P<name>[A-Za-z_][\w.]*)")
TEST_REF = re.compile(r"^(?P<path>tests/[\w./]+\.py)::(?P<name>[A-Za-z_]\w*)")
BARE = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)?$")


def _file(path: str) -> Path:
    if path.startswith(("tests/", "scripts/")) or path == "__init__.py":
        return ROOT / path
    return ROOT / "confidential_mode" / path


@cache
def _defined(file: Path) -> dict[str, set[str]]:
    """Top-level names of ``file`` mapped to their members (a class's methods and attributes)."""
    tree = ast.parse(file.read_text(encoding="utf-8"))
    out: dict[str, set[str]] = {}

    def targets(node: ast.stmt) -> list[str]:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return [node.name]
        if isinstance(node, ast.Assign):
            names = []
            for t in node.targets:
                elts = t.elts if isinstance(t, ast.Tuple) else [t]
                names += [e.id for e in elts if isinstance(e, ast.Name)]
            return names
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            return [node.target.id]
        return []

    for node in tree.body:
        for name in targets(node):
            members = out.setdefault(name, set())
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    members.update(targets(item))
    return out


@cache
def _plugin_files() -> tuple[Path, ...]:
    files = [ROOT / "__init__.py", *sorted((ROOT / "confidential_mode").rglob("*.py"))]
    return tuple(f for f in files if "__pycache__" not in f.parts)


def _resolves(file: Path, name: str) -> bool:
    head, _, member = name.partition(".")
    defined = _defined(file)
    if head not in defined:
        return False
    return not member or member.split(".")[0] in defined[head]


def _groups(text: str) -> list[str]:
    """Bullets, paragraphs and table cells: a bare name is read only against a reference in its group."""
    out: list[str] = []
    for block in re.split(r"\n\s*\n|\n(?=\s*[-*] )|\n(?=\s*\d+\. )", text):
        out += block.split("|") if block.lstrip().startswith("|") else [block]
    return out


def _problems(doc: str, text: str | None = None) -> list[str]:
    text = (ROOT / doc).read_text(encoding="utf-8") if text is None else text
    bad: list[str] = []
    for group in _groups(text):
        context: Path | None = None
        for m in SPAN.finditer(group):
            span = " ".join(m.group(1).split())
            hermes = group[max(0, m.start() - 8):m.start()].rstrip().endswith("Hermes")
            test = TEST_REF.match(span)
            code = CODE_REF.match(span)
            if test:
                f = ROOT / test["path"]
                if not f.is_file():
                    bad.append(f"{doc}: {span}: no such file")
                elif not _resolves(f, test["name"]):
                    bad.append(f"{doc}: {span}: no such test")
                context = None
            elif code:
                f = _file(code["path"])
                if hermes or not f.is_file() and code["path"].split("/")[0] in ("agent", "hermes_cli", "tools"):
                    context = None
                    continue
                if not f.is_file():
                    bad.append(f"{doc}: {span}: no such file")
                    context = None
                elif not _resolves(f, code["name"]):
                    bad.append(f"{doc}: {span}: {code['name']} is not defined in {code['path']}")
                    context = f
                else:
                    context = f
            elif context is not None and BARE.match(span) and "." in span:
                head = span.split(".")[0]
                owners = [f for f in (context, *_plugin_files()) if head in _defined(f)]
                if owners and not any(_resolves(f, span) for f in owners):
                    bad.append(f"{doc}: {span}: {head} has no such member")
    return bad


def test_every_code_and_test_reference_in_the_developer_documents_resolves():
    problems = [p for doc in DOCS if (ROOT / doc).is_file() for p in _problems(doc)]
    assert problems == [], "\n".join(problems)


def test_the_check_reads_references_and_catches_a_missing_one():
    assert _resolves(_file("gate_llm.py"), "LlmGate.handle")
    assert not _resolves(_file("gate_llm.py"), "LlmGate.no_such_method")
    assert _resolves(ROOT / "tests/unit/test_ledger.py", "test_kinds_match_contract")
    text = ("- Code: `gate_llm.py:LlmGate.handle`, `LlmGate.missing`, `ledger.py:Ledger.append`, `Ledger.tail`;\n"
            "  Hermes `agent/turn_api_call.py:run`; `security_verified`.\n"
            "- Tests: `tests/unit/test_ledger.py::test_no_such_test`.\n")
    found = _problems("example.md", text)
    assert len(found) == 2, found
    assert "LlmGate.missing" in found[0] and "test_no_such_test" in found[1], found
    assert _problems("example.md", "`gate_tools_policy.py:_Policy.decide` and `Allowlist.add`") == []
