"""Every plugin source file must parse on Python 3.11, the oldest version Hermes and the plugin declare.

``ast.parse(feature_version=(3, 11))`` rejects most 3.12-only syntax (type statements, type parameter
lists) on any interpreter, but not the PEP 701 f-string forms, because the 3.12+ tokenizer accepts them
whatever the feature version. A second check walks the f-string tokens and refuses what the 3.11
tokenizer refused: a replacement field that reuses the enclosing quote, holds a backslash or a comment,
or spans a line inside a single-quoted f-string.
"""
import ast
import io
import sys
import tokenize
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCES = sorted([ROOT / "__init__.py", *(ROOT / "confidential_mode").rglob("*.py"), *(ROOT / "scripts").rglob("*.py")])


def _quote_of(text: str) -> str:
    body = text.lstrip("rRbBfFuUtT")
    return body[:3] if body[:3] in ('"""', "'''") else body[:1]


def _clashes(inner: str, outer: str) -> bool:
    """True when a quote opened inside a replacement field would have ended the enclosing f-string on 3.11."""
    return outer in inner


def pep701_constructs(source: str) -> list:
    """(line, reason) for each f-string form the Python 3.11 tokenizer rejects. Needs Python 3.12+."""
    found = []
    stack = []  # the quote of each open f-string, innermost last
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.FSTRING_START:
            q = _quote_of(tok.string)
            if stack and _clashes(q, stack[-1]):
                found.append((tok.start[0], "nested f-string reuses the enclosing quote"))
            stack.append(q)
            continue
        if tok.type == tokenize.FSTRING_END:
            stack.pop()
            continue
        if not stack or tok.type == tokenize.FSTRING_MIDDLE:
            continue
        outer = stack[-1]
        if tok.type == tokenize.STRING:
            if _clashes(_quote_of(tok.string), outer):
                found.append((tok.start[0], "string inside a replacement field reuses the enclosing quote"))
            if "\\" in tok.string:
                found.append((tok.start[0], "backslash inside a replacement field"))
        elif tok.type == tokenize.COMMENT:
            found.append((tok.start[0], "comment inside a replacement field"))
        elif tok.type in (tokenize.NL, tokenize.NEWLINE) and len(outer) == 1:
            found.append((tok.start[0], "line break inside a single-quoted f-string"))
    return found


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(ROOT)))
def test_source_parses_on_python_311(path):
    source = path.read_text(encoding="utf-8")
    ast.parse(source, filename=str(path), feature_version=(3, 11))
    if sys.version_info >= (3, 12):
        assert pep701_constructs(source) == [], f"{path.relative_to(ROOT)} uses Python 3.12-only f-string syntax"


@pytest.mark.skipif(sys.version_info < (3, 12), reason="the 3.11 tokenizer rejects these forms itself")
@pytest.mark.parametrize("snippet", [
    "x = f\"{'a' if y else \"b\"}\"\n",
    "x = f'{\"a\" + f'{y}'}'\n",
    "x = f\"{'\\n'.join(y)}\"\n",
    "x = f\"{y # note\n}\"\n",
])
def test_the_check_catches_each_312_form(snippet):
    assert pep701_constructs(snippet)


def test_the_check_accepts_311_forms():
    if sys.version_info < (3, 12):
        pytest.skip("needs the 3.12 tokenizer")
    assert pep701_constructs("x = f\"{'a' if y else 'b'}\" + f'{d[\"k\"]}' + f\"\"\"{'q'}\"\"\"\n") == []
