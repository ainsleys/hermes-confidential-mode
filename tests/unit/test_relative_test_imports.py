"""Test modules import each other relatively, so the suite runs under any checkout directory name.

The repository root has an ``__init__.py`` (the Hermes plugin package). When the checkout's directory name is
a valid Python identifier (``plugin``), pytest imports the test modules as ``plugin.tests...``; an absolute
``tests.near_world`` import would then load a second copy beside ``plugin.tests.near_world``, and a test that
patches one copy would miss the other. Relative imports name the same module under either name.
"""
import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]


def _absolute_test_imports(tree: ast.AST) -> list[int]:
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            lines += [node.lineno for a in node.names if a.name == "tests" or a.name.startswith("tests.")]
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module \
                and (node.module == "tests" or node.module.startswith("tests.")):
            lines.append(node.lineno)
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str) and node.args[0].value.startswith("tests.") \
                and ast.unparse(node.func) in ("__import__", "importlib.import_module"):
            lines.append(node.lineno)
    return lines


def test_no_test_module_imports_tests_absolutely():
    offenders = [f"{p.relative_to(TESTS)}:{line}"
                 for p in sorted(TESTS.rglob("*.py")) if "spikes" not in p.parts and "__pycache__" not in p.parts
                 for line in _absolute_test_imports(ast.parse(p.read_text(encoding="utf-8")))]
    assert offenders == [], "import test modules relatively (from ..near_world import ...)"
