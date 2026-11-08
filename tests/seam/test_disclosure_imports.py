"""DISCLOSURE.md states how many private core import sites `hermes plugins validate` reports. This test
compares that number with the validator's own count, so the document cannot drift (Amendment 10 review)."""
import re
from pathlib import Path

from hermes_cli.plugin_validate_private_imports import private_import_findings

ROOT = Path(__file__).resolve().parents[2]


def test_documented_private_import_count_matches_the_validator():
    text = (ROOT / "docs" / "DISCLOSURE.md").read_text(encoding="utf-8")
    m = re.search(r"`hermes plugins validate` reports (\d+) of these import sites", text)
    assert m, "DISCLOSURE.md no longer states the private import count"
    assert int(m.group(1)) == len(private_import_findings(ROOT)), private_import_findings(ROOT)


def test_manifest_and_catalog_state_the_validator_count():
    count = len(private_import_findings(ROOT))
    for rel in ("plugin.yaml", "catalog/confidential-mode.yaml"):
        text = " ".join((ROOT / rel).read_text(encoding="utf-8").split())
        m = re.search(r"hermes plugins validate counts (\d+) private core import sites", text)
        assert m, f"{rel} no longer states the private import count"
        assert int(m.group(1)) == count, rel
