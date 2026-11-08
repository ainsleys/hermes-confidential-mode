"""Helpers every ``/confidential`` and ``hermes confidential`` command shares.

``PROFILE_NAME`` (the Tinfoil profile), ``_short`` (a fingerprint shortened for display),
``_provider_module`` (the provider module the runtime uses), the interactive verification wait, and
``TerminalAsker``, the terminal stand-in for ``ctx.ask_choice`` that the CLI verbs and ``setup`` use.
"""
from __future__ import annotations

import importlib
import os
import sys
from typing import Any

from . import locking as _locking

PROFILE_NAME = _locking.PROFILE_NAME


def _short(fp: Any, n: int = 8) -> str:
    s = str(fp or "")
    return s[:n] if s else "(none)"


def _provider_module(rt: Any):
    """The provider module the runtime registered (the plugin's own package copy)."""
    return importlib.import_module(__package__ + ".provider")


INTERACTIVE_VERIFY_WAIT_SECONDS = 60.0   # check / setup / on: a human is waiting; cold attestation ~5-20 s


class TerminalAsker:
    """ask_choice for `hermes confidential setup`: numbered prompt on the controlling terminal. An exact
    choice value, its number, or on an approve/deny prompt y/yes/n/no (any case) is an answer; anything else
    asks once more, then is no answer (None). End of input or non-tty stdin => None (Amendment 14).

    Self-approval guard (Amendment 7): selfapproval.self_approval_reason() decides, as for every asker;
    under a reason the asker raises SelfApprovalRefused and never reads an answer (docs/LIMITATIONS.md)."""

    def __init__(self, stdin=None, stdout=None, environ=None):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.environ = environ if environ is not None else os.environ

    def ask_choice(self, question: str, choices: list) -> str | None:
        from .consent import SelfApprovalRefused
        from .selfapproval import self_approval_reason
        reason = self_approval_reason(self.environ)
        if reason:
            raise SelfApprovalRefused(reason)
        try:
            if not self.stdin.isatty():
                return None
        except Exception:  # noqa: BLE001
            return None
        values = [c["value"] if isinstance(c, dict) else str(c) for c in choices]
        self.stdout.write(question + "\n")
        for i, c in enumerate(choices, 1):
            label = c.get("label", c["value"]) if isinstance(c, dict) else str(c)
            self.stdout.write(f"  {i}. {label}\n")
        yes_no = "approve" in values and "deny" in values
        for attempt in range(2):
            self.stdout.write("Choice: " if attempt == 0 else
                              f"Answer {' or '.join(str(n) for n in range(1, len(values) + 1))}"
                              + (", y or n" if yes_no else "") + ": ")
            self.stdout.flush()
            line = self.stdin.readline()
            if not line:            # end of input: nobody is there to ask again
                return None
            picked = self._pick(line.strip(), values, yes_no)
            if picked is not None:
                return picked
        return None

    @staticmethod
    def _pick(answer: str, values: list, yes_no: bool) -> str | None:
        """A choice value, its number, or (on an approve/deny prompt) y, yes, n or no in any case
        (Amendment 14). Anything else is None."""
        if answer in values:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(values):
            return values[int(answer) - 1]
        if yes_no:
            low = answer.lower()
            if low in ("y", "yes"):
                return "approve"
            if low in ("n", "no"):
                return "deny"
        return None
