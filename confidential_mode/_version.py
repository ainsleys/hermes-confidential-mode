"""Plugin build identity, printed in receipts beside the verifier SDK version.

PLUGIN_COMMIT is filled in by packaging (the git commit the release was built from). A source checkout
that was not packaged reports "unpackaged"; receipts print whatever is here verbatim.
"""
PLUGIN_VERSION = "0.1.0"
PLUGIN_COMMIT = "unpackaged"
