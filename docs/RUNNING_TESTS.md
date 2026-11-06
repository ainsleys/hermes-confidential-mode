# Running the tests

Hermes' own `.venv` has no pytest (its pyproject sets `default-groups = []`), so use an
ephemeral overlay that leaves that environment untouched:

    cd ~/hermes-agent && PYTHONDONTWRITEBYTECODE=1 HERMES_HOME=$(mktemp -d) \
      uv run --no-sync --with pytest==9.1.1 --with pytest-asyncio==1.4.0 \
      pytest ~/hermes-confidential-mode/tests -q -p no:cacheprovider

Never `uv pip install` from inside ~/hermes-agent: that targets its `.venv`. For SDK
experiments use a separate environment synced from Hermes' lock:

    cd ~/hermes-agent && UV_PROJECT_ENVIRONMENT=<dir>/.venv uv sync
    uv pip install --python <dir>/.venv/bin/python tinfoil==0.14.2
