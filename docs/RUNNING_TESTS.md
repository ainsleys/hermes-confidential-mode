# Running the tests

The tests run inside Hermes' own Python environment, because the seam tests import real Hermes
modules. That environment does not include pytest. Hermes' `pyproject.toml` sets
`default-groups = []`, so no development dependencies are installed into its `.venv`.

The command below adds pytest for the length of one run only. `uv run --with` builds a temporary
overlay on top of Hermes' environment. The overlay goes away when the run ends, and Hermes' `.venv`
is left untouched.

    cd ~/hermes-agent && PYTHONDONTWRITEBYTECODE=1 HERMES_HOME=$(mktemp -d) \
      uv run --no-sync --with pytest==9.1.1 --with pytest-asyncio==1.4.0 \
      pytest ~/hermes-confidential-mode/tests -q -p no:cacheprovider

The other settings in that command each keep the run from leaving traces:

- `HERMES_HOME=$(mktemp -d)` points Hermes at an empty temporary home. The tests therefore never
  read or write your real profile.
- `PYTHONDONTWRITEBYTECODE=1` stops Python from writing `.pyc` files.
- `-p no:cacheprovider` stops pytest from writing its `.pytest_cache` directory.
- `--no-sync` stops uv from changing Hermes' environment to match its lock file.

Never run `uv pip install` from inside `~/hermes-agent`. From that directory, uv targets Hermes' own
`.venv`, and the install would change it.

For experiments with the tinfoil SDK, use a separate environment. Build it from Hermes' lock file, so
it has the same versions, and then add the SDK to it:

    cd ~/hermes-agent && UV_PROJECT_ENVIRONMENT=<dir>/.venv uv sync
    uv pip install --python <dir>/.venv/bin/python tinfoil==0.14.2

`UV_PROJECT_ENVIRONMENT` tells uv to create the environment in `<dir>/.venv` instead of in Hermes'
own `.venv`. The second command installs the SDK into that separate environment only.

## PyNaCl, for NEAR request encryption

The plugin encrypts NEAR requests with PyNaCl. PyNaCl is a Python binding to the libsodium library.
Hermes' lock file pins PyNaCl to version 1.6 but does not install it. Installing the plugin does not
install it either, so install it by hand. Install it into the separate test environment described
above:

    uv pip install --python <dir>/.venv/bin/python pynacl==1.6.*

The suite was last run with PyNaCl 1.6.2. Install the same package into the environment that runs
Hermes before you lock a profile on `attested-near`. Without it, the lock is refused with a message
that names the package. The plugin never sends a NEAR request unencrypted instead.

## Live NEAR AI Cloud tests

`tests/live/test_near_live.py` talks to `cloud-api.near.ai` and spends tokens. It is skipped unless
`NEAR_AI_API_KEY` is set. `NEAR_LIVE_MODEL` picks the model; the default is `Qwen/Qwen3.8-27B`.
Every other NEAR test is offline: `tests/near_world.py` serves a synthetic NEAR with real signatures,
and `tests/fixtures/near_real_capture/` holds a real public capture that replays offline.

`scripts/near_first_contact.py` is the manual counterpart. It attests NEAR, sends one unstreamed and
one streamed request when the key is set, writes what it recorded to a JSON file, and replays that
file offline. It prints no secrets.

## Real captures in the fixtures

Two fixture directories hold real vendor responses, not synthetic ones.
`tests/fixtures/real_capture_sev/` holds a Tinfoil verification captured from a live AMD SEV-SNP
router. `tests/fixtures/near_real_capture/` holds NEAR AI Cloud's public attestation responses. Both
name real hosts.

Real captures age. Certificates expire, and Intel Trust Authority tokens carry an expiry time. The
tests that replay them therefore pin the check time to the capture time (`as_of`), so they keep
passing after the material expires. A replay without that pin fails once the material is past its
expiry, which is the correct result for a live check.

