#!/usr/bin/env python3
"""First contact with NEAR AI Cloud through the plugin's NEAR adapter. Prints no secrets.

What it does, in order:
  1. Attests the gateway and each model you name (public endpoints; no API key is sent), and prints every
     check, the pin identity, both fingerprints, the measured components, the gateway's Intel TCB status
     and the two signing public keys (public values).
  2. If NEAR_AI_API_KEY is set: sends one unstreamed and one streamed chat completion ("Reply with the
     word ok."), fetches each response signature, and prints the digests, the signature kind, the verdict
     and the reason. Response text is never printed (only its length in bytes).
  3. Writes everything it recorded (evidence and the per-send rows, no API key, no message text) to
     --out, then replays it offline with confidential_mode.verify.replay_near and prints the verdicts.

The API key is read through Hermes (catalog rule 11). The script first loads the env file of the Hermes
home named by HERMES_HOME (default ~/.hermes) with Hermes' own loader, hermes_cli.env_loader.
load_hermes_dotenv, as `hermes` does at start-up (external secret sources are not loaded), and then
reads NEAR_AI_API_KEY with agent.secret_scope.get_secret. In a standalone process no secret scope is
bound, so get_secret returns the process environment: the key from that env file, or an exported
NEAR_AI_API_KEY when the env file does not set it. A key held only in Hermes' credential pool
(`hermes auth`) is not read. The key is only ever sent as the Authorization header to the configured
base URL. It is not printed, logged or written to --out.

Hermes' loader does more than read the env file, the same as when `hermes` starts:
  - It can rewrite <HERMES_HOME>/.env: an env file saved as UTF-16 is rewritten as UTF-8, NUL characters
    are stripped, and lines Hermes considers malformed are normalised in place. The script itself never
    writes the file.
  - It also loads <HERMES_HOME>/.op.env (a 1Password service account token) into this process's
    environment when that file exists and OP_SERVICE_ACCOUNT_TOKEN is not already set. With
    load_external_secrets=False, Hermes' external secret sources (1Password among them) are not queried.
  - It loads every variable the env file sets, not only NEAR_AI_API_KEY, into this process's
    environment, and removes exported provider-selection variables Hermes manages that the env file does
    not set. That environment ends with the process.
  - It boots the config backend the home selects; a home set up with a remote config backend has its
    config fetched from that backend, as at `hermes` start-up.
Run with HERMES_HOME pointing at a home you are willing to have Hermes touch in these ways.

Run it in Hermes' environment (it needs tinfoil 0.14.2 for the TDX quote check), for example:
    cd ~/hermes-agent && HERMES_HOME=~/.hermes UV_PROJECT_ENVIRONMENT=<venv with tinfoil> uv run --no-sync \\
      python ~/hermes-confidential-mode/scripts/near_first_contact.py --model Qwen/Qwen3.8-27B
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from confidential_mode import sendctx  # noqa: E402
from confidential_mode.verify import near, replay_near  # noqa: E402

PROMPT = [{"role": "user", "content": "Reply with the word ok."}]


def _near_key() -> str:
    """NEAR_AI_API_KEY through Hermes: its env-file loader for HERMES_HOME, then its secret scope. "" when
    Hermes is not importable or the scope refuses."""
    try:
        from hermes_cli.env_loader import load_hermes_dotenv
        load_hermes_dotenv(load_external_secrets=False)
    except Exception:  # noqa: BLE001
        pass
    try:
        from agent.secret_scope import get_secret
        return (get_secret("NEAR_AI_API_KEY") or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", action="append", default=None, help="model id (repeatable); default Qwen/Qwen3.8-27B")
    ap.add_argument("--base-url", default=near.DEFAULT_BASE_URL)
    ap.add_argument("--out", default="near-first-contact.json", help="where to write evidence and rows")
    ap.add_argument("--no-send", action="store_true", help="attest only, even when NEAR_AI_API_KEY is set")
    args = ap.parse_args(argv)
    models = args.model or ["Qwen/Qwen3.8-27B"]
    key = _near_key()
    print(f"NEAR_AI_API_KEY: {'set' if key else 'not set or not readable through Hermes (attestation only)'}")

    rows: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        ad = near.NearAdapter(data_dir=tmp, base_url=args.base_url, models=models, signature_wait_seconds=10.0)
        ad.event_sink = rows.append
        try:
            result = ad.verify()
        except Exception as exc:  # print the reason and every check the evidence recorded
            print(f"VERIFY FAILED: {exc}")
            return 1
        ev = result.evidence
        print(f"identity: {result.router_repo}")
        print(f"code fingerprint:    {result.code_fingerprint}")
        print(f"enclave fingerprint: {result.enclave_fingerprint}")
        for k, v in ev["checks"].items():
            print(f"  check {k}: {'pass' if v is True else v}")
        for line in ev["claims"]["components"]:
            print(f"  {line}")
        print(f"gateway TCB status (Intel Trust Authority): {ev['claims']['tcb_status']}")
        print(f"gateway signer (ed25519 public key): {ev['claims']['gateway_signer']}")
        for m, signers in ev["claims"]["model_signers"].items():
            print(f"model signer {m}: {', '.join(signers)} ({len(signers)} report candidate(s))")
        print(f"TLS: {ev['tls_observation']}")
        print(f"evidence size: {len(json.dumps(ev))} bytes; capture_complete={ev['capture_complete']}")

        if key and not args.no_send:
            import openai
            ad.release()
            client = openai.OpenAI(api_key=key, base_url=args.base_url, http_client=ad.sync_http_view(), max_retries=0)
            with sendctx.send_context(session_id="near-first-contact", purpose="main", tier="attested"):
                for stream in (False, True):
                    try:
                        out = client.chat.completions.create(model=models[0], messages=PROMPT, max_tokens=16,
                                                             stream=stream)
                        if stream:
                            n = sum(len((c.choices[0].delta.content or "").encode()) for c in out if c.choices)
                        else:
                            n = len((out.choices[0].message.content or "").encode())
                        print(f"\n{'streamed' if stream else 'unstreamed'} send: reply {n} bytes")
                    except Exception as exc:
                        why = f"{exc} {exc.__cause__ or ''}"
                        if stream and "streaming is refused while encrypting" in why:
                            print("\nstreamed send: refused before sending, as designed (request encryption is on)")
                            continue
                        print(f"\n{'streamed' if stream else 'unstreamed'} send FAILED: {type(exc).__name__}: "
                              f"{why[:200]}")
                        continue
                    d = rows[-1]["detail"] if rows else {}
                    sig = d.get("signature") or {}
                    print(f"  id {d.get('chat_id')}  request sha256 {d.get('request_sha256')}")
                    print(f"  response sha256 {d.get('response_sha256')} ({d.get('response_bytes')} bytes, "
                          f"content-encoding {d.get('response_content_encoding')})")
                    print(f"  signature {sig.get('status')} kind={sig.get('signature_kind')} "
                          f"signer={sig.get('signing_address')}")
                    print(f"  signed text: {sig.get('text')}")
                    print(f"  verdict {rows[-1]['verdict']}: {(d.get('check') or {}).get('reason')}")
                    print(f"  TLS matches attested gateway key: {d.get('tls_matches_attested')}")

    doc = {"evidence": [{"row_id": 1, "evidence": ev}],
           "rows": [{"id": 1, "kind": "verify_ok", "detail": {"vendor": "near", "evidence": ev}}]
           + [{"id": i + 2, **r} for i, r in enumerate(rows)]}
    Path(args.out).write_text(json.dumps(doc, indent=1, sort_keys=True))
    print(f"\nwrote {args.out} (evidence and rows; no API key, no message text)")
    r = replay_near.replay(json.loads(Path(args.out).read_text())["evidence"][0]["evidence"])
    print(f"offline replay of the evidence: {'OK' if r.ok else 'FAIL'}")
    for k, v in r.checks.items():
        if v is not True:
            print(f"  {k}: {v}")
    if rows:
        res = replay_near.replay_receipt(json.loads(Path(args.out).read_text()))
        for s in res["sends"]:
            print(f"offline replay of row #{s['row']}: {s['verdict']} ({s['kind']}) {s['reason']}")
        print(f"fully attested: {res['fully_attested']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
