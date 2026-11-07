"""A synthetic NEAR AI Cloud for tests: real cryptography, fake hardware.

Everything that is signed is signed for real with keys generated here: the gateway and model ed25519
response-signing keys, an RSA certificate chain standing in for Intel Trust Authority (root pinned
through ``TEST_ROOTS``), and PS384 attestation JWTs. Only the TDX quote is fake: a JSON body behind a
"FAKEQUOTE" prefix, read by ``fake_quote_verifier`` (the real verifier needs Intel-signed quotes; the
real-capture fixture covers that path). Formats follow docs.near.ai as near_checks.py cites them.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import struct
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from confidential_mode.verify import near_checks as nc
from confidential_mode.verify.near import NearAdapter

HOST = "cloud-api.near.ai"
BASE = f"https://{HOST}/v1"
MODEL = "zai-org/GLM-test"
JWKS_URL = nc.ITA_JWKS_URLS[0]
NOW = 1_794_000_000.0


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign_hex(key: Ed25519PrivateKey, text: str) -> str:
    return key.sign(text.encode("utf-8")).hex()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_key, issuer_key, subject: str, issuer: str, *, ca: bool) -> x509.Certificate:
    start = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(start + dt.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return b.sign(issuer_key, hashes.SHA256())


@dataclass
class ItaAuthority:
    """An RSA CA chain and JWKS in Intel Trust Authority's shape."""
    root_key: rsa.RSAPrivateKey = field(default_factory=lambda: rsa.generate_private_key(65537, 2048))
    inter_key: rsa.RSAPrivateKey = field(default_factory=lambda: rsa.generate_private_key(65537, 2048))
    leaf_key: rsa.RSAPrivateKey = field(default_factory=lambda: rsa.generate_private_key(65537, 2048))
    kid: str = "test-kid.PS384"

    def __post_init__(self):
        self.root = _cert(self.root_key, self.root_key, "Test ITA Root", "Test ITA Root", ca=True)
        self.inter = _cert(self.inter_key, self.root_key, "Test ITA Signing CA", "Test ITA Root", ca=True)
        self.leaf = _cert(self.leaf_key, self.inter_key, "Test ITA Token Signing", "Test ITA Signing CA", ca=False)
        der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
        self.roots = {hashlib.sha256(der(self.root)).hexdigest(): "Test ITA Root"}
        nums = self.leaf_key.public_key().public_numbers()
        x5c = [base64.b64encode(der(c)).decode() for c in (self.leaf, self.inter, self.root)]
        self.jwks = {"keys": [{"kty": "RSA", "alg": "PS384", "kid": self.kid, "use": "sig",
                               "n": _b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
                               "e": _b64u(nums.e.to_bytes(3, "big")), "x5c": x5c}]}

    def token(self, claims: dict, *, alg: str = "PS384", kid: str | None = None, key=None) -> str:
        header = {"alg": alg, "kid": kid or self.kid, "typ": "JWT", "jku": JWKS_URL}
        h, p = _b64u(json.dumps(header).encode()), _b64u(json.dumps(claims).encode())
        msg = f"{h}.{p}".encode()
        k = key or self.leaf_key
        if alg == "PS384":
            sig = k.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())
        elif alg == "RS256":
            sig = k.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        else:
            sig = b""
        return f"{h}.{p}.{_b64u(sig)}"


def fake_quote(fields: dict) -> bytes:
    return b"FAKEQUOTE" + json.dumps(fields, sort_keys=True).encode()


def fake_quote_verifier(quote: bytes) -> dict:
    if not quote.startswith(b"FAKEQUOTE"):
        raise nc.CheckError("TDX quote did not verify: not a test quote")
    q = json.loads(quote[len(b"FAKEQUOTE"):])
    if q.get("bad_signature"):
        raise nc.CheckError("TDX quote did not verify: signature")
    return {**q, "verifier": "test"}


def events_for(app_id: str) -> list[dict]:
    out = []
    for name, payload in (("app-id", app_id.encode().hex()), ("compose-hash", "ab" * 32), ("instance-id", "cd" * 20)):
        digest = hashlib.sha384(struct.pack("<I", 134217729) + b":" + name.encode() + b":" + bytes.fromhex(payload)).hexdigest()
        out.append({"imr": 3, "event_type": 134217729, "digest": digest, "event": name, "event_payload": payload})
    out.insert(0, {"imr": 0, "event_type": 2147483659, "digest": "00" * 48, "event": "", "event_payload": ""})
    return out


def report(signer_hex: str, nonce: str, compose: str, *, tls_fp: str | None = None, model: str | None = None,
           mrtd: str = "11" * 48, bad_signature: bool = False, debug: bool = False, app_id: str = "app") -> dict:
    events = events_for(app_id)
    rtmr3 = nc.replay_rtmr3(events).hex()
    q = {"report_data": nc.expected_report_data(signer_hex, nonce, tls_fp).hex(),
         "mr_config_id": nc.mr_config_id_for(compose).hex(), "mrtd": mrtd, "rtmr0": "22" * 48, "rtmr1": "33" * 48,
         "rtmr2": "44" * 48, "rtmr3": rtmr3, "td_attributes": "01" if debug else "00", "debug": debug,
         "bad_signature": bad_signature}
    rep = {"signing_address": signer_hex, "signing_algo": "ed25519", "request_nonce": nonce,
           "intel_quote": fake_quote(q).hex(), "event_log": json.dumps(events) if model is None else events,
           "info": {"app_id": app_id, "instance_id": "inst-" + app_id, "app_name": "dstack-test",
                    "tcb_info": {"app_compose": compose}}}
    if tls_fp is not None:
        rep["tls_cert_fingerprint"] = tls_fp
        rep["report_data"] = q["report_data"]
    if model is not None:
        rep.update(model_name=model, signing_public_key=signer_hex, nvidia_payload=json.dumps({"nonce": nonce}))
    return rep


class _FakeSSL:
    def __init__(self, der: bytes):
        self._der = der

    def getpeercert(self, binary=False):
        return self._der


class _FakeStream:
    def __init__(self, der: bytes):
        self._ssl = _FakeSSL(der)

    def get_extra_info(self, name):
        return self._ssl if name == "ssl_object" else None


def tls_cert() -> tuple[bytes, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _cert(key, key, HOST, HOST, ca=False) if False else (
        x509.CertificateBuilder().subject_name(_name(HOST)).issuer_name(_name("Test LE"))
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
        .not_valid_after(dt.datetime(2036, 1, 1, tzinfo=dt.timezone.utc)).sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return der, hashlib.sha256(spki).hexdigest()


GATEWAY_COMPOSE = '{"manifest_version":2,"name":"dstack-gateway-test","docker_compose_file":"services: {}"}'
MODEL_COMPOSE = '{"manifest_version":2,"name":"dstack-nvidia-test","docker_compose_file":"services: {vllm: {}}"}'


class NearWorld:
    """Serves the NEAR endpoints the adapter uses through httpx.MockTransport."""

    def __init__(self, *, models=(MODEL,), sig_mode: str = "auto", tcb: str = "UpToDate"):
        self.gateway_key = Ed25519PrivateKey.generate()
        self.model_key = Ed25519PrivateKey.generate()
        self.ita = ItaAuthority()
        self.tls_der, self.tls_fp = tls_cert()
        self.models = list(models)
        self.sig_mode = sig_mode
        self.tcb = tcb
        self.requests: list[tuple[str, str, str]] = []   # (method, path, query)
        self.chat_bodies: list[bytes] = []
        self.chat_request_headers: list[httpx.Headers] = []
        self.signatures: dict[str, dict] = {}
        self.sig_404_left = 0
        self.model_candidates = 1
        self.second_model_key: Ed25519PrivateKey | None = None   # a second candidate's own key
        self.gateway_overrides: dict = {}
        self.model_overrides: dict = {}
        self.ita_overrides: dict = {}
        self.serve_tls = True
        self.chat_tls_der: bytes | None = None     # a different certificate on inference responses
        self.chat_serve_tls = True
        self.stream_chunks: list[bytes] | None = None
        self.gzip = False
        self.preread = False
        self._n = 0

    # ── attestation ─────────────────────────────────────────────────────────────────────────────
    def _ok(self, payload) -> httpx.Response:
        ext = {"network_stream": _FakeStream(self.tls_der)} if self.serve_tls else {}
        return httpx.Response(200, json=payload, extensions=ext)

    def _chat_ext(self) -> dict:
        if not self.chat_serve_tls:
            return {}
        return {"network_stream": _FakeStream(self.chat_tls_der or self.tls_der)}

    def gateway_report(self, nonce: str) -> dict:
        rep = report(pub_hex(self.gateway_key), nonce, GATEWAY_COMPOSE, tls_fp=self.tls_fp, app_id="gw")
        rep.update(self.gateway_overrides)
        return {"gateway_attestation": rep}

    def model_report(self, nonce: str, model: str) -> dict:
        keys = [self.model_key] + [self.second_model_key or self.model_key] * max(0, self.model_candidates - 1)
        cands = [report(pub_hex(keys[i]), nonce, MODEL_COMPOSE, model=model, mrtd="55" * 48, app_id=f"m{i}")
                 for i in range(self.model_candidates)]
        for c in cands:
            c.update(self.model_overrides)
        return {"gateway_attestation": self.gateway_report(nonce)["gateway_attestation"], "model_attestations": cands}

    def ita_claims(self, nonce: str) -> dict:
        gw = fake_quote_verifier(bytes.fromhex(self.gateway_report(nonce)["gateway_attestation"]["intel_quote"]))
        tdx = {"attester_type": "TDX", "attester_tcb_status": self.tcb, "tdx_is_debuggable": False,
               "attester_runtime_data": {"caller_nonce": nonce, "signing_address": pub_hex(self.gateway_key),
                                         "signing_algo": "ed25519"},
               "tdx_mrconfigid": gw["mr_config_id"], "tdx_mrtd": gw["mrtd"], "tdx_rtmr0": gw["rtmr0"],
               "tdx_rtmr1": gw["rtmr1"], "tdx_rtmr2": gw["rtmr2"], "tdx_rtmr3": "99" * 48}
        tdx.update(self.ita_overrides)
        return {"iss": "https://portal.trustauthority.intel.com", "iat": int(NOW), "exp": int(NOW) + 300,
                "nbf": int(NOW), "ver": "2.0.0", "tdx": tdx}

    def ita_response(self, nonce: str, model: str | None) -> dict:
        gw = self.ita.token(self.ita_claims(nonce))
        models = []
        if model:
            c = self.ita_claims(nonce)
            c["nvgpu"] = {"x-nvidia-overall-att-result": True}
            models.append({"model": model, "token": self.ita.token(c), "token_type": "JWT",
                           "attestation_type": "nvgpu", "token_signing_alg": "PS384"})
        return {"gateway": {"token": gw, "token_type": "JWT", "attestation_type": "tdx", "token_signing_alg": "PS384"},
                "models": models, "jwks_url": JWKS_URL, "policy_ids": [], "policy_must_match": False, "nonce": nonce}

    # ── inference and signatures ────────────────────────────────────────────────────────────────
    def _completion(self, model: str) -> tuple[str, bytes]:
        self._n += 1
        cid = f"chatcmpl-{self._n}"
        body = json.dumps({"id": cid, "object": "chat.completion", "created": 1, "model": model,
                           "choices": [{"index": 0, "finish_reason": "stop",
                                        "message": {"role": "assistant", "content": "NEAR-FAKE-REPLY"}}],
                           "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}).encode()
        return cid, body

    def _sse(self, model: str) -> tuple[str, bytes]:
        self._n += 1
        cid = f"chatcmpl-{self._n}"
        base = {"id": cid, "object": "chat.completion.chunk", "created": 1, "model": model}
        chunks = [dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": "NEAR-FAKE-REPLY"},
                                       "finish_reason": None}]),
                  dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}])]
        return cid, b"".join(b"data: " + json.dumps(c).encode() + b"\n\n" for c in chunks) + b"data: [DONE]\n\n"

    def make_signature(self, kind: str, model: str, req: bytes, resp: bytes) -> dict:
        rh, sh = hashlib.sha256(req).hexdigest(), hashlib.sha256(resp).hexdigest()
        mode = self.sig_mode
        key, k = (self.model_key, "provider_tee") if kind == "provider_tee" else (self.gateway_key, "gateway")
        text = f"{model}:{rh}:{sh}" if k == "provider_tee" else f"{rh}:{sh}"
        if mode == "tamper_response":
            text = f"{model}:{rh}:{'0' * 64}"
        elif mode == "wrong_key":
            key = Ed25519PrivateKey.generate()
        elif mode == "gateway_as_tee":
            key, k, text = self.gateway_key, "provider_tee", f"{rh}:{sh}"
        elif mode == "gateway_text_labelled_tee":
            key, k, text = self.gateway_key, "provider_tee", f"{model}:{rh}:{sh}"
        elif mode == "tee_text_as_gateway":
            key, k, text = self.gateway_key, "gateway", f"{model}:{rh}:{sh}"
        elif mode == "absent_kind":
            k = None
        elif mode == "ecdsa":
            return {"text": text, "signature": "00" * 65, "signing_address": "11" * 20, "signing_algo": "ecdsa",
                    "signature_kind": k}
        sig = {"text": text, "signature": sign_hex(key, text), "signing_address": pub_hex(key),
               "signing_algo": "ed25519"}
        if k is not None:
            sig["signature_kind"] = k
        if mode == "bad_signature_bytes":
            sig["signature"] = sign_hex(key, text + "x")
        return sig

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        self.requests.append((request.method, url.path, url.query.decode() if isinstance(url.query, bytes) else str(url.query)))
        q = {k: v[0] for k, v in parse_qs(url.query.decode() if isinstance(url.query, bytes) else str(url.query)).items()}
        if str(url).startswith(JWKS_URL):
            return httpx.Response(200, json=self.ita.jwks)
        if url.host != HOST:
            return httpx.Response(404, json={"error": {"message": "unknown host", "type": "x"}})
        if url.path == "/v1/attestation/report":
            if q.get("model"):
                return self._ok(self.model_report(q["nonce"], q["model"]))
            return self._ok(self.gateway_report(q["nonce"]))
        if url.path == "/v1/attestation/ita-token":
            return self._ok(self.ita_response(q["nonce"], q.get("model")))
        if url.path == "/v1/chat/completions" and request.method == "POST":
            body = request.read()
            self.chat_bodies.append(body)
            self.chat_request_headers.append(request.headers)
            data = json.loads(body)
            model = data.get("model")
            stream = data.get("stream") is True
            cid, resp = self._sse(model) if stream else self._completion(model)
            if self.stream_chunks is not None and stream:
                resp = b"".join(self.stream_chunks)
            kind = "gateway" if stream else "provider_tee"
            if self.sig_mode in ("gateway", "provider_tee"):
                kind = self.sig_mode
            if self.sig_mode == "other_chat" and self.signatures:
                self.signatures[cid] = dict(next(iter(self.signatures.values())))
            else:
                self.signatures[cid] = self.make_signature(kind, model, body, resp)
            headers = {"content-type": "text/event-stream" if stream else "application/json"}
            content = resp
            if self.gzip:
                import gzip
                content = gzip.compress(resp)
                headers["content-encoding"] = "gzip"
            if stream:
                parts = [content[i:i + 37] for i in range(0, len(content), 37)]
                return httpx.Response(200, headers=headers, stream=_ChunkStream(parts),
                                      extensions=self._chat_ext())
            if self.preread:   # a body httpx holds in memory already (Response(content=...))
                return httpx.Response(200, headers=headers, content=content,
                                      extensions=self._chat_ext())
            return httpx.Response(200, headers=headers, stream=_ChunkStream([content[:50], content[50:]]),
                                  extensions=self._chat_ext())
        if url.path.startswith("/v1/signature/"):
            cid = unquote(url.path[len("/v1/signature/"):])
            if self.sig_mode == "404" or self.sig_404_left > 0:
                self.sig_404_left -= 1
                return httpx.Response(404, json={"error": {"message": "not found", "type": "not_found"}})
            if self.sig_mode == "unavailable":
                return httpx.Response(200, json={"error_code": "stream_disconnected", "message": "client disconnected"})
            if self.sig_mode == "http500":
                return httpx.Response(500, json={"error": {"message": "boom", "type": "server"}})
            sig = self.signatures.get(cid)
            if sig is None:
                return httpx.Response(404, json={"error": {"message": "not found", "type": "not_found"}})
            return httpx.Response(200, json=sig)
        return httpx.Response(404, json={"error": {"message": "no route", "type": "x"}})

    def signature_fetches(self) -> int:
        return sum(1 for m, p, _ in self.requests if p.startswith("/v1/signature/"))

    def chat_posts(self) -> int:
        return sum(1 for m, p, _ in self.requests if p == "/v1/chat/completions")

    def adapter(self, tmp_path, **kw) -> NearAdapter:
        kw.setdefault("models", self.models)
        kw.setdefault("signature_wait_seconds", 0.0)
        kw.setdefault("ita_roots", self.ita.roots)
        kw.setdefault("quote_verifier", fake_quote_verifier)
        return NearAdapter(data_dir=tmp_path, transport_factory=lambda: httpx.MockTransport(lambda r: self.handler(r)),
                           async_transport_factory=lambda: httpx.MockTransport(lambda r: self.handler(r)),
                           clock=lambda: NOW, sleep=lambda s: None, **kw)


class _ChunkStream(httpx.SyncByteStream, httpx.AsyncByteStream):
    """A response body delivered in several chunks (sync and async)."""

    def __init__(self, parts: list[bytes]):
        self._parts = parts

    def __iter__(self):
        yield from self._parts

    async def __aiter__(self):
        for p in self._parts:
            yield p

    def close(self):
        pass

    async def aclose(self):
        pass
