"""NEAR AI Cloud request encryption (NEAR's "E2EE", protocol version 2), as a pure library.

Source: https://docs.near.ai/cloud/guides/e2ee-chat-completions, read 2026-11-07.

The cipher, per that page:
  * keys are Ed25519; both sides convert them to X25519 for the key exchange;
  * the sender makes a fresh ephemeral X25519 key, computes X25519(ephemeral, recipient), and derives a
    32-byte key with HKDF-SHA256 (no salt, info ``ed25519_encryption``);
  * the field is sealed with XChaCha20-Poly1305 (24-byte nonce, no associated data);
  * wire format, hex-encoded: ``[ephemeral public key, 32 bytes][nonce, 24 bytes][ciphertext + 16-byte tag]``.
The request is encrypted to the model's Ed25519 key (``X-Model-Pub-Key``). The response is encrypted to
the client's Ed25519 key (``X-Client-Pub-Key``), which this plugin generates fresh for every exchange and
never writes anywhere.

The field table, per that page, with ``X-Encrypt-All-Fields: true`` always on here (never configurable):

  Direction  Default fields                       Added by X-Encrypt-All-Fields
  request    messages[].content                   tools[].function.name, .description, .parameters (the JSON
                                                  schema serialised to a string and encrypted whole),
                                                  tool_choice.function.name, messages[].name,
                                                  messages[].refusal, messages[].tool_calls[].function.name
                                                  and .arguments
  response   choices[].message.content,           choices[].message.tool_calls[].function.name and
             .reasoning_content, .reasoning,      .arguments, choices[].message.refusal, logprobs token
             .audio.data                          strings

What this module adds to that table, all fail-closed (``E2EEError``, raised before anything is sent):
  * a top-level plaintext allowlist (``PLAINTEXT_KEYS``): any other top-level key that carries a string
    anywhere inside it is refused and named, since NEAR would forward it as plaintext;
  * structured settings validated by shape (``STRUCTURED_KEYS``): ``reasoning`` (keys ``enabled``,
    ``effort``, ``summary``, ``max_tokens``, ``exclude`` only), ``stream_options`` (``include_usage`` only) and
    ``reasoning_effort``. Each string must be one of a fixed set of words, so these settings carry no
    free text; any other key or value is refused;
  * ``logprobs`` and ``top_logprobs`` are refused (the page does not define the encrypted token format);
  * message content that is a list is flattened to one string when every part is text. A list with any
    other part (an image, audio, a file) keeps its structure (Amendment 9): every text part is sealed in
    place and every other part leaves as plaintext, because NEAR's encryption does not cover it. The report
    counts those parts by type (``plaintext_parts``). With ``image_parts="refuse"``
    (config ``confidential.near.image_parts``) such a message is refused instead, as before;
  * reasoning that Hermes may echo back on assistant messages (``reasoning_content``, ``reasoning``,
    ``reasoning_details``) is dropped from the request rather than sent as plaintext (NEAR's table has no
    request field for it); every drop is listed in the report;
  * in a response, every field the table lists that is present and not ``null`` must parse as the wire
    format and decrypt under this exchange's key, or the whole response is refused (a downgrade or
    tampering is never passed through). ``null`` or absent passes unchanged: the live probe of 2026-11-07
    showed a tool-call turn carries ``content: null`` with encrypted ``tool_calls`` and
    ``reasoning_content``. An empty string is not ciphertext and is refused; requests seal ``""`` too.

Live probe (scratchpad live/near_e2ee_probe.py, 2026-11-07, Qwen/Qwen3.8-27B and Qwen/Qwen3-VL-30B-A3B-Instruct):
the provider_tee signature covers the SHA-256 of the ciphertext request and response bytes; tool_calls
name and arguments and reasoning_content come back encrypted; a wrong X-Model-Pub-Key gets HTTP 421 ("The
encryption key is no longer valid"); the gateway accepts a list with an encrypted text part and a
plaintext image part and still returns a provider_tee signature, so image parts are sent beside sealed
text by default and disclosed (``image_parts="disclose"``).

Decryption authenticates nothing by itself: anyone can encrypt to the client's public key, which travels
in a request header. The transport (verify/near.py) therefore decrypts only after a verified provider_tee
signature over the ciphertext bytes.

Dependency: PyNaCl (``pynacl==1.6.*``) for the Ed25519 to X25519 conversion, X25519 and XChaCha20-Poly1305
(libsodium). HKDF-SHA256 is RFC 5869 over the standard library's HMAC. ``available()`` says whether the
library imports; nothing here falls back to plaintext.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Mapping

SOURCE_URL = "https://docs.near.ai/cloud/guides/e2ee-chat-completions"
SOURCE_READ = "2026-11-07"
ENCRYPTION_VERSION = 2
HKDF_INFO = b"ed25519_encryption"
EPHEMERAL_BYTES, NONCE_BYTES, TAG_BYTES = 32, 24, 16
MIN_WIRE_BYTES = EPHEMERAL_BYTES + NONCE_BYTES + TAG_BYTES
INSTALL_HINT = ("install the Python package pynacl==1.6.* into Hermes' environment (docs/RUNNING_TESTS.md); "
                "NEAR request encryption needs it and the plugin never falls back to plaintext")

#: Top-level request keys that may leave as plaintext. ``messages``, ``tools`` and ``tool_choice`` are
#: processed field by field. Any other top-level key carrying a string is refused.
PLAINTEXT_KEYS = frozenset({
    "model", "stream", "temperature", "top_p", "max_tokens", "max_completion_tokens", "n", "seed",
    "presence_penalty", "frequency_penalty",
    # Probe 4 (2026-11-07, live): accepted under encryption, not echoed in the response. They leave as
    # plaintext: a response_format schema, stop strings, metadata and the user id are visible to the gateway.
    "response_format", "stop", "metadata", "user",
})
#: Reasoning effort levels: Hermes' widest OpenAI-compatible wire vocabulary
#: (agent/reasoning_effort.py OPENAI_COMPAT_WIRE_EFFORTS at Hermes 84a0301). clamp_effort only returns a
#: level from a declared wire set, and every declared set is a subset of this one (Hermes-internal
#: "ultra" never reaches a wire).
REASONING_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "xhigh", "max"})
REASONING_SUMMARIES = frozenset({"auto", "concise", "detailed", "none"})


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _enum(allowed: frozenset, *, null: bool = False):
    return lambda v: (null and v is None) or (isinstance(v, str) and v in allowed)


#: Structured top-level settings that may leave as plaintext, each checked by shape: a mapping may hold
#: only the listed keys, each value of the listed type, and every string is one of a fixed set of words.
#: Nothing in them is free text, so they carry no conversation content. Any other key, or any value
#: outside the shape, is refused. ``logit_bias`` and free-form ``extra_body`` entries stay refused:
#: token ids could encode text.
STRUCTURED_KEYS: dict = {
    "reasoning": {"enabled": lambda v: isinstance(v, bool),
                  # effort may be null: Hermes' clamp_reasoning_config passes {"enabled": True, "effort": None}
                  # through unchanged, and a null carries no text.
                  "effort": _enum(REASONING_EFFORTS, null=True), "summary": _enum(REASONING_SUMMARIES),
                  "max_tokens": _is_int, "exclude": lambda v: isinstance(v, bool)},
    "stream_options": {"include_usage": lambda v: isinstance(v, bool)},
    "reasoning_effort": _enum(REASONING_EFFORTS),
}


def _structured_ok(key: str, value: Any) -> bool:
    """True when ``value`` has the shape STRUCTURED_KEYS[key] allows (``None`` counts as unset)."""
    if value is None:
        return True
    shape = STRUCTURED_KEYS[key]
    if callable(shape):
        return shape(value) is True
    if not isinstance(value, Mapping):
        return False
    return all(isinstance(k, str) and k in shape and shape[k](v) is True for k, v in value.items())


PROCESSED_KEYS = frozenset({"messages", "tools", "tool_choice"})
REFUSED_KEYS = frozenset({"logprobs", "top_logprobs"})
ROLES = frozenset({"system", "developer", "user", "assistant", "tool"})
MESSAGE_PLAINTEXT_KEYS = frozenset({"role", "tool_call_id"})
MESSAGE_DROPPED_KEYS = frozenset({"reasoning_content", "reasoning", "reasoning_details"})
TOOL_CALL_PLAINTEXT_KEYS = frozenset({"id", "type", "index"})
RESPONSE_MESSAGE_FIELDS = ("content", "reasoning_content", "reasoning", "refusal")
TEXT_PART_KEYS = frozenset({"type", "text", "cache_control"})
# confidential.near.image_parts: "disclose" (default) sends non-text parts as plaintext beside the sealed
# text and records them; "refuse" refuses any message that has one.
IMAGE_PARTS_MODES = ("disclose", "refuse")
DEFAULT_IMAGE_PARTS = "disclose"
IMAGE_PART_TYPES = frozenset({"image_url", "input_image", "image"})


def plaintext_parts_note(parts: Mapping | None) -> str | None:
    """The sentence the ledger row and the receipt show, or None when no part left in plaintext."""
    if not isinstance(parts, Mapping) or not parts.get("count"):
        return None
    types = parts.get("types") if isinstance(parts.get("types"), Mapping) else {}
    n = int(parts["count"])
    if set(types) <= IMAGE_PART_TYPES:
        return f"{n} image part(s) left this host in plaintext to NEAR's gateway"
    names = ", ".join(f"{k} x{v}" for k, v in sorted(types.items()))
    return f"{n} non-text part(s) ({names}) left this host in plaintext to NEAR's gateway"
_HEX = re.compile(r"[0-9a-fA-F]*")
_PUB = re.compile(r"[0-9a-f]{64}")


class E2EEError(ValueError):
    """A request that cannot leave encrypted, or a response that is not this exchange's ciphertext."""


def available() -> tuple[bool, str]:
    """(True, "") when PyNaCl imports with every binding used here; else (False, the reason)."""
    try:
        from nacl import bindings as b
        for name in ("crypto_sign_ed25519_pk_to_curve25519", "crypto_sign_ed25519_sk_to_curve25519",
                     "crypto_scalarmult", "crypto_scalarmult_base",
                     "crypto_aead_xchacha20poly1305_ietf_encrypt", "crypto_aead_xchacha20poly1305_ietf_decrypt"):
            getattr(b, name)
        from nacl.signing import SigningKey  # noqa: F401
    except Exception as exc:
        return False, f"pynacl unavailable ({type(exc).__name__}): {INSTALL_HINT}"
    return True, ""


def _nacl():
    ok, reason = available()
    if not ok:
        raise E2EEError(reason)
    from nacl import bindings
    return bindings


# ── the cipher ──────────────────────────────────────────────────────────────────────────────────

def hkdf_sha256(ikm: bytes, info: bytes = HKDF_INFO, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 with no salt (a zero-filled 32-byte salt, as the RFC defines)."""
    prk = hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def _x25519(secret: bytes, public: bytes) -> bytes:
    b = _nacl()
    try:
        shared = b.crypto_scalarmult(secret, public)
    except Exception as exc:
        raise E2EEError("X25519 key exchange failed (a low-order or malformed public key)") from exc
    if not any(shared):
        raise E2EEError("X25519 key exchange produced the all-zero secret (a low-order public key)")
    return shared


def ed25519_pub_to_x25519(pub: bytes) -> bytes:
    try:
        return _nacl().crypto_sign_ed25519_pk_to_curve25519(pub)
    except E2EEError:
        raise
    except Exception as exc:
        raise E2EEError("the Ed25519 public key is not a valid curve point") from exc


def parse_public_key(value: Any, label: str = "model public key") -> bytes:
    """32 bytes from exactly 64 lower-case hex characters."""
    if not isinstance(value, str) or not _PUB.fullmatch(value):
        raise E2EEError(f"{label} is not 32 bytes of lower-case hex")
    return bytes.fromhex(value)


@dataclass
class ClientKey:
    """One exchange's Ed25519 key pair. The public half goes in ``X-Client-Pub-Key``; the private half,
    converted to X25519, decrypts the response. Held in memory only."""
    public_hex: str
    _x25519_secret: bytes = field(repr=False)

    @classmethod
    def generate(cls) -> "ClientKey":
        _nacl()
        from nacl.bindings import crypto_sign_ed25519_sk_to_curve25519
        from nacl.signing import SigningKey
        sk = SigningKey.generate()
        pub = bytes(sk.verify_key)
        return cls(public_hex=pub.hex(), _x25519_secret=crypto_sign_ed25519_sk_to_curve25519(bytes(sk) + pub))

    @classmethod
    def from_seed(cls, seed: bytes) -> "ClientKey":
        """Deterministic key from a 32-byte Ed25519 seed (known-answer tests only)."""
        _nacl()
        from nacl.bindings import crypto_sign_ed25519_sk_to_curve25519
        from nacl.signing import SigningKey
        sk = SigningKey(seed)
        pub = bytes(sk.verify_key)
        return cls(public_hex=pub.hex(), _x25519_secret=crypto_sign_ed25519_sk_to_curve25519(bytes(sk) + pub))


def seal(model_ed25519_pub_hex: str, plaintext: bytes, *, _ephemeral_secret: bytes | None = None,
         _nonce: bytes | None = None) -> str:
    """Encrypt ``plaintext`` to an Ed25519 public key; returns the hex wire format. The two private
    arguments exist for known-answer tests only; production always draws them fresh."""
    b = _nacl()
    recipient = ed25519_pub_to_x25519(parse_public_key(model_ed25519_pub_hex))
    eph = _ephemeral_secret if _ephemeral_secret is not None else secrets.token_bytes(32)
    eph_pub = b.crypto_scalarmult_base(eph)
    key = hkdf_sha256(_x25519(eph, recipient))
    nonce = _nonce if _nonce is not None else secrets.token_bytes(NONCE_BYTES)
    if len(nonce) != NONCE_BYTES:
        raise E2EEError("XChaCha20-Poly1305 needs a 24-byte nonce")
    ct = b.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes(plaintext), None, nonce, key)
    return (eph_pub + nonce + ct).hex()


def is_wire(value: Any) -> bool:
    """Whether ``value`` has the shape of the wire format (hex, long enough). Says nothing about keys."""
    return (isinstance(value, str) and len(value) % 2 == 0 and len(value) >= 2 * MIN_WIRE_BYTES
            and bool(_HEX.fullmatch(value)))


def open(client: "ClientKey | bytes", wire_hex: str) -> bytes:  # noqa: A001 - the plan's name; no builtin open here
    """Decrypt one wire-format field with the client's key (a ClientKey or its X25519 secret)."""
    b = _nacl()
    if not is_wire(wire_hex):
        raise E2EEError("a field that must be ciphertext is not in NEAR's wire format")
    data = bytes.fromhex(wire_hex)
    eph, nonce, ct = data[:EPHEMERAL_BYTES], data[EPHEMERAL_BYTES:EPHEMERAL_BYTES + NONCE_BYTES], \
        data[EPHEMERAL_BYTES + NONCE_BYTES:]
    secret = client._x25519_secret if isinstance(client, ClientKey) else bytes(client)
    key = hkdf_sha256(_x25519(secret, eph))
    try:
        return b.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, None, nonce, key)
    except Exception as exc:
        raise E2EEError("a ciphertext field does not decrypt under this exchange's key (tampered, or "
                        "not encrypted to this client)") from exc


open_sealed = open


def request_headers(client_pub_hex: str, model_pub_hex: str) -> dict[str, str]:
    """The headers NEAR's guide requires, with all-fields encryption on."""
    return {"X-Signing-Algo": "ed25519", "X-Client-Pub-Key": client_pub_hex, "X-Model-Pub-Key": model_pub_hex,
            "X-Encryption-Version": str(ENCRYPTION_VERSION), "x-no-aliasing": "true",
            "X-Encrypt-All-Fields": "true"}


# ── requests ────────────────────────────────────────────────────────────────────────────────────

def _carries_string(value: Any) -> bool:
    if isinstance(value, str):
        return True
    if isinstance(value, Mapping):
        # A mapping key is text too ({"<anything>": 1} would leave the key in plaintext).
        return any(isinstance(k, str) or _carries_string(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_carries_string(v) for v in value)
    return False


class _Report:
    def __init__(self):
        self.encrypted: dict[str, int] = {}
        self.dropped: dict[str, int] = {}
        self.flattened = 0
        self.plaintext_keys: list[str] = []
        self.plaintext_parts: dict[str, int] = {}

    def add(self, path: str) -> None:
        self.encrypted[path] = self.encrypted.get(path, 0) + 1

    def drop(self, path: str) -> None:
        self.dropped[path] = self.dropped.get(path, 0) + 1

    def as_dict(self) -> dict:
        return {"encrypted_fields": sorted(self.encrypted), "encrypted_count": sum(self.encrypted.values()),
                "dropped_fields": sorted(self.dropped), "flattened_messages": self.flattened,
                "plaintext_keys": sorted(self.plaintext_keys), "encryption_version": ENCRYPTION_VERSION,
                "plaintext_parts": {"count": sum(self.plaintext_parts.values()),
                                    "types": dict(sorted(self.plaintext_parts.items()))},
                "all_fields": True}


def _seal_str(model_pub: str, value: Any, path: str, report: _Report) -> Any:
    if value is None:
        return value
    if not isinstance(value, str):
        raise E2EEError(f"{path} is not a string; refused (it would leave as plaintext)")
    report.add(path)
    return seal(model_pub, value.encode("utf-8"))


def _flatten(content: list, where: str) -> str:
    texts = []
    for part in content:
        ptype = part.get("type") if isinstance(part, Mapping) else None
        if ptype != "text":
            kind = ptype if isinstance(ptype, str) else type(part).__name__
            if kind in ("image_url", "input_image", "image"):
                raise E2EEError(f"{where}: NEAR's encryption does not cover image parts; refused before sending "
                                "(confidential.near.image_parts is refuse)")
            raise E2EEError(f"{where}: NEAR's encryption does not cover {kind!r} content parts; refused before "
                            "sending")
        extra = sorted(k for k in part if k not in TEXT_PART_KEYS and _carries_string(part[k]))
        if extra or not isinstance(part.get("text"), str):
            raise E2EEError(f"{where}: a text part carries fields this plugin does not encrypt "
                            f"({', '.join(extra) or 'text is not a string'}); refused")
        texts.append(part["text"])
    return "\n".join(texts)


def _text_part(part: Mapping, where: str) -> str:
    extra = sorted(k for k in part if k not in TEXT_PART_KEYS and _carries_string(part[k]))
    if extra or not isinstance(part.get("text"), str):
        raise E2EEError(f"{where}: a text part carries fields this plugin does not encrypt "
                        f"({', '.join(extra) or 'text is not a string'}); refused")
    return part["text"]


def _mixed(content: list, where: str, model_pub: str, report: _Report) -> list:
    """A list with a non-text part, under image_parts=disclose: text parts sealed in place, every other part
    unchanged (plaintext) and counted. A part without a string type is refused."""
    out = []
    for part in content:
        ptype = part.get("type") if isinstance(part, Mapping) else None
        if not isinstance(ptype, str) or not ptype:
            raise E2EEError(f"{where}: a content part has no type; refused before sending")
        if ptype == "text":
            text = _text_part(part, where)
            if "cache_control" in part:
                report.drop("messages[].content[].cache_control")
            out.append({"type": "text", "text": _seal_str(model_pub, text, "messages[].content[].text", report)})
        else:
            report.plaintext_parts[ptype] = report.plaintext_parts.get(ptype, 0) + 1
            out.append(dict(part))
    return out


def _message(msg: Any, i: int, model_pub: str, report: _Report, image_parts: str = DEFAULT_IMAGE_PARTS) -> dict:
    where = f"messages[{i}]"
    if not isinstance(msg, Mapping):
        raise E2EEError(f"{where} is not an object; refused")
    role = msg.get("role")
    if role not in ROLES:
        raise E2EEError(f"{where}.role {str(role)[:20]!r} is not a chat role this plugin knows; refused")
    out: dict = {}
    for key, value in msg.items():
        if key in MESSAGE_PLAINTEXT_KEYS:
            out[key] = value
        elif key in MESSAGE_DROPPED_KEYS:
            report.drop(f"messages[].{key}")
        elif key == "content":
            if isinstance(value, list) and image_parts == "disclose" and any(
                    not (isinstance(p, Mapping) and p.get("type") == "text") for p in value):
                out[key] = _mixed(value, where, model_pub, report)
                continue
            if isinstance(value, list):
                value = _flatten(value, where)
                report.flattened += 1
            out[key] = _seal_str(model_pub, value, "messages[].content", report)
        elif key in ("name", "refusal"):
            out[key] = _seal_str(model_pub, value, f"messages[].{key}", report)
        elif key == "tool_calls":
            out[key] = None if value is None else _tool_calls(value, where, model_pub, report)
        elif _carries_string(value):
            raise E2EEError(f"{where}.{key} carries text this plugin does not encrypt; refused before sending")
        else:
            out[key] = value
    return out


def _tool_calls(calls: Any, where: str, model_pub: str, report: _Report) -> list:
    if not isinstance(calls, list):
        raise E2EEError(f"{where}.tool_calls is not a list; refused")
    out = []
    for j, call in enumerate(calls):
        w = f"{where}.tool_calls[{j}]"
        if not isinstance(call, Mapping) or call.get("type", "function") != "function":
            raise E2EEError(f"{w} is not a function call; refused")
        new: dict = {}
        for key, value in call.items():
            if key in TOOL_CALL_PLAINTEXT_KEYS:
                new[key] = value
            elif key == "function":
                if not isinstance(value, Mapping):
                    raise E2EEError(f"{w}.function is not an object; refused")
                fn: dict = {}
                for fk, fv in value.items():
                    if fk == "arguments" and isinstance(fv, Mapping):
                        fv = json.dumps(fv, ensure_ascii=False)
                    if fk in ("name", "arguments"):
                        fn[fk] = _seal_str(model_pub, fv, f"messages[].tool_calls[].function.{fk}", report)
                    elif _carries_string(fv):
                        raise E2EEError(f"{w}.function.{fk} carries text this plugin does not encrypt; refused")
                    else:
                        fn[fk] = fv
                new[key] = fn
            elif _carries_string(value):
                raise E2EEError(f"{w}.{key} carries text this plugin does not encrypt; refused")
            else:
                new[key] = value
        out.append(new)
    return out


def _tools(tools: Any, model_pub: str, report: _Report) -> list:
    if not isinstance(tools, list):
        raise E2EEError("tools is not a list; refused")
    out = []
    for i, tool in enumerate(tools):
        w = f"tools[{i}]"
        if not isinstance(tool, Mapping) or tool.get("type") != "function" or not isinstance(tool.get("function"), Mapping):
            raise E2EEError(f"{w} is not a function tool; NEAR's table covers function tools only; refused")
        new: dict = {}
        for key, value in tool.items():
            if key == "type":
                new[key] = value
            elif key == "function":
                fn: dict = {}
                for fk, fv in value.items():
                    if fk == "parameters":
                        text = fv if isinstance(fv, str) else json.dumps(fv, ensure_ascii=False)
                        fn[fk] = _seal_str(model_pub, text, "tools[].function.parameters", report)
                    elif fk in ("name", "description"):
                        fn[fk] = _seal_str(model_pub, fv, f"tools[].function.{fk}", report)
                    elif _carries_string(fv):
                        raise E2EEError(f"{w}.function.{fk} carries text this plugin does not encrypt; refused")
                    else:
                        fn[fk] = fv
                new[key] = fn
            elif _carries_string(value):
                raise E2EEError(f"{w}.{key} carries text this plugin does not encrypt; refused")
            else:
                new[key] = value
        out.append(new)
    return out


def _tool_choice(choice: Any, model_pub: str, report: _Report) -> Any:
    if choice is None or choice in ("auto", "none", "required"):
        return choice
    if isinstance(choice, Mapping) and choice.get("type") == "function" and isinstance(choice.get("function"), Mapping) \
            and set(choice) <= {"type", "function"} and set(choice["function"]) <= {"name"}:
        return {"type": "function",
                "function": {"name": _seal_str(model_pub, choice["function"].get("name"),
                                               "tool_choice.function.name", report)}}
    raise E2EEError("tool_choice has a shape NEAR's table does not cover; refused")


def encrypt_request(body: Mapping, model_pub: str, *, plaintext_keys=PLAINTEXT_KEYS,
                    image_parts: str = DEFAULT_IMAGE_PARTS) -> tuple[dict, dict]:
    """A chat completion request body with every field of NEAR's table sealed to ``model_pub``.
    Returns (new body, report). Raises E2EEError, naming the field, for anything that would leave as
    plaintext; nothing partial is ever returned. The one exception is a non-text content part under
    ``image_parts="disclose"``: it leaves as plaintext and the report's ``plaintext_parts`` counts it."""
    parse_public_key(model_pub)
    if image_parts not in IMAGE_PARTS_MODES:
        image_parts = "refuse"           # an unknown setting fails closed
    if not isinstance(body, Mapping):
        raise E2EEError("the request body is not a JSON object; refused")
    report = _Report()
    out: dict = {}
    for key, value in body.items():
        if key == "messages":
            if not isinstance(value, list):
                raise E2EEError("messages is not a list; refused")
            out[key] = [_message(m, i, model_pub, report, image_parts) for i, m in enumerate(value)]
        elif key == "tools":
            out[key] = None if value is None else _tools(value, model_pub, report)
        elif key == "tool_choice":
            out[key] = _tool_choice(value, model_pub, report)
        elif key in REFUSED_KEYS:
            if value not in (None, False, 0):
                raise E2EEError(f"{key} is refused while encrypting: NEAR encrypts logprobs token strings in a "
                                "format its guide does not define")
            out[key] = value
        elif key in plaintext_keys:
            out[key] = value
            if key != "model":
                report.plaintext_keys.append(key)
        elif key in STRUCTURED_KEYS:
            if not _structured_ok(key, value):
                raise E2EEError(f"request key {key!r} has a value outside the structured shape this plugin "
                                "lets leave as plaintext (fixed keys, booleans, integers and enumerated "
                                "words only); refused before sending")
            out[key] = value
            report.plaintext_keys.append(key)
        elif _carries_string(value):
            raise E2EEError(f"request key {key!r} carries text that would leave as plaintext (not in NEAR's "
                            "encrypted-field table, not on this plugin's plaintext allowlist); refused before sending")
        else:
            out[key] = value
            report.plaintext_keys.append(key)
    if not isinstance(out.get("messages"), list):
        raise E2EEError("the request has no messages; refused")
    return out, report.as_dict()


# ── responses ───────────────────────────────────────────────────────────────────────────────────

def _open_str(client, value: Any, path: str, opened: dict) -> Any:
    if value is None:
        return value
    if not isinstance(value, str):
        raise E2EEError(f"{path} should be ciphertext and is not a string; response refused")
    try:
        text = open(client, value).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise E2EEError(f"{path} decrypts to bytes that are not UTF-8; response refused") from exc
    except E2EEError as exc:
        raise E2EEError(f"{path}: {exc}; response refused") from exc
    opened[path] = opened.get(path, 0) + 1
    return text


def decrypt_response(body: Mapping, client) -> tuple[dict, dict]:
    """An unstreamed chat completion with every field of NEAR's response table opened with ``client``.
    Returns (new body, report). Raises E2EEError when a field that must be ciphertext is not, or does
    not decrypt: a downgrade is never passed through."""
    if not isinstance(body, Mapping):
        raise E2EEError("the response body is not a JSON object; response refused")
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise E2EEError("the response carries no choices; response refused")
    opened: dict[str, int] = {}
    new_choices = []
    for ch in choices:
        if not isinstance(ch, Mapping) or not isinstance(ch.get("message"), Mapping):
            raise E2EEError("a response choice carries no message; response refused")
        if ch.get("logprobs") is not None:
            raise E2EEError("the response carries logprobs, whose encrypted format NEAR does not define; refused")
        msg = dict(ch["message"])
        for f in RESPONSE_MESSAGE_FIELDS:
            if f in msg:
                msg[f] = _open_str(client, msg[f], f"choices[].message.{f}", opened)
        if isinstance(msg.get("audio"), Mapping):
            audio = dict(msg["audio"])
            if "data" in audio:
                audio["data"] = _open_str(client, audio["data"], "choices[].message.audio.data", opened)
            msg["audio"] = audio
        elif msg.get("audio") is not None:
            raise E2EEError("choices[].message.audio has an unknown shape; response refused")
        calls = msg.get("tool_calls")
        if calls is not None:
            if not isinstance(calls, list):
                raise E2EEError("choices[].message.tool_calls is not a list; response refused")
            new_calls = []
            for call in calls:
                if not isinstance(call, Mapping) or not isinstance(call.get("function"), Mapping):
                    raise E2EEError("a response tool call carries no function; response refused")
                fn = dict(call["function"])
                if not (isinstance(fn.get("name"), str) and fn["name"]):
                    raise E2EEError("a response tool call has no name ciphertext; response refused")
                for fk in ("name", "arguments"):
                    if fk in fn:
                        fn[fk] = _open_str(client, fn[fk], f"choices[].message.tool_calls[].function.{fk}", opened)
                new_calls.append({**call, "function": fn})
            msg["tool_calls"] = new_calls
        new_choices.append({**ch, "message": msg})
    return {**body, "choices": new_choices}, {"decrypted_fields": sorted(opened),
                                              "decrypted_count": sum(opened.values())}
