"""Generator for the frozen NEAR E2EE version 2 vectors in tests/unit/test_near_e2ee.py.

Source of the algorithm: NEAR's guide, https://docs.near.ai/cloud/guides/e2ee-chat-completions (read
2026-11-07), "Quick Start". ``v2_encrypt_guide`` below is the guide's ``v2_encrypt`` with one change:
``X25519PrivateKey.generate()`` and ``secrets.token_bytes(...)`` are replaced by the fixed ephemeral
secret and nonce passed in, so the output is reproducible. The key conversion is the guide's
(``crypto_sign_ed25519_pk_to_curve25519``). ``v2_encrypt_independent`` recomputes the same bytes without
PyNaCl's key conversion: the Montgomery map u = (1 + y) / (1 - y) mod 2^255 - 19, cryptography's X25519
and HKDF; only XChaCha20-Poly1305 is PyNaCl's (checked against draft-irtf-cfrg-xchacha A.3.1 in the tests).

Run:  python tests/fixtures/near_e2ee_vectors/generate.py   (prints the constants)
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MODEL_SEED = bytes(range(32))
REQ_EPH, REQ_NONCE = bytes(range(32, 64)), bytes(range(64, 88))
REQ_PLAINTEXT = b"What is the capital of France?"
CLIENT_SEED = bytes(range(100, 132))
RESP_EPH, RESP_NONCE = bytes(range(140, 172)), bytes(range(180, 204))
RESP_PLAINTEXT = b"Paris"


def v2_encrypt_guide(plaintext: bytes, recipient_x25519_pub: bytes, eph_secret: bytes, nonce: bytes) -> bytes:
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
    eph = X25519PrivateKey.from_private_bytes(eph_secret)               # guide: X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_x25519_pub))
    key = HKDF(hashes.SHA256(), 32, None, b"ed25519_encryption").derive(shared)
    # guide: nonce = secrets.token_bytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key)
    return eph.public_key().public_bytes_raw() + nonce + ct


def ed_pub(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def montgomery(pub: bytes) -> bytes:
    p = 2 ** 255 - 19
    y = int.from_bytes(pub, "little") & ((1 << 255) - 1)
    return ((1 + y) * pow(1 - y, p - 2, p) % p).to_bytes(32, "little")


def v2_encrypt_independent(plaintext: bytes, recipient_ed_pub: bytes, eph_secret: bytes, nonce: bytes) -> bytes:
    return v2_encrypt_guide(plaintext, montgomery(recipient_ed_pub), eph_secret, nonce)


def vectors() -> dict:
    from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519
    model_pub, client_pub = ed_pub(MODEL_SEED), ed_pub(CLIENT_SEED)
    req = v2_encrypt_guide(REQ_PLAINTEXT, crypto_sign_ed25519_pk_to_curve25519(model_pub), REQ_EPH, REQ_NONCE)
    resp = v2_encrypt_guide(RESP_PLAINTEXT, crypto_sign_ed25519_pk_to_curve25519(client_pub), RESP_EPH, RESP_NONCE)
    assert req == v2_encrypt_independent(REQ_PLAINTEXT, model_pub, REQ_EPH, REQ_NONCE)
    assert resp == v2_encrypt_independent(RESP_PLAINTEXT, client_pub, RESP_EPH, RESP_NONCE)
    return {"MODEL_PUB": model_pub.hex(), "REQ_WIRE": req.hex(), "CLIENT_PUB": client_pub.hex(),
            "RESP_WIRE": resp.hex(), "sha256": hashlib.sha256(req + resp).hexdigest()}


if __name__ == "__main__":
    for k, v in vectors().items():
        print(f"{k} = {v!r}")
