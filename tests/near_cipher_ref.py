"""An independent implementation of NEAR's E2EE version 2 cipher, for the synthetic gateway's model side.

It shares no code with confidential_mode/verify/near_e2ee.py: X25519 and HKDF-SHA256 come from
``cryptography``; the Ed25519 to X25519 conversion is computed from the curve equations (Montgomery
u = (1 + y) / (1 - y) mod 2^255 - 19 for a public key; the clamped first half of SHA-512(seed) for a
secret). Only the AEAD, XChaCha20-Poly1305, comes from PyNaCl, as in NEAR's own guide; that primitive is
checked separately against the draft-irtf-cfrg-xchacha A.3.1 vector (tests/unit/test_near_e2ee.py).
Algorithm: https://docs.near.ai/cloud/guides/e2ee-chat-completions (read 2026-11-07).
"""
from __future__ import annotations

import hashlib
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

P = 2 ** 255 - 19
INFO = b"ed25519_encryption"


def ed_pub_to_x(pub: bytes) -> bytes:
    y = int.from_bytes(pub, "little") & ((1 << 255) - 1)
    return ((1 + y) * pow(1 - y, P - 2, P) % P).to_bytes(32, "little")


def ed_seed_to_x_secret(seed: bytes) -> bytes:
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def _key(shared: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, None, INFO).derive(shared)


def seal(recipient_ed_pub_hex: str, plaintext: bytes, *, eph: bytes | None = None, nonce: bytes | None = None) -> str:
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
    e = X25519PrivateKey.from_private_bytes(eph or secrets.token_bytes(32))
    shared = e.exchange(X25519PublicKey.from_public_bytes(ed_pub_to_x(bytes.fromhex(recipient_ed_pub_hex))))
    n = nonce or secrets.token_bytes(24)
    from cryptography.hazmat.primitives import serialization
    eph_pub = e.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return (eph_pub + n + crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, n, _key(shared))).hex()


def open_(x_secret: bytes, wire_hex: str) -> bytes:
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
    data = bytes.fromhex(wire_hex)
    shared = X25519PrivateKey.from_private_bytes(x_secret).exchange(X25519PublicKey.from_public_bytes(data[:32]))
    return crypto_aead_xchacha20poly1305_ietf_decrypt(data[56:], None, data[32:56], _key(shared))


def keypair() -> tuple[str, bytes]:
    """(Ed25519 public hex, X25519 secret) for a fresh key, as a gateway swapping the client key would make."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    seed = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return pub.hex(), ed_seed_to_x_secret(seed)
