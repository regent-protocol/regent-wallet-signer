"""P-256 keys as Privy encodes them (base64 DER PKCS#8 private, base64 DER SPKI public),
plus RSA public keys from a JWKS for verifying Regent's RS256 decision tokens."""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

_PREFIXES = ("wallet-auth:", "wallet-api:")


class P256Key:
    def __init__(self, private_key_b64: str) -> None:
        raw = private_key_b64.strip()
        for p in _PREFIXES:
            if raw.startswith(p):
                raw = raw[len(p):]
        try:
            key = serialization.load_der_private_key(base64.b64decode(raw, validate=True), password=None)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid key: expected base64 DER PKCS#8") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("the key must be P-256")
        self._key = key

    @classmethod
    def generate(cls) -> P256Key:
        key = ec.generate_private_key(ec.SECP256R1())
        der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        return cls(base64.b64encode(der).decode())

    @classmethod
    def load(cls, path: str | Path) -> P256Key:
        return cls(Path(path).read_text().strip())

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.write_text(self.private_key_b64 + "\n")
        try:
            p.chmod(0o600)
        except OSError:
            pass

    @property
    def private_key_b64(self) -> str:
        der = self._key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
        return base64.b64encode(der).decode()

    @property
    def public_key_b64(self) -> str:
        der = self._key.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(der).decode()

    def sign(self, payload: bytes) -> str:
        return base64.b64encode(self._key.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()


def verify_p256(public_key_b64: str, payload: bytes, signature_b64: str) -> bool:
    try:
        pub = serialization.load_der_public_key(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), payload, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def rsa_from_jwk(jwk: dict) -> rsa.RSAPublicKey:
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def verify_rs256(pub: rsa.RSAPublicKey, signing_input: bytes, signature: bytes) -> bool:
    try:
        pub.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
