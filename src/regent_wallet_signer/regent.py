"""What this signer trusts from Regent, and how it checks it.

* The decision token: an RS256 JWT issued by Regent Control, verified against Regent's
  published JWKS (cached, refreshed when a kid is unknown). Its claims name the agent,
  the tool and action, the decision id, the amount and currency, the counterparty and
  ``args_hash``, the commitment to the exact request the gate authorized.
* Regent's P-256 authorization key: the gateway's half of the quorum, published at the
  gateway's well-known document. Its signature over the Privy request proves the request
  came from the gateway holding that key, not merely from someone holding this
  service's bearer token.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx

from regent_wallet_signer.keys import rsa_from_jwk, verify_p256, verify_rs256


class Refusal(Exception):
    def __init__(self, code: str, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class RegentTrust:
    def __init__(self, *, jwks_url: str, issuer: str, signer_key_url: str, pinned_signer_key: str = "",
                 http: httpx.AsyncClient | None = None, cache_seconds: int = 600) -> None:
        self._jwks_url = jwks_url
        self._issuer = issuer
        self._signer_key_url = signer_key_url
        self._pinned = pinned_signer_key.strip()
        self._http = http
        self._cache = cache_seconds
        self._keys: dict[str, Any] = {}
        self._keys_at = 0.0
        self._signer_key = ""
        self._signer_key_at = 0.0

    async def _get(self, url: str) -> dict[str, Any]:
        try:
            if self._http is not None:
                r = await self._http.get(url, timeout=10.0)
            else:
                async with httpx.AsyncClient(timeout=10.0) as c:
                    r = await c.get(url)
            r.raise_for_status()
            data = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise Refusal("REGENT_UNREACHABLE", f"could not read {url}: {exc.__class__.__name__}", 503) from exc
        return data if isinstance(data, dict) else {}

    async def _jwks(self, *, force: bool = False) -> dict[str, Any]:
        if force or not self._keys or time.time() - self._keys_at > self._cache:
            doc = await self._get(self._jwks_url)
            self._keys = {str(k.get("kid")): k for k in (doc.get("keys") or []) if k.get("kty") == "RSA"}
            self._keys_at = time.time()
        return self._keys

    async def signer_public_key(self) -> str:
        if self._pinned:
            return self._pinned
        if not self._signer_key or time.time() - self._signer_key_at > self._cache:
            doc = await self._get(self._signer_key_url)
            key = str(((doc.get("providers") or {}).get("privy") or {}).get("public_key") or "")
            if not key:
                raise Refusal("REGENT_KEY_UNAVAILABLE", "the Regent gateway publishes no Privy signer key", 503)
            self._signer_key, self._signer_key_at = key, time.time()
        return self._signer_key

    async def verify_regent_signature(self, payload: bytes, signature_b64: str) -> None:
        key = await self.signer_public_key()
        if not verify_p256(key, payload, signature_b64):
            if self._pinned:
                raise Refusal("REGENT_SIGNATURE_INVALID", "the request is not signed by Regent's quorum key")
            # the gateway may have rotated its key: read it once more before refusing
            self._signer_key = ""
            key = await self.signer_public_key()
            if not verify_p256(key, payload, signature_b64):
                raise Refusal("REGENT_SIGNATURE_INVALID", "the request is not signed by Regent's quorum key")

    async def verify_decision_token(self, token: str, *, now: float | None = None, leeway: int = 60) -> dict[str, Any]:
        now = now if now is not None else time.time()
        try:
            h, p, s = token.split(".")
            header = json.loads(_b64url_decode(h))
            claims = json.loads(_b64url_decode(p))
            sig = _b64url_decode(s)
        except (ValueError, TypeError) as exc:
            raise Refusal("DECISION_INVALID", "the decision token is not a JWT") from exc
        if header.get("alg") != "RS256":
            raise Refusal("DECISION_INVALID", f"unexpected token algorithm {header.get('alg')!r}")
        kid = str(header.get("kid") or "")
        keys = await self._jwks()
        jwk = keys.get(kid)
        if jwk is None:
            jwk = (await self._jwks(force=True)).get(kid)
        if jwk is None:
            raise Refusal("DECISION_INVALID", "the token's key is not in Regent's JWKS")
        if not verify_rs256(rsa_from_jwk(jwk), f"{h}.{p}".encode(), sig):
            raise Refusal("DECISION_INVALID", "the decision token's signature does not verify")
        if claims.get("iss") != self._issuer:
            raise Refusal("DECISION_INVALID", f"the token's issuer is {claims.get('iss')!r}, expected {self._issuer!r}")
        exp, iat = claims.get("exp"), claims.get("iat")
        if not isinstance(exp, (int, float)) or exp + leeway < now:
            raise Refusal("DECISION_EXPIRED", "the decision token has expired")
        if isinstance(iat, (int, float)) and iat - leeway > now:
            raise Refusal("DECISION_INVALID", "the decision token is from the future")
        if not claims.get("decision_id") or not claims.get("args_hash"):
            raise Refusal("DECISION_INVALID", "the decision token names no decision or request")
        return claims
