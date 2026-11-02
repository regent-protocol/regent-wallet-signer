"""The few Privy calls: setup (quorum, policy, wallet) with the app secret, and the one
co-signed RPC. Two authorization signatures travel comma-separated in
``privy-authorization-signature``, as Privy's quorum guide has it."""

from __future__ import annotations

import base64
import json
from decimal import ROUND_UP, Decimal
from typing import Any

import httpx

from regent_wallet_signer.canonical import canonical_request
from regent_wallet_signer.chains import Chain
from regent_wallet_signer.keys import P256Key
from regent_wallet_signer.regent import Refusal

SIGNATURE_HEADER = "privy-authorization-signature"
TYPES = {
    "primary_type": "TransferWithAuthorization",
    "types": {"TransferWithAuthorization": [
        {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"},
    ]},
}


def policy_for(chain: Chain, cap_usdc: Decimal, *, name: str, owner_id: str | None = None) -> dict[str, Any]:
    atomic = int((cap_usdc * (10 ** chain.decimals)).to_integral_value(rounding=ROUND_UP))
    policy: dict[str, Any] = {
        "version": "1.0", "name": name[:100], "chain_type": "ethereum",
        "rules": [{"name": "x402 USDC under the cap", "method": "eth_signTypedData_v4", "action": "ALLOW", "conditions": [
            {"field_source": "ethereum_typed_data_domain", "field": "chainId", "operator": "eq", "value": str(chain.chain_id)},
            {"field_source": "ethereum_typed_data_domain", "field": "verifyingContract", "operator": "eq",
             "value": chain.usdc_checksummed},
            {"field_source": "ethereum_typed_data_message", "typed_data": TYPES, "field": "value", "operator": "lte",
             "value": str(atomic)},
        ]}],
    }
    if owner_id:
        policy["owner_id"] = owner_id
    return policy


class PrivyApp:
    def __init__(self, *, app_id: str, app_secret: str, base_url: str = "https://api.privy.io",
                 http: httpx.AsyncClient | None = None) -> None:
        self.app_id = app_id
        self._basic = "Basic " + base64.b64encode(f"{app_id}:{app_secret}".encode()).decode()
        self._base = base_url.rstrip("/")
        self._http = http

    async def request(self, method: str, path: str, body: dict[str, Any] | None = None, *,
                      signatures: list[str] | None = None, privy_headers: dict[str, str] | None = None,
                      ) -> tuple[int, dict[str, Any]]:
        url = self._base + path
        ph = {"privy-app-id": self.app_id, **(privy_headers or {})}
        headers = {"Authorization": self._basic, "Content-Type": "application/json", **ph}
        if signatures:
            headers[SIGNATURE_HEADER] = ",".join(signatures)
        content = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        try:
            if self._http is not None:
                r = await self._http.request(method.upper(), url, content=content, headers=headers, timeout=20.0)
            else:
                async with httpx.AsyncClient(timeout=20.0) as c:
                    r = await c.request(method.upper(), url, content=content, headers=headers)
        except httpx.HTTPError as exc:
            raise Refusal("PRIVY_UNAVAILABLE", f"Privy unreachable: {exc.__class__.__name__}", 502) from exc
        try:
            data = json.loads(r.content) if r.content else {}
        except ValueError:
            data = {}
        return r.status_code, data if isinstance(data, dict) else {"data": data}

    @staticmethod
    def _said(data: dict[str, Any]) -> str:
        err = data.get("error") or data.get("message") or json.dumps(data)[:200]
        return err if isinstance(err, str) else json.dumps(err)[:200]

    async def create_key_quorum(self, public_keys: list[str], *, threshold: int, display_name: str) -> str:
        st, d = await self.request("POST", "/v1/key_quorums", {
            "public_keys": public_keys, "authorization_threshold": threshold, "display_name": display_name[:100]})
        if st != 200 or not d.get("id"):
            raise Refusal("PRIVY_SETUP_FAILED", f"key quorum: {st} {self._said(d)}", 502)
        return str(d["id"])

    async def create_policy(self, policy: dict[str, Any]) -> str:
        st, d = await self.request("POST", "/v1/policies", policy)
        if st != 200 or not d.get("id"):
            raise Refusal("PRIVY_SETUP_FAILED", f"policy: {st} {self._said(d)}", 502)
        return str(d["id"])

    async def create_wallet(self, *, owner_id: str, policy_id: str, display_name: str) -> tuple[str, str]:
        st, d = await self.request("POST", "/v1/wallets", {
            "chain_type": "ethereum", "display_name": display_name[:100], "owner_id": owner_id, "policy_ids": [policy_id]})
        if st != 200 or not d.get("id") or not d.get("address"):
            raise Refusal("PRIVY_SETUP_FAILED", f"wallet: {st} {self._said(d)}", 502)
        return str(d["id"]), str(d["address"])

    async def cosign_rpc(self, *, url: str, body: dict[str, Any], privy_headers: dict[str, str],
                         regent_signature: str, client_key: P256Key) -> str:
        """Add this host's signature to Regent's and ask Privy for the wallet's signature."""
        path = url[len(self._base):] if url.startswith(self._base) else url
        ph = {k: v for k, v in privy_headers.items() if k.lower().startswith("privy-")}
        ours = client_key.sign(canonical_request("POST", url, body, ph))
        st, d = await self.request("POST", path, body, signatures=[regent_signature, ours],
                                   privy_headers={k: v for k, v in ph.items() if k.lower() != "privy-app-id"})
        if st == 200 and (d.get("data") or {}).get("signature"):
            sig = str(d["data"]["signature"])
            return sig if sig.startswith("0x") else "0x" + sig
        text = self._said(d)
        if st in (401, 403) and "signature" in text.lower():
            raise Refusal("WALLET_AUTH_REFUSED", f"Privy refused the quorum's authorization: {text[:160]}")
        if "policy" in text.lower() or st == 403:
            raise Refusal("WALLET_POLICY_REFUSED", f"the wallet's policy refused this signature: {text[:160]}")
        raise Refusal("PRIVY_UNAVAILABLE", f"Privy did not sign ({st}): {text[:160]}", 502)
