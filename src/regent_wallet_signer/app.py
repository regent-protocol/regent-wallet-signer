"""The service: one endpoint the Regent gateway calls after the gate allowed a payment.

    POST /v1/sign     Authorization: Bearer <SIGNER_TOKEN>
    {
      "decision": {"token": "<Regent decision JWT>", "tool": "x402", "action": "PAY api.example.com",
                   "resource": "https://api.example.com/v1/quote", "args": {...}},
      "request":  {"method": "POST", "url": "https://api.privy.io/v1/wallets/<id>/rpc",
                   "body": {"method": "eth_signTypedData_v4", "params": {"typed_data": {...}}},
                   "headers": {"privy-app-id": "..."}},
      "regent_signature": "<base64 ECDSA over Privy's canonical form of `request`>"
    }
    → 200 {"signature": "0x…", "decision_id": "dec_…"}
    → 4xx/5xx {"code": "…", "message": "…"}   nothing was signed

    GET /v1/health → what this signer is bound to (no secrets)
"""

from __future__ import annotations

import hmac
import time
from decimal import Decimal
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from regent_wallet_signer import __version__
from regent_wallet_signer.canonical import canonical_request
from regent_wallet_signer.checks import check_request
from regent_wallet_signer.config import Settings
from regent_wallet_signer.keys import P256Key
from regent_wallet_signer.privy import PrivyApp
from regent_wallet_signer.regent import Refusal, RegentTrust
from regent_wallet_signer.state import State


def create_app(cfg: Settings, *, http: httpx.AsyncClient | None = None, state: State | None = None) -> FastAPI:
    app = FastAPI(title="regent-wallet-signer", version=__version__, docs_url=None, redoc_url=None)
    key = P256Key(cfg.client_key_b64)
    trust = RegentTrust(jwks_url=cfg.regent_jwks_url, issuer=cfg.regent_issuer,
                        signer_key_url=cfg.regent_signer_key_url, pinned_signer_key=cfg.regent_signer_public_key, http=http)
    privy = PrivyApp(app_id=cfg.privy_app_id, app_secret=cfg.privy_app_secret, base_url=cfg.privy_api_base, http=http)
    st = state or State(cfg.state_file)
    app.state.cfg, app.state.trust, app.state.privy, app.state.key, app.state.store = cfg, trust, privy, key, st

    def _authorized(authorization: str | None) -> None:
        token = (authorization or "").removeprefix("Bearer ").strip()
        if not token or not hmac.compare_digest(token, cfg.signer_token):
            raise HTTPException(status_code=401, detail={"code": "BAD_SIGNER_TOKEN", "message": "unknown caller"})

    @app.exception_handler(Refusal)
    async def _refused(_: Request, exc: Refusal) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content={"code": exc.code, "message": exc.message})

    @app.get("/v1/health")
    async def health() -> dict[str, Any]:
        return {
            "ok": True, "version": __version__, "wallet_id": cfg.wallet_id, "address": cfg.wallet_address,
            "network": cfg.network, "app_id": cfg.privy_app_id, "client_public_key": key.public_key_b64,
            "regent_issuer": cfg.regent_issuer, "regent_jwks_url": cfg.regent_jwks_url,
            "max_usdc_per_payment": str(cfg.max_usdc_per_payment) if cfg.max_usdc_per_payment > 0 else None,
            "daily_usdc": str(cfg.daily_usdc) if cfg.daily_usdc > 0 else None,
            "spent_today_usdc": str(st.spent_today()),
        }

    @app.post("/v1/sign")
    async def sign(body: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _authorized(authorization)
        decision, request, regent_sig = body.get("decision"), body.get("request"), body.get("regent_signature")
        if not isinstance(decision, dict) or not isinstance(request, dict) or not isinstance(regent_sig, str):
            raise Refusal("BAD_REQUEST", "decision, request and regent_signature are required", 400)
        token = str(decision.get("token") or "")
        now = time.time()
        claims = await trust.verify_decision_token(token, now=now)
        did = str(claims["decision_id"])
        if st.already_used(did, int(now)):
            raise Refusal("DECISION_REUSED", f"decision {did} was already co-signed once")
        usdc = check_request(decision, claims, request, cfg, now=now)
        if cfg.daily_usdc > 0 and st.spent_today(now) + usdc > cfg.daily_usdc:
            raise Refusal("LIMIT", f"today's ceiling of {cfg.daily_usdc} USDC on this signer would be exceeded")
        # the request came from the gateway holding Regent's quorum key, not just from
        # whoever holds this service's bearer token
        privy_headers = {k: v for k, v in (request.get("headers") or {}).items() if k.lower().startswith("privy-")}
        payload = canonical_request("POST", str(request["url"]), request.get("body"), privy_headers)
        await trust.verify_regent_signature(payload, regent_sig)
        # one decision, one signature: marked before Privy is asked, so a retry after a
        # timeout cannot produce a second valid authorization for the same decision
        st.mark_used(did, int(claims.get("exp") or now + 60), int(now))
        signature = await privy.cosign_rpc(url=str(request["url"]), body=request.get("body") or {},
                                           privy_headers=privy_headers, regent_signature=regent_sig, client_key=key)
        st.add_spent(Decimal(usdc), now)
        return {"signature": signature, "decision_id": did}

    return app
