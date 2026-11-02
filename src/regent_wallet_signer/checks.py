"""The one question this service answers before adding its signature: is the Privy
request in front of it exactly the payment Regent decided, for this wallet, on this
network, within this host's own ceilings? Every check names what it refuses."""

from __future__ import annotations

import time
from decimal import ROUND_UP, Decimal
from typing import Any
from urllib.parse import urlsplit

from regent_wallet_signer.canonical import canonical_args_hash
from regent_wallet_signer.config import Settings
from regent_wallet_signer.regent import Refusal

RPC_METHOD = "eth_signTypedData_v4"
PRIMARY_TYPE = "TransferWithAuthorization"
_ALLOWED_PRIVY_HEADERS = {"privy-app-id", "privy-idempotency-key"}


def _lower(s: Any) -> str:
    return str(s or "").strip().lower()


def _int(value: Any, what: str) -> int:
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (TypeError, ValueError) as exc:
        raise Refusal("REQUEST_MISMATCH", f"{what} is not a number") from exc


def check_request(decision: dict[str, Any], claims: dict[str, Any], request: dict[str, Any],
                  cfg: Settings, *, now: float | None = None) -> Decimal:
    """Returns the amount in USDC the request moves; raises Refusal otherwise."""
    now = now if now is not None else time.time()
    tool, action = str(decision.get("tool") or ""), str(decision.get("action") or "")
    resource = decision.get("resource")
    args = decision.get("args")
    if not isinstance(args, dict):
        raise Refusal("DECISION_MISMATCH", "the decision names no request arguments")

    # 1. The token commits to this exact request (tool, action, resource, args).
    if claims.get("aud") != tool or claims.get("scope") != f"{tool}:{action}":
        raise Refusal("DECISION_MISMATCH", "the token was issued for a different tool or action")
    if claims.get("args_hash") != canonical_args_hash(tool, action, resource, args):
        raise Refusal("DECISION_MISMATCH", "the token's args_hash does not match this request")
    if _lower(claims.get("currency")) != "usdc":
        raise Refusal("DECISION_MISMATCH", f"the decision is in {claims.get('currency')!r}, not USDC")
    amount = claims.get("amount")
    if not isinstance(amount, (int, float)) or amount <= 0:
        raise Refusal("DECISION_MISMATCH", "the decision names no amount")

    # 2. The request is Privy's RPC for THIS wallet, and nothing else.
    url = str(request.get("url") or "")
    if url.rstrip("/") != f"{cfg.privy_api_base}/v1/wallets/{cfg.wallet_id}/rpc":
        raise Refusal("REQUEST_MISMATCH", "the request is not this wallet's RPC endpoint")
    if str(request.get("method") or "").upper() != "POST":
        raise Refusal("REQUEST_MISMATCH", "the request is not a POST")
    headers = {k.lower(): v for k, v in (request.get("headers") or {}).items()}
    privy_headers = {k: v for k, v in headers.items() if k.startswith("privy-")}
    if privy_headers.get("privy-app-id") != cfg.privy_app_id or set(privy_headers) - _ALLOWED_PRIVY_HEADERS:
        raise Refusal("REQUEST_MISMATCH", "unexpected Privy headers on the request")
    body = request.get("body")
    if not isinstance(body, dict) or body.get("method") != RPC_METHOD:
        raise Refusal("REQUEST_MISMATCH", f"only {RPC_METHOD} is co-signed")
    typed = ((body.get("params") or {}).get("typed_data")) if isinstance(body.get("params"), dict) else None
    if not isinstance(typed, dict):
        raise Refusal("REQUEST_MISMATCH", "the request carries no typed data")
    if typed.get("primary_type") != PRIMARY_TYPE or set(typed.get("types") or {}) != {PRIMARY_TYPE}:
        raise Refusal("REQUEST_MISMATCH", f"only {PRIMARY_TYPE} is co-signed")

    # 3. The typed data is USDC on this network, from this wallet, to the decided
    #    recipient, for the decided amount, for a short validity.
    chain = cfg.chain
    domain, message = typed.get("domain") or {}, typed.get("message") or {}
    if _int(domain.get("chainId"), "chainId") != chain.chain_id:
        raise Refusal("REQUEST_MISMATCH", f"the payment is not on {chain.key}")
    if _lower(domain.get("verifyingContract")) != chain.usdc:
        raise Refusal("REQUEST_MISMATCH", f"the token is not USDC on {chain.key}")
    if _lower(args.get("network")) not in (chain.key, f"eip155:{chain.chain_id}"):
        raise Refusal("DECISION_MISMATCH", "the decision names another network")
    if _lower(message.get("from")) != cfg.wallet_address:
        raise Refusal("REQUEST_MISMATCH", "the payment is not from this wallet")
    if _lower(message.get("to")) != _lower(args.get("pay_to")) or not _lower(args.get("pay_to")):
        raise Refusal("REQUEST_MISMATCH", "the recipient differs from the decided one")
    value = _int(message.get("value"), "value")
    if value != _int(args.get("amount_atomic"), "amount_atomic") or value <= 0:
        raise Refusal("REQUEST_MISMATCH", "the amount differs from the decided one")
    usdc = Decimal(value) / (10 ** chain.decimals)
    # the gate rounds the mandate amount UP to a cent; the signed value may not exceed it
    decided = Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_UP)
    if usdc > decided:
        raise Refusal("DECISION_MISMATCH", f"the payment ({usdc} USDC) exceeds the decided amount ({decided})")
    payee = _lower(claims.get("payee"))
    host = _lower(urlsplit(str(args.get("url") or "")).hostname)
    if payee and host and payee != host:
        raise Refusal("DECISION_MISMATCH", "the decision's counterparty is not the resource's host")
    valid_after, valid_before = _int(message.get("validAfter"), "validAfter"), _int(message.get("validBefore"), "validBefore")
    if valid_before <= now:
        raise Refusal("REQUEST_MISMATCH", "the authorization has already expired")
    if valid_before - valid_after > cfg.max_validity_seconds or valid_before - now > cfg.max_validity_seconds + 60:
        raise Refusal("REQUEST_MISMATCH", f"the authorization is valid for longer than {cfg.max_validity_seconds}s")
    nonce = str(message.get("nonce") or "")
    if not (nonce.startswith("0x") and len(nonce) == 66):
        raise Refusal("REQUEST_MISMATCH", "the authorization nonce is malformed")

    # 4. This host's own ceilings, under the Privy policy and the Regent mandate.
    if cfg.max_usdc_per_payment > 0 and usdc > cfg.max_usdc_per_payment:
        raise Refusal("LIMIT", f"{usdc} USDC is above this signer's ceiling of {cfg.max_usdc_per_payment} per payment")
    return usdc
