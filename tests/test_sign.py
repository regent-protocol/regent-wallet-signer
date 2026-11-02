"""The signer co-signs exactly one Privy request per verified Regent decision, and
refuses everything else by name. Regent Control (the JWKS and the token), the Regent
gateway (its quorum key) and Privy are fakes; the cryptography is real."""

from __future__ import annotations

import base64
import json
import time
import uuid
from decimal import Decimal
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from httpx import ASGITransport, AsyncClient

from regent_wallet_signer.app import create_app
from regent_wallet_signer.canonical import canonical_args_hash, canonical_request
from regent_wallet_signer.chains import CHAINS
from regent_wallet_signer.config import Settings
from regent_wallet_signer.keys import P256Key, verify_p256
from regent_wallet_signer.state import State

SEPOLIA = CHAINS["base-sepolia"]
WALLET = "0x79b2ac728d7d00b35e8f1942acb4a9b9008a4f4e"
PAY_TO = "0x3d7e0309f8e90db8a66d4f425db20a5eb2380586"
APP_ID, SECRET, TOKEN = "cm_app_test", "privy_secret_test", "signer-token-test"
JWKS_URL = "https://control.test/v1/control/.well-known/jwks.json"
KEY_URL = "https://gw.test/.well-known/x402-signer.json"
PRIVY = "https://privy.test"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class Control:
    """Regent Control's token issuer, as far as the signer sees it."""

    def __init__(self, issuer="regent-control"):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "kid-test"
        self.issuer = issuer

    def jwks(self):
        nums = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                          "n": _b64url(nums.n.to_bytes(256, "big")), "e": _b64url(nums.e.to_bytes(3, "big"))}]}

    def issue(self, *, tool="x402", action="PAY api.example.com", resource="https://api.example.com/v1/quote",
              args=None, amount=0.01, currency="USDC", payee="api.example.com", ttl=60, now=None, kid=None, **extra):
        now = now if now is not None else time.time()
        claims = {"iss": self.issuer, "sub": "agent_1", "aud": tool, "scope": f"{tool}:{action}",
                  "decision_id": "dec_" + uuid.uuid4().hex[:12], "jti": uuid.uuid4().hex,
                  "iat": int(now), "exp": int(now + ttl),
                  "args_hash": canonical_args_hash(tool, action, resource, args or {}),
                  "amount": amount, "currency": currency, "payee": payee, "payee_source": "rail", **extra}
        header = {"alg": "RS256", "typ": "JWT", "kid": kid or self.kid}
        signing = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
        sig = self.key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing}.{_b64url(sig)}", claims


class Fakes:
    """Outbound HTTP: the JWKS, the gateway's key document, and Privy."""

    def __init__(self, control: Control, regent_key: P256Key, *, privy_status=200, privy_body=None):
        self.control, self.regent_key = control, regent_key
        self.privy_status, self.privy_body = privy_status, privy_body
        self.privy_calls: list[dict] = []
        self.gets: list[str] = []

    async def get(self, url, timeout=None):
        self.gets.append(url)
        if url == JWKS_URL:
            return SimpleNamespace(status_code=200, json=lambda: self.control.jwks(), raise_for_status=lambda: None)
        if url == KEY_URL:
            return SimpleNamespace(status_code=200, raise_for_status=lambda: None,
                                   json=lambda: {"providers": {"privy": {"public_key": self.regent_key.public_key_b64}}})
        raise AssertionError(url)

    async def request(self, method, url, content=None, headers=None, timeout=None):
        assert url.startswith(PRIVY)
        self.privy_calls.append({"method": method, "url": url, "headers": dict(headers or {}),
                                 "body": json.loads(content) if content else None})
        body = self.privy_body if self.privy_body is not None else {
            "method": "eth_signTypedData_v4", "data": {"signature": "0x" + "ab" * 65, "encoding": "hex"}}
        return SimpleNamespace(status_code=self.privy_status, content=json.dumps(body).encode())


def settings(**over):
    base = dict(signer_token=TOKEN, privy_app_id=APP_ID, privy_app_secret=SECRET, client_key_b64=P256Key.generate().private_key_b64,
                wallet_id="w_test", wallet_address=WALLET, network="base-sepolia", privy_api_base=PRIVY,
                regent_jwks_url=JWKS_URL, regent_signer_key_url=KEY_URL)
    return Settings(**{**base, **over})


def typed(*, value=10000, to=PAY_TO, frm=WALLET, chain=SEPOLIA, now=None, validity=300, contract=None):
    now = int(now if now is not None else time.time())
    return {"domain": {"name": "USDC", "version": "2", "chainId": chain.chain_id,
                       "verifyingContract": contract or chain.usdc_checksummed},
            "types": {"TransferWithAuthorization": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"},
                                                    {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
                                                    {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}]},
            "primary_type": "TransferWithAuthorization",
            "message": {"from": frm, "to": to, "value": hex(value), "validAfter": hex(now - 60),
                        "validBefore": hex(now - 60 + validity), "nonce": "0x" + "11" * 32}}


def gateway_call(control: Control, regent_key: P256Key, cfg: Settings, *, value=10000, amount=0.01, args_over=None,
                 typed_over=None, token_over=None, url=None):
    """What the Regent gateway sends: the decision, the Privy request, Regent's signature."""
    args = {"url": "https://api.example.com/v1/quote", "method": "GET", "amount_atomic": str(value), "pay_to": PAY_TO,
            "network": "base-sepolia", **(args_over or {})}
    token, claims = control.issue(args=args, amount=amount, **(token_over or {}))
    body = {"method": "eth_signTypedData_v4", "params": {"typed_data": typed(**{"value": value, **(typed_over or {})})}}
    url = url or f"{PRIVY}/v1/wallets/{cfg.wallet_id}/rpc"
    headers = {"privy-app-id": APP_ID}
    sig = regent_key.sign(canonical_request("POST", url, body, headers))
    return {"decision": {"token": token, "tool": "x402", "action": "PAY api.example.com",
                         "resource": "https://api.example.com/v1/quote", "args": args},
            "request": {"method": "POST", "url": url, "body": body, "headers": headers},
            "regent_signature": sig}, claims


async def post(app, body, token=TOKEN):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://signer") as c:
        return await c.post("/v1/sign", json=body, headers={"Authorization": f"Bearer {token}"})


async def test_a_verified_decision_is_co_signed_once_with_both_signatures():
    control, regent = Control(), P256Key.generate()
    cfg = settings()
    fakes = Fakes(control, regent)
    app = create_app(cfg, http=fakes)
    body, claims = gateway_call(control, regent, cfg)
    r = await post(app, body)
    assert r.status_code == 200, r.text
    assert r.json() == {"signature": "0x" + "ab" * 65, "decision_id": claims["decision_id"]}
    call = fakes.privy_calls[0]
    assert call["url"] == f"{PRIVY}/v1/wallets/w_test/rpc" and call["body"] == body["request"]["body"]
    assert call["headers"]["Authorization"] == "Basic " + base64.b64encode(f"{APP_ID}:{SECRET}".encode()).decode()
    regent_sig, client_sig = call["headers"]["privy-authorization-signature"].split(",")
    payload = canonical_request("POST", call["url"], call["body"], {"privy-app-id": APP_ID})
    assert regent_sig == body["regent_signature"] and verify_p256(regent.public_key_b64, payload, regent_sig)
    assert verify_p256(P256Key(cfg.client_key_b64).public_key_b64, payload, client_sig)
    # the same decision a second time: nothing signed
    r = await post(app, body)
    assert r.status_code == 403 and r.json()["code"] == "DECISION_REUSED" and len(fakes.privy_calls) == 1


async def test_without_the_bearer_token_nothing_is_read():
    control, regent = Control(), P256Key.generate()
    cfg = settings()
    fakes = Fakes(control, regent)
    body, _ = gateway_call(control, regent, cfg)
    r = await post(create_app(cfg, http=fakes), body, token="wrong")
    assert r.status_code == 401 and fakes.gets == [] and fakes.privy_calls == []


@pytest.mark.parametrize("tamper, code", [
    (dict(token_over={"ttl": -120}), "DECISION_EXPIRED"),
    (dict(token_over={"kid": "unknown"}), "DECISION_INVALID"),
    (dict(token_over={"currency": "USD"}), "DECISION_MISMATCH"),
    (dict(token_over={"action": "PAY other.example"}), "DECISION_MISMATCH"),
    (dict(typed_over={"value": 10001}), "REQUEST_MISMATCH"),  # signed more than decided
    (dict(typed_over={"to": "0x" + "99" * 20}), "REQUEST_MISMATCH"),
    (dict(typed_over={"frm": "0x" + "88" * 20}), "REQUEST_MISMATCH"),
    (dict(typed_over={"chain": CHAINS["base"]}), "REQUEST_MISMATCH"),
    (dict(typed_over={"contract": "0x" + "77" * 20}), "REQUEST_MISMATCH"),
    (dict(typed_over={"validity": 4000}), "REQUEST_MISMATCH"),
    (dict(url=f"{PRIVY}/v1/wallets/w_other/rpc"), "REQUEST_MISMATCH"),
    (dict(value=2_000_000, amount=0.01), "DECISION_MISMATCH"),  # the decision covers less than the signature
])
async def test_a_request_that_is_not_the_decision_is_refused_by_name(tamper, code):
    control, regent = Control(), P256Key.generate()
    cfg = settings()
    fakes = Fakes(control, regent)
    body, _ = gateway_call(control, regent, cfg, **tamper)
    if "args_over" not in tamper and tamper.get("value"):
        body["decision"]["args"]["amount_atomic"] = str(tamper["value"])  # args match the signature; the token does not
    r = await post(create_app(cfg, http=fakes), body)
    assert r.status_code == 403 and r.json()["code"] == code, r.text
    assert fakes.privy_calls == []


async def test_args_the_token_did_not_commit_to_are_refused():
    control, regent = Control(), P256Key.generate()
    cfg = settings()
    body, _ = gateway_call(control, regent, cfg)
    body["decision"]["args"]["pay_to"] = "0x" + "66" * 20  # the hash in the token no longer matches
    r = await post(create_app(cfg, http=Fakes(control, regent)), body)
    assert r.status_code == 403 and r.json()["code"] == "DECISION_MISMATCH"


async def test_a_request_not_signed_by_regents_quorum_key_is_refused():
    control, regent, impostor = Control(), P256Key.generate(), P256Key.generate()
    cfg = settings()
    body, _ = gateway_call(control, impostor, cfg)  # a valid token, but the wrong key signed the Privy request
    fakes = Fakes(control, regent)
    r = await post(create_app(cfg, http=fakes), body)
    assert r.status_code == 403 and r.json()["code"] == "REGENT_SIGNATURE_INVALID" and fakes.privy_calls == []


async def test_the_signers_own_ceilings_hold_under_the_mandate():
    control, regent = Control(), P256Key.generate()
    cfg = settings(max_usdc_per_payment=Decimal("0.005"))
    body, _ = gateway_call(control, regent, cfg)
    r = await post(create_app(cfg, http=Fakes(control, regent)), body)
    assert r.status_code == 403 and r.json()["code"] == "LIMIT"
    cfg = settings(daily_usdc=Decimal("0.015"))
    fakes = Fakes(control, regent)
    app = create_app(cfg, http=fakes, state=State())
    assert (await post(app, gateway_call(control, regent, cfg)[0])).status_code == 200
    r = await post(app, gateway_call(control, regent, cfg)[0])
    assert r.status_code == 403 and r.json()["code"] == "LIMIT" and len(fakes.privy_calls) == 1


async def test_privy_refusals_are_named_and_the_decision_stays_spent():
    control, regent = Control(), P256Key.generate()
    cfg = settings()
    fakes = Fakes(control, regent, privy_status=403, privy_body={"error": "policy_violation: rule denied"})
    body, _ = gateway_call(control, regent, cfg)
    app = create_app(cfg, http=fakes)
    r = await post(app, body)
    assert r.status_code == 403 and r.json()["code"] == "WALLET_POLICY_REFUSED"
    r = await post(app, body)  # a retry of the same decision never reaches Privy again
    assert r.json()["code"] == "DECISION_REUSED" and len(fakes.privy_calls) == 1
    fakes = Fakes(control, regent, privy_status=401, privy_body={"error": "Not enough valid authorization signatures"})
    r = await post(create_app(cfg, http=fakes), gateway_call(control, regent, cfg)[0])
    assert r.json()["code"] == "WALLET_AUTH_REFUSED"


async def test_state_survives_a_restart(tmp_path):
    path = str(tmp_path / "signer.json")
    st = State(path)
    st.mark_used("dec_1", int(time.time()) + 300)
    st.add_spent(Decimal("0.25"))
    again = State(path)
    assert again.already_used("dec_1") and again.spent_today() == Decimal("0.25")
    assert not again.already_used("dec_2")


def test_health_names_the_binding_without_secrets():
    cfg = settings()
    app = create_app(cfg, http=Fakes(Control(), P256Key.generate()))
    import asyncio

    async def go():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://signer") as c:
            return await c.get("/v1/health")
    r = asyncio.run(go())
    data = r.json()
    assert data["ok"] and data["wallet_id"] == "w_test" and data["address"] == WALLET and data["network"] == "base-sepolia"
    assert SECRET not in r.text and cfg.client_key_b64 not in r.text and TOKEN not in r.text


def test_keys_round_trip_privys_encoding(tmp_path):
    key = P256Key.generate()
    key.save(tmp_path / "k")
    again = P256Key.load(tmp_path / "k")
    assert again.public_key_b64 == key.public_key_b64
    pub = serialization.load_der_public_key(base64.b64decode(key.public_key_b64))
    assert pub.curve.name == "secp256r1"
    assert P256Key("wallet-auth:" + key.private_key_b64).public_key_b64 == key.public_key_b64
