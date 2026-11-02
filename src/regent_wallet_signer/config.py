"""Configuration from the environment. Everything secret stays on the client's host:
the Privy app secret and the client's quorum key are never sent anywhere but Privy."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from decimal import Decimal

from regent_wallet_signer.chains import CHAINS, Chain, chain_for

DEFAULT_JWKS = "https://control-api.regentprotocol.org/v1/control/.well-known/jwks.json"
DEFAULT_SIGNER_KEY_URL = "https://gw.regentprotocol.org/.well-known/x402-signer.json"
DEFAULT_PRIVY = "https://api.privy.io"


@dataclass
class Settings:
    signer_token: str  # what the Regent gateway presents on /v1/sign (shared once, in the console)
    privy_app_id: str
    privy_app_secret: str
    client_key_b64: str  # this host's quorum key (base64 DER PKCS#8)
    wallet_id: str
    wallet_address: str
    network: str = "base-sepolia"
    privy_api_base: str = DEFAULT_PRIVY
    regent_jwks_url: str = DEFAULT_JWKS
    regent_issuer: str = "regent-control"
    regent_signer_key_url: str = DEFAULT_SIGNER_KEY_URL
    regent_signer_public_key: str = ""  # pinned; when empty it is read from the URL above
    max_usdc_per_payment: Decimal = Decimal("0")  # 0 = the Privy policy's cap is the only ceiling
    daily_usdc: Decimal = Decimal("0")  # 0 = no daily ceiling here
    max_validity_seconds: int = 300
    state_file: str = ""  # used decision ids + today's total; memory only when empty
    listen: str = "127.0.0.1:8402"
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def chain(self) -> Chain:
        c = chain_for(self.network)
        if c is None:
            raise ValueError(f"NETWORK must be one of {', '.join(CHAINS)}")
        return c

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        e = env if env is not None else os.environ
        missing = [k for k in ("SIGNER_TOKEN", "PRIVY_APP_ID", "PRIVY_APP_SECRET", "WALLET_ID", "WALLET_ADDRESS")
                   if not e.get(k)]
        key_b64 = e.get("CLIENT_KEY", "")
        key_file = e.get("CLIENT_KEY_FILE", "")
        if not key_b64 and key_file:
            from pathlib import Path

            key_b64 = Path(key_file).read_text().strip()
        if not key_b64:
            missing.append("CLIENT_KEY or CLIENT_KEY_FILE")
        if missing:
            raise ValueError("missing settings: " + ", ".join(missing))
        return cls(
            signer_token=e["SIGNER_TOKEN"],
            privy_app_id=e["PRIVY_APP_ID"],
            privy_app_secret=e["PRIVY_APP_SECRET"],
            client_key_b64=key_b64,
            wallet_id=e["WALLET_ID"],
            wallet_address=e["WALLET_ADDRESS"].lower(),
            network=e.get("NETWORK", "base-sepolia").strip().lower(),
            privy_api_base=e.get("PRIVY_API_BASE", DEFAULT_PRIVY).rstrip("/"),
            regent_jwks_url=e.get("REGENT_JWKS_URL", DEFAULT_JWKS),
            regent_issuer=e.get("REGENT_ISSUER", "regent-control"),
            regent_signer_key_url=e.get("REGENT_SIGNER_KEY_URL", DEFAULT_SIGNER_KEY_URL),
            regent_signer_public_key=e.get("REGENT_SIGNER_PUBLIC_KEY", ""),
            max_usdc_per_payment=Decimal(e.get("MAX_USDC_PER_PAYMENT", "0") or "0"),
            daily_usdc=Decimal(e.get("DAILY_USDC", "0") or "0"),
            max_validity_seconds=int(e.get("MAX_VALIDITY_SECONDS", "300") or "300"),
            state_file=e.get("STATE_FILE", ""),
            listen=e.get("LISTEN", "127.0.0.1:8402"),
        )
