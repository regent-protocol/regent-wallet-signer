"""regent-wallet-signer keygen | setup | serve

    keygen  --key-file ./client.key
        A new P-256 key for this host. Its public half joins the quorum.

    setup   --key-file ./client.key --network base --cap 1.00 [--regent-key-url …]
        With PRIVY_APP_ID and PRIVY_APP_SECRET in the environment: creates in YOUR Privy
        app a 2-of-2 key quorum (this key + Regent's published key), a policy (USDC on
        the network, at most the cap per signature), and a wallet owned by the quorum
        under that policy. Prints the settings to run the service and what to paste into
        the Regent console. Nothing is sent to Regent.

    serve
        Runs the service on LISTEN (default 127.0.0.1:8402) from the environment.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
from decimal import Decimal, InvalidOperation

import httpx

from regent_wallet_signer.chains import CHAINS, chain_for
from regent_wallet_signer.config import DEFAULT_PRIVY, DEFAULT_SIGNER_KEY_URL, Settings
from regent_wallet_signer.keys import P256Key
from regent_wallet_signer.privy import PrivyApp, policy_for
from regent_wallet_signer.regent import Refusal


def _keygen(args: argparse.Namespace) -> int:
    if os.path.exists(args.key_file) and not args.force:
        print(f"{args.key_file} exists; pass --force to overwrite (the old key leaves any quorum it is in)", file=sys.stderr)
        return 2
    key = P256Key.generate()
    key.save(args.key_file)
    print(f"wrote {args.key_file} (mode 600)\npublic key: {key.public_key_b64}")
    return 0


async def _regent_key(url: str) -> str:
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(url)
        r.raise_for_status()
        doc = r.json()
    key = str(((doc.get("providers") or {}).get("privy") or {}).get("public_key") or "")
    if not key:
        raise SystemExit(f"{url} publishes no Privy signer key")
    return key


async def _setup(args: argparse.Namespace) -> int:
    app_id, secret = os.environ.get("PRIVY_APP_ID", ""), os.environ.get("PRIVY_APP_SECRET", "")
    if not app_id or not secret:
        print("PRIVY_APP_ID and PRIVY_APP_SECRET must be in the environment", file=sys.stderr)
        return 2
    chain = chain_for(args.network)
    if chain is None:
        print(f"--network must be one of {', '.join(CHAINS)}", file=sys.stderr)
        return 2
    try:
        cap = Decimal(args.cap)
    except InvalidOperation:
        print("--cap must be a number of USDC", file=sys.stderr)
        return 2
    if not (Decimal("0.000001") <= cap <= Decimal("100000")):
        print("--cap must be between 0.000001 and 100000 USDC", file=sys.stderr)
        return 2
    key = P256Key.load(args.key_file)
    regent_key = args.regent_public_key or await _regent_key(args.regent_key_url)
    privy = PrivyApp(app_id=app_id, app_secret=secret, base_url=args.privy_api_base)
    label = args.label or f"Regent x402 ({chain.key})"
    try:
        quorum_id = await privy.create_key_quorum([key.public_key_b64, regent_key], threshold=2,
                                                  display_name=f"2-of-2 · {label}")
        policy_id = await privy.create_policy(policy_for(chain, cap, name=f"{label} · cap {cap} USDC",
                                                         owner_id=quorum_id if args.policy_owner == "quorum" else None))
        wallet_id, address = await privy.create_wallet(owner_id=quorum_id, policy_id=policy_id, display_name=label)
    except Refusal as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 1
    token = secrets.token_urlsafe(32)
    env = {
        "SIGNER_TOKEN": token, "PRIVY_APP_ID": app_id, "CLIENT_KEY_FILE": os.path.abspath(args.key_file),
        "WALLET_ID": wallet_id, "WALLET_ADDRESS": address.lower(), "NETWORK": chain.key,
        "REGENT_SIGNER_PUBLIC_KEY": regent_key,
    }
    if args.privy_api_base != DEFAULT_PRIVY:
        env["PRIVY_API_BASE"] = args.privy_api_base
    print("# Created in your Privy app:")
    print(f"#   key quorum {quorum_id} (2 of 2: this host + Regent)")
    print(f"#   policy     {policy_id} (USDC on {chain.key}, at most {cap} per signature)")
    print(f"#   wallet     {wallet_id} = {address}")
    print("#\n# Run the service with (PRIVY_APP_SECRET stays in your secret store):")
    for k, v in env.items():
        print(f"{k}={v}")
    print("#\n# Paste into the Regent console (Connect → Gateway → Your wallet, through Privy → 2-of-2):")
    print(json.dumps({"mode": "quorum", "signer_url": args.public_url or "https://<this host>",
                      "signer_token": token, "app_id": app_id, "wallet_id": wallet_id,
                      "address": address.lower(), "network": chain.key, "cap_usdc": str(cap)}, indent=2))
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from regent_wallet_signer.app import create_app

    try:
        cfg = Settings.from_env()
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    host, _, port = cfg.listen.rpartition(":")
    uvicorn.run(create_app(cfg), host=host or "127.0.0.1", port=int(port or 8402), log_level="info")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="regent-wallet-signer", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--key-file", default="./client.key")
    k.add_argument("--force", action="store_true")
    s = sub.add_parser("setup")
    s.add_argument("--key-file", default="./client.key")
    s.add_argument("--network", default="base-sepolia")
    s.add_argument("--cap", default="1.00", help="USDC per signature, enforced by Privy's policy")
    s.add_argument("--label", default="")
    s.add_argument("--public-url", default="", help="where the Regent gateway reaches this service")
    s.add_argument("--regent-key-url", default=DEFAULT_SIGNER_KEY_URL)
    s.add_argument("--regent-public-key", default="", help="pin Regent's key instead of reading the URL")
    s.add_argument("--privy-api-base", default=DEFAULT_PRIVY)
    s.add_argument("--policy-owner", choices=("quorum", "app"), default="quorum",
                   help="who may change the cap: the 2-of-2 quorum (default) or your app secret alone")
    sub.add_parser("serve")
    args = p.parse_args(argv)
    if args.cmd == "keygen":
        return _keygen(args)
    if args.cmd == "setup":
        return asyncio.run(_setup(args))
    return _serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
