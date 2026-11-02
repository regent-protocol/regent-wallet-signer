# regent-wallet-signer

The client's half of a 2-of-2 [Privy](https://privy.io) wallet governed by
[Regent](https://regentprotocol.org). Your agents pay web resources over
[x402](https://docs.regentprotocol.org/gateway/x402) from a wallet that nobody can
move funds from alone:

- the wallet at Privy is owned by a **key quorum of two P-256 keys, threshold 2**: this
  host's key and the Regent gateway's key;
- **Regent holds no app secret and one key of two**: on its own it signs nothing;
- **this service holds your app secret and the other key**, and adds its signature only
  to a request that carries a Regent decision token verified against Regent's published
  JWKS and matching that exact payment (recipient, amount, token, network, wallet, a
  validity of at most 300 s), once per decision, within your own ceilings.

So an agent, a leaked app secret, or a leaked bearer token cannot pay past the owner's
mandate, and Regent cannot pay without you. Privy's own policy (USDC on one network, at
most X per signature) is the third ceiling, enforced in Privy's enclave.

## Install

```bash
pip install regent-wallet-signer           # or: docker build -t regent-wallet-signer .
```

## Set up (once)

```bash
regent-wallet-signer keygen --key-file ./client.key
export PRIVY_APP_ID=…  PRIVY_APP_SECRET=…          # your Privy app (the free plan is enough)
regent-wallet-signer setup --key-file ./client.key --network base-sepolia --cap 1.00 \
    --public-url https://signer.example.com
```

`setup` creates, in **your** Privy app, the quorum (your key + Regent's key, read from
`https://gw.regentprotocol.org/.well-known/x402-signer.json`), the policy and the wallet
owned by the quorum, then prints the environment for `serve` and a JSON block to paste
into the Regent console (Connect → Gateway → *Your wallet, through Privy* → **2-of-2**).
Nothing is sent to Regent by `setup`; you paste the block yourself.

By default the policy is owned by the quorum too, so the cap changes only when both keys
agree (`--policy-owner app` leaves it to your app secret alone).

## Run

```bash
export SIGNER_TOKEN=… PRIVY_APP_ID=… PRIVY_APP_SECRET=… CLIENT_KEY_FILE=./client.key \
       WALLET_ID=… WALLET_ADDRESS=0x… NETWORK=base-sepolia
regent-wallet-signer serve                 # LISTEN=0.0.0.0:8402 behind your TLS
```

| Variable | Meaning |
|---|---|
| `SIGNER_TOKEN` | the bearer the Regent gateway presents; printed by `setup`, pasted into the console |
| `PRIVY_APP_ID`, `PRIVY_APP_SECRET` | your Privy app; the secret never leaves this host except to Privy |
| `CLIENT_KEY_FILE` or `CLIENT_KEY` | this host's quorum key (base64 DER PKCS#8) |
| `WALLET_ID`, `WALLET_ADDRESS`, `NETWORK` | the wallet this service co-signs for; `base-sepolia` or `base` |
| `MAX_USDC_PER_PAYMENT`, `DAILY_USDC` | your own ceilings here, under the mandate and the Privy policy (0 = none) |
| `REGENT_SIGNER_PUBLIC_KEY` | pin Regent's quorum key (printed by `setup`); otherwise it is read from the gateway |
| `REGENT_JWKS_URL`, `REGENT_ISSUER` | where Regent Control publishes its token keys (defaults are production) |
| `STATE_FILE` | co-signed decision ids and today's total, so a restart forgets nothing |

Put the service behind TLS on a host the Regent gateway can reach (a public address: the
gateway refuses private ones). `GET /v1/health` shows what it is bound to and holds no secret.

## What one call looks like

```
POST /v1/sign                     Authorization: Bearer <SIGNER_TOKEN>
{
  "decision": {"token": "<Regent decision JWT>", "tool": "x402", "action": "PAY api.example.com",
               "resource": "https://api.example.com/v1/quote", "args": {"url": …, "method": "GET",
               "amount_atomic": "10000", "pay_to": "0x…", "network": "base-sepolia"}},
  "request":  {"method": "POST", "url": "https://api.privy.io/v1/wallets/<id>/rpc",
               "body": {"method": "eth_signTypedData_v4", "params": {"typed_data": {…}}},
               "headers": {"privy-app-id": "…"}},
  "regent_signature": "<Regent's ECDSA over Privy's canonical form of request>"
}
→ 200 {"signature": "0x…", "decision_id": "dec_…"}
```

Checks, in order: bearer token · decision token (RS256 against the JWKS, issuer, expiry,
`args_hash` over `{tool, action, resource, args}`) · the decision is in USDC, for this
host's amount and recipient · the request is this wallet's RPC, `eth_signTypedData_v4`,
`TransferWithAuthorization`, USDC on this network, from this wallet, to `pay_to`, for
`amount_atomic`, at most the decided amount, validity ≤ 300 s · your ceilings · Regent's
quorum key signed the request · the decision was not co-signed before. Then this host
signs the same canonical request and asks Privy with both signatures. A refusal names
its reason (`DECISION_*`, `REQUEST_MISMATCH`, `LIMIT`, `REGENT_SIGNATURE_INVALID`,
`WALLET_POLICY_REFUSED`, `WALLET_AUTH_REFUSED`) and nothing is signed.

## Why this shape

A wallet whose policy lets one outside key sign alone is, for US money-transmission
purposes, controlled by whoever holds that key. A 2-of-2 quorum where the governing
service holds one key and no app secret is the "additional validation at the request
of the owner" shape (FinCEN FIN-2019-G001 §4.2.2): it cannot move your funds by itself,
and you cannot move them past your own mandate. The code is short on purpose so you can
read every check.

Apache-2.0.
