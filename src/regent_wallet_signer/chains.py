"""The networks an x402 payment may be signed on, and USDC on each. The same registry
the Regent gateway uses: a chain or token not listed here is refused by name."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Chain:
    key: str  # x402 v1 slug, and Regent's `settlement_network`
    chain_id: int
    usdc: str  # USDC contract, lowercase
    usdc_checksummed: str  # the same, EIP-55, as a Privy policy condition is written
    decimals: int
    testnet: bool


CHAINS: dict[str, Chain] = {
    "base-sepolia": Chain("base-sepolia", 84532, "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
                          "0x036CbD53842c5426634e7929541eC2318f3dCF7e", 6, True),
    "base": Chain("base", 8453, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                  "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6, False),
}


def chain_for(network: str | None) -> Chain | None:
    if not network:
        return None
    s = str(network).strip().lower()
    if s in CHAINS:
        return CHAINS[s]
    if s.startswith("eip155:"):
        try:
            cid = int(s.split(":", 1)[1])
        except ValueError:
            return None
        return next((c for c in CHAINS.values() if c.chain_id == cid), None)
    return None
