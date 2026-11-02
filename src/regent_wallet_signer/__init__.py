"""regent-wallet-signer: the client's half of a 2-of-2 Privy wallet governed by Regent.

The wallet at Privy is owned by a key quorum of two P-256 keys with threshold 2: the
client's key (held here, next to the client's Privy app secret) and Regent's key (held
by the Regent gateway). Privy signs nothing unless both keys authorize the same request.

Regent never holds the app secret or this key, so Regent alone cannot move funds. This
service never signs without a Regent decision token that verifies against Regent's
published JWKS and matches the exact payment, so the client's own agents (or anyone
holding the app secret) cannot move funds past the owner's mandate either.
"""

__version__ = "0.1.0"
