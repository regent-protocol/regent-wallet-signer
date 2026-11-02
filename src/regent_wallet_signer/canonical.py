"""Two canonical forms, byte-identical to their counterparts in Regent.

* ``canonical_request``: what a Privy authorization signature covers (Privy's own SDKs:
  ``{version:1, method, url, body, headers:{privy-*}}``, sorted keys, compact).
* ``canonical_args_hash``: what a Regent decision token's ``args_hash`` claim commits to
  (``{tool, action, resource, args}``, sorted keys, compact, SHA-256 hex).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_request(method: str, url: str, body: Any, headers: dict[str, str]) -> bytes:
    if (isinstance(body, dict) and not body) or (isinstance(body, (list, tuple)) and not body):
        body = ""
    payload = {
        "version": 1,
        "method": method.upper(),
        "url": url.rstrip("/"),
        "body": body,
        "headers": {k: v for k, v in headers.items() if k.lower().startswith("privy-")},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def canonical_args_hash(tool: str, action: str, resource: str | None, args: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"tool": tool, "action": action, "resource": resource, "args": args},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
