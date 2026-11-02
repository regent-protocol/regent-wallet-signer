"""What the signer remembers: decision ids already co-signed (one decision, one
signature) and today's total. In memory, mirrored to a JSON file when one is configured
so a restart does not forget a decision signed a minute ago."""

from __future__ import annotations

import json
import time
from decimal import Decimal
from pathlib import Path


class State:
    def __init__(self, path: str = "") -> None:
        self._path = Path(path) if path else None
        self._used: dict[str, int] = {}  # decision_id -> expiry (unix)
        self._day = ""
        self._spent = Decimal("0")
        self._load()

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
            self._used = {str(k): int(v) for k, v in (data.get("used") or {}).items()}
            self._day = str(data.get("day") or "")
            self._spent = Decimal(str(data.get("spent") or "0"))
        except (ValueError, OSError):
            pass

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"used": self._used, "day": self._day, "spent": str(self._spent)}))
            tmp.replace(self._path)
        except OSError:
            pass

    def _prune(self, now: int) -> None:
        self._used = {k: v for k, v in self._used.items() if v > now}

    def already_used(self, decision_id: str, now: int | None = None) -> bool:
        now = int(now if now is not None else time.time())
        self._prune(now)
        return decision_id in self._used

    def mark_used(self, decision_id: str, expires: int, now: int | None = None) -> None:
        now = int(now if now is not None else time.time())
        self._prune(now)
        self._used[decision_id] = max(int(expires), now + 60)
        self._save()

    def spent_today(self, now: float | None = None) -> Decimal:
        day = time.strftime("%Y-%m-%d", time.gmtime(now if now is not None else time.time()))
        if day != self._day:
            self._day, self._spent = day, Decimal("0")
        return self._spent

    def add_spent(self, amount: Decimal, now: float | None = None) -> None:
        self.spent_today(now)
        self._spent += amount
        self._save()
