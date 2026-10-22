"""Small key-value store abstraction with TTL.

Used for pending logins, sessions and the SAML assertion replay cache.
Swap `InMemoryTTLStore` for a Redis-backed implementation in multi-instance deployments.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Protocol


class TTLStore(Protocol):
    def get(self, key: str) -> Any | None: ...
    def set(self, key: str, value: Any, ttl_seconds: int) -> None: ...
    def pop(self, key: str) -> Any | None: ...
    def delete(self, key: str) -> None: ...
    def add_if_absent(self, key: str, value: Any, ttl_seconds: int) -> bool: ...


class InMemoryTTLStore:
    """Process-local store. Not shared between workers — dev / single instance only."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def _live(self, key: str) -> tuple[float, Any] | None:
        item = self._data.get(key)
        if item is None:
            return None
        if item[0] < time.monotonic():
            del self._data[key]
            return None
        return item

    def get(self, key: str) -> Any | None:
        with self._lock:
            item = self._live(key)
            return item[1] if item else None

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        with self._lock:
            self._data[key] = (time.monotonic() + ttl_seconds, value)

    def pop(self, key: str) -> Any | None:
        with self._lock:
            item = self._live(key)
            self._data.pop(key, None)
            return item[1] if item else None

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def add_if_absent(self, key: str, value: Any, ttl_seconds: int) -> bool:
        with self._lock:
            if self._live(key) is not None:
                return False
            self._data[key] = (time.monotonic() + ttl_seconds, value)
            return True
