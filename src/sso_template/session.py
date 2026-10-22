"""Server-side sessions. The browser only holds an opaque random session id."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field, replace

from sso_template.auth.base import Identity
from sso_template.settings import Settings
from sso_template.store import TTLStore


@dataclass(frozen=True)
class Session:
    identity: Identity
    created_at: float
    last_seen: float
    logout_hint: dict[str, str | None] = field(default_factory=dict)


class SessionManager:
    def __init__(self, store: TTLStore, settings: Settings) -> None:
        self.store = store
        self.idle = settings.session_idle_seconds
        self.absolute = settings.session_absolute_seconds

    @staticmethod
    def _key(sid: str) -> str:
        return f"session:{sid}"

    def create(self, identity: Identity, logout_hint: dict[str, str | None]) -> str:
        sid = secrets.token_urlsafe(32)
        now = time.time()
        self.store.set(self._key(sid), Session(identity, now, now, logout_hint), self.idle)
        return sid

    def load(self, sid: str | None) -> Session | None:
        if not sid:
            return None
        sess: Session | None = self.store.get(self._key(sid))
        if sess is None:
            return None
        now = time.time()
        if now - sess.created_at > self.absolute:
            self.store.delete(self._key(sid))
            return None
        sess = replace(sess, last_seen=now)
        self.store.set(self._key(sid), sess, self.idle)  # sliding idle timeout
        return sess

    def destroy(self, sid: str | None) -> Session | None:
        if not sid:
            return None
        return self.store.pop(self._key(sid))
