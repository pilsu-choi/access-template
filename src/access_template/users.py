"""Just-in-time user provisioning. Replace `InMemoryUserRepository` with a DB-backed one."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from access_template.auth.base import Identity


@dataclass
class User:
    id: str
    tenant: str
    subject: str
    email: str | None
    name: str | None
    roles: frozenset[str]
    first_login: float
    last_login: float


class UserRepository(Protocol):
    def upsert(self, identity: Identity) -> User: ...
    def get(self, user_id: str) -> User | None: ...


class InMemoryUserRepository:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def upsert(self, identity: Identity) -> User:
        now = time.time()
        existing = self._users.get(identity.user_id)
        user = User(
            id=identity.user_id,
            tenant=identity.tenant,
            subject=identity.subject,
            email=identity.email,
            name=identity.name,
            roles=identity.roles,
            first_login=existing.first_login if existing else now,
            last_login=now,
        )
        self._users[user.id] = user
        return user

    def get(self, user_id: str) -> User | None:
        return self._users.get(user_id)
