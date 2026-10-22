"""Provider adapter contract.

Every protocol (OIDC, SAML, future vendor adapters) implements `AuthProvider`.
The web layer only talks to this interface and never sees protocol details.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AuthError(Exception):
    """Login / logout failed. The message is for server logs only — never show it to users
    and never put tokens or assertions in it."""


@dataclass(frozen=True)
class Identity:
    tenant: str
    subject: str
    email: str | None
    name: str | None
    groups: tuple[str, ...]
    roles: frozenset[str]

    @property
    def user_id(self) -> str:
        return f"{self.tenant}:{self.subject}"


@dataclass(frozen=True)
class RawIdentity:
    """Protocol output before claim mapping."""

    attributes: dict[str, Any]
    # Whatever the provider needs later to log the user out at the IdP
    # (id_token for OIDC, NameID / SessionIndex for SAML). Kept server-side only.
    logout_hint: dict[str, str | None] = field(default_factory=dict)


@dataclass(frozen=True)
class CallbackData:
    """What the browser sent back to us, decoupled from the web framework."""

    path: str
    query: dict[str, str]
    form: dict[str, str]


@dataclass(frozen=True)
class Redirect:
    url: str
    # Stored in the pending store and handed back to finish_* on the callback.
    state: dict[str, str] = field(default_factory=dict)


class AuthProvider(Protocol):
    tenant: str
    display_name: str
    protocol: str

    async def start_login(self, return_to: str) -> Redirect: ...

    async def finish_login(self, data: CallbackData, state: dict[str, str]) -> RawIdentity: ...

    async def start_logout(self, logout_hint: dict[str, str | None]) -> Redirect | None:
        """Return a redirect to the IdP, or None when the IdP has no logout endpoint."""
        ...

    async def finish_logout(self, data: CallbackData, state: dict[str, str]) -> None: ...

    def normalize(self, raw: RawIdentity) -> Identity: ...
