"""Access-control contract.

Independent of `auth/`: anything with `user_id`, `roles` and `orgs` is a `Principal`
(`Identity` from the SSO side satisfies it). The web layer only talks to `Authorizer`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

# `resource:action`, `resource:*` or `*`. Lowercase so policy files and code can't drift on case.
PERMISSION = re.compile(r"^(\*|[a-z][a-z0-9_-]*:(\*|[a-z][a-z0-9_-]*))$")


class ConfigError(ValueError):
    pass


def permission_matches(granted: str, wanted: str) -> bool:
    if granted == "*" or granted == wanted:
        return True
    resource, _, action = granted.partition(":")
    return action == "*" and wanted.partition(":")[0] == resource


class Principal(Protocol):
    @property
    def user_id(self) -> str: ...
    @property
    def roles(self) -> frozenset[str]: ...  # roles asserted by the IdP (already mapped)
    @property
    def orgs(self) -> tuple[str, ...]: ...  # org ids asserted by the IdP; may be empty


@dataclass(frozen=True)
class Resource:
    """What is being accessed. `org` / `owner` feed org scopes and conditions like `owner`."""

    type: str
    id: str
    org: str | None = None
    owner: str | None = None  # owner's user_id
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.type}:{self.id}"


@dataclass(frozen=True)
class Scope:
    """Where a grant applies. `org=None` means everywhere."""

    org: str | None = None
    subtree: bool = True  # include descendant orgs


GLOBAL = Scope()


@dataclass(frozen=True)
class Grant:
    """App-managed assignment of a role, or of a single permission, to one user."""

    user_id: str
    role: str | None = None
    permission: str | None = None
    scope: Scope = GLOBAL

    def __post_init__(self) -> None:
        if (self.role is None) == (self.permission is None):
            raise ValueError("grant needs exactly one of 'role' or 'permission'")
        if self.permission is not None and not PERMISSION.match(self.permission):
            raise ValueError(f"invalid permission {self.permission!r}")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    permission: str
    reason: str  # what matched, e.g. "role:manager@sales/*", or why it was denied

    def __bool__(self) -> bool:
        return self.allowed


@dataclass(frozen=True)
class Visibility:
    """Which orgs a permission reaches, for filtering lists in a query (`WHERE org IN (...)`).

    `conditional` grants (e.g. `when: owner`) are not included in `orgs`: rows they might allow
    must be checked one by one with `Authorizer.check`.
    """

    all: bool
    orgs: frozenset[str]
    conditional: bool

    def covers(self, org: str | None) -> bool:
        return self.all or (org is not None and org in self.orgs)


@dataclass(frozen=True)
class AuditEvent:
    """One authorization decision. Carries the user id only — never email, name or tokens."""

    at: float
    user_id: str
    permission: str
    resource: str | None
    allowed: bool
    reason: str


class Authorizer(Protocol):
    def check(self, principal: Principal, permission: str, resource: Resource | None = None) -> Decision:
        """Default deny. Without a resource: "does the user hold this permission anywhere"."""
        ...

    def visible(self, principal: Principal, permission: str) -> Visibility: ...

    def permissions(self, principal: Principal) -> frozenset[str]:
        """Every permission the user holds in some scope (for display, not for decisions)."""
        ...


class GrantRepository(Protocol):
    def grants_for(self, user_id: str) -> list[Grant]: ...
    def add(self, grant: Grant) -> None: ...
    def remove(self, grant: Grant) -> None: ...


class OrgDirectory(Protocol):
    def exists(self, org: str) -> bool: ...
    def ancestors(self, org: str) -> list[str]:
        """Parent first, root last. Excludes `org` itself."""
        ...

    def descendants(self, org: str) -> set[str]:
        """All orgs below `org`, excluding itself."""
        ...

    def memberships(self, user_id: str) -> frozenset[str]: ...


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None: ...
