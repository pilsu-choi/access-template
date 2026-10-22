"""Access policy loaded from `config/rbac.yaml`: permission catalog, roles, org tree, seed data.

Everything is validated at load time (unknown roles, inheritance / org cycles, permission typos)
so a broken policy fails at startup instead of silently denying or allowing at runtime.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from access_template.rbac.base import PERMISSION, ConfigError, Grant, Scope

_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _check_permission(v: str) -> str:
    if not PERMISSION.match(v):
        raise ValueError(f"invalid permission {v!r} (use 'resource:action', 'resource:*' or '*')")
    return v


class PermissionRule(_Strict):
    permission: str
    # Name of a condition registered with the authorizer (built-in: `owner`).
    when: str | None = None

    @field_validator("permission")
    @classmethod
    def _perm(cls, v: str) -> str:
        return _check_permission(v)


class RoleDef(_Strict):
    description: str = ""
    inherits: list[str] = Field(default_factory=list)
    permissions: list[str | PermissionRule] = Field(default_factory=list)
    # Scope of this role when it comes from the IdP (tenants.yaml group mapping):
    #   global         - everywhere
    #   member         - only the user's own orgs
    #   member_subtree - the user's own orgs and everything below them
    # Roles granted by the app carry their own scope instead.
    idp_scope: Literal["global", "member", "member_subtree"] = "global"

    def rules(self) -> list[PermissionRule]:
        return [PermissionRule(permission=p) if isinstance(p, str) else p for p in self.permissions]

    @field_validator("permissions")
    @classmethod
    def _perms(cls, v: list[str | PermissionRule]) -> list[str | PermissionRule]:
        for p in v:
            if isinstance(p, str):
                _check_permission(p)
        return v


class OrgDef(_Strict):
    name: str
    parent: str | None = None


class GrantDef(_Strict):
    """Seed grant. `org` omitted = global."""

    user: str
    role: str | None = None
    permission: str | None = None
    org: str | None = None
    subtree: bool = True

    def to_grant(self) -> Grant:
        return Grant(self.user, self.role, self.permission, Scope(self.org, self.subtree))


class RBACPolicy(_Strict):
    # Optional catalog `permission: description`. When set, every concrete permission used by a
    # role or grant must be listed (catches typos like `reprot:read`).
    permissions: dict[str, str] = Field(default_factory=dict)
    roles: dict[str, RoleDef] = Field(default_factory=dict)
    orgs: dict[str, OrgDef] = Field(default_factory=dict)
    # Seed data for dev / small deployments. Real projects load these from their own store.
    members: dict[str, list[str]] = Field(default_factory=dict)  # user_id -> org ids
    grants: list[GrantDef] = Field(default_factory=list)

    @field_validator("permissions")
    @classmethod
    def _catalog(cls, v: dict[str, str]) -> dict[str, str]:
        for p in v:
            if "*" in _check_permission(p):
                raise ValueError(f"catalog entries must be concrete permissions, got {p!r}")
        return v

    @field_validator("roles", "orgs")
    @classmethod
    def _ids(cls, v: dict[str, Any]) -> dict[str, Any]:
        for key in v:
            if not _ID.match(key):
                raise ValueError(f"invalid id {key!r} (use [a-z0-9_-])")
        return v

    @model_validator(mode="after")
    def _references(self) -> RBACPolicy:
        for name, role in self.roles.items():
            for parent in role.inherits:
                if parent not in self.roles:
                    raise ValueError(f"role {name!r} inherits unknown role {parent!r}")
            for rule in role.rules():
                self._in_catalog(rule.permission, f"role {name!r}")
        _no_cycles({n: r.inherits for n, r in self.roles.items()}, "role inheritance")

        for name, org in self.orgs.items():
            if org.parent is not None and org.parent not in self.orgs:
                raise ValueError(f"org {name!r} has unknown parent {org.parent!r}")
        _no_cycles({n: [o.parent] if o.parent else [] for n, o in self.orgs.items()}, "org tree")

        for user, orgs in self.members.items():
            for o in orgs:
                if o not in self.orgs:
                    raise ValueError(f"member {user!r} references unknown org {o!r}")
        for g in self.grants:
            if (g.role is None) == (g.permission is None):
                raise ValueError(f"grant for {g.user!r} needs exactly one of 'role' or 'permission'")
            if g.role is not None and g.role not in self.roles:
                raise ValueError(f"grant for {g.user!r} references unknown role {g.role!r}")
            if g.permission is not None:
                _check_permission(g.permission)
                self._in_catalog(g.permission, f"grant for {g.user!r}")
            if g.org is not None and g.org not in self.orgs:
                raise ValueError(f"grant for {g.user!r} references unknown org {g.org!r}")
        return self

    def _in_catalog(self, permission: str, where: str) -> None:
        if not self.permissions or permission == "*":
            return
        if permission.endswith(":*"):
            prefix = permission[:-1]
            if not any(p.startswith(prefix) for p in self.permissions):
                raise ValueError(f"{where}: {permission!r} matches nothing in the permission catalog")
        elif permission not in self.permissions:
            raise ValueError(f"{where}: permission {permission!r} is not in the permission catalog")


def _no_cycles(edges: dict[str, list[str]], what: str) -> None:
    done: set[str] = set()

    def visit(node: str, path: list[str]) -> None:
        if node in path:
            raise ValueError(f"cycle in {what}: {' -> '.join([*path[path.index(node) :], node])}")
        if node in done:
            return
        for nxt in edges.get(node, []):
            visit(nxt, [*path, node])
        done.add(node)

    for n in edges:
        visit(n, [])


def parse_policy(raw: dict[str, Any]) -> RBACPolicy:
    try:
        return RBACPolicy.model_validate(raw)
    except ValidationError as e:
        raise ConfigError(str(e)) from e


def load_policy(path: Path) -> RBACPolicy:
    with path.open(encoding="utf-8") as f:
        return parse_policy(yaml.safe_load(f) or {})
