"""In-memory org directory and grant repository.

Fine for dev and for deployments whose org tree lives in `rbac.yaml`. Replace with implementations
backed by the app DB or the customer's HR / EAM system (same protocols, see `base.py`).
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping

from access_template.rbac.base import Grant
from access_template.rbac.config import RBACPolicy


class InMemoryOrgDirectory:
    def __init__(
        self,
        parents: Mapping[str, str | None],
        members: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        self._parents = dict(parents)
        self._children: dict[str, set[str]] = {}
        for org, parent in self._parents.items():
            if parent is not None:
                self._children.setdefault(parent, set()).add(org)
        self._members = {u: frozenset(orgs) for u, orgs in (members or {}).items()}

    @classmethod
    def from_policy(cls, policy: RBACPolicy) -> InMemoryOrgDirectory:
        return cls({k: o.parent for k, o in policy.orgs.items()}, policy.members)

    def exists(self, org: str) -> bool:
        return org in self._parents

    def ancestors(self, org: str) -> list[str]:
        out: list[str] = []
        parent = self._parents.get(org)
        while parent is not None:
            out.append(parent)
            parent = self._parents.get(parent)
        return out

    def descendants(self, org: str) -> set[str]:
        out: set[str] = set()
        stack = list(self._children.get(org, ()))
        while stack:
            child = stack.pop()
            out.add(child)
            stack.extend(self._children.get(child, ()))
        return out

    def memberships(self, user_id: str) -> frozenset[str]:
        return self._members.get(user_id, frozenset())

    def set_memberships(self, user_id: str, orgs: Iterable[str]) -> None:
        self._members[user_id] = frozenset(orgs)


class InMemoryGrantRepository:
    """Process-local. Not shared between workers — dev / single instance only."""

    def __init__(self, grants: Iterable[Grant] = ()) -> None:
        self._grants: list[Grant] = list(grants)
        self._lock = threading.Lock()

    @classmethod
    def from_policy(cls, policy: RBACPolicy) -> InMemoryGrantRepository:
        return cls(g.to_grant() for g in policy.grants)

    def grants_for(self, user_id: str) -> list[Grant]:
        with self._lock:
            return [g for g in self._grants if g.user_id == user_id]

    def add(self, grant: Grant) -> None:
        with self._lock:
            if grant not in self._grants:
                self._grants.append(grant)

    def remove(self, grant: Grant) -> None:
        with self._lock:
            if grant in self._grants:
                self._grants.remove(grant)
