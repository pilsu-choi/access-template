"""`PolicyAuthorizer`: role / org-scoped permission checks driven by `RBACPolicy`.

Where a user's permissions come from:
  1. IdP roles (`Principal.roles`), scoped by each role's `idp_scope` relative to the user's orgs
  2. App-managed grants (`GrantRepository`): a role or a single permission with an explicit scope
The user's orgs are the IdP org claim when present, otherwise the `OrgDirectory` membership.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass

from access_template.rbac.base import (
    GLOBAL,
    PERMISSION,
    AuditEvent,
    AuditSink,
    ConfigError,
    Decision,
    GrantRepository,
    OrgDirectory,
    Principal,
    Resource,
    Scope,
    Visibility,
    permission_matches,
)
from access_template.rbac.config import PermissionRule, RBACPolicy
from access_template.rbac.stores import InMemoryGrantRepository, InMemoryOrgDirectory

Condition = Callable[[Principal, Resource], bool]


def owner(principal: Principal, resource: Resource) -> bool:
    return resource.owner is not None and resource.owner == principal.user_id


BUILTIN_CONDITIONS: dict[str, Condition] = {"owner": owner}


class LoggingAuditSink:
    """Writes one line per decision to the `access_template.audit` logger."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.log = logger or logging.getLogger("access_template.audit")

    def record(self, event: AuditEvent) -> None:
        self.log.info(
            "authz %s user=%s permission=%s resource=%s reason=%s",
            "allow" if event.allowed else "deny",
            event.user_id,
            event.permission,
            event.resource or "-",
            event.reason,
        )


@dataclass(frozen=True)
class _Binding:
    rule: PermissionRule
    scope: Scope
    source: str  # "role:<name>" / "grant:<permission>"


class PolicyAuthorizer:
    def __init__(
        self,
        policy: RBACPolicy,
        orgs: OrgDirectory,
        grants: GrantRepository,
        audit: AuditSink | None = None,
        conditions: Mapping[str, Condition] | None = None,
    ) -> None:
        self.policy = policy
        self.orgs = orgs
        self.grants = grants
        self.audit = audit or LoggingAuditSink()
        self.conditions = {**BUILTIN_CONDITIONS, **(conditions or {})}
        self._rules = {name: self._expand(name) for name in policy.roles}
        for name, rules in self._rules.items():
            for r in rules:
                if r.when is not None and r.when not in self.conditions:
                    raise ConfigError(f"role {name!r} uses unregistered condition {r.when!r}")

    def _expand(self, role: str) -> list[PermissionRule]:
        """Own rules plus everything inherited (the policy is validated cycle-free)."""
        seen: list[str] = []
        stack = [role]
        while stack:
            r = stack.pop()
            if r not in seen:
                seen.append(r)
                stack.extend(self.policy.roles[r].inherits)
        return [rule for r in seen for rule in self.policy.roles[r].rules()]

    # --- resolution ------------------------------------------------------

    def user_orgs(self, principal: Principal) -> frozenset[str]:
        return frozenset(principal.orgs) if principal.orgs else self.orgs.memberships(principal.user_id)

    def _bindings(self, principal: Principal) -> Iterator[_Binding]:
        member_of = self.user_orgs(principal)
        for role in sorted(principal.roles):
            if role not in self._rules:
                continue  # unknown IdP role: grants nothing
            match self.policy.roles[role].idp_scope:
                case "global":
                    scopes = [GLOBAL]
                case "member":
                    scopes = [Scope(o, subtree=False) for o in sorted(member_of)]
                case "member_subtree":
                    scopes = [Scope(o, subtree=True) for o in sorted(member_of)]
            for scope in scopes:
                for rule in self._rules[role]:
                    yield _Binding(rule, scope, f"role:{role}")
        for g in self.grants.grants_for(principal.user_id):
            if g.role is not None:
                for rule in self._rules.get(g.role, []):
                    yield _Binding(rule, g.scope, f"grant-role:{g.role}")
            elif g.permission is not None:
                yield _Binding(PermissionRule(permission=g.permission), g.scope, "grant")

    def _in_scope(self, scope: Scope, resource: Resource | None) -> bool:
        if scope.org is None or resource is None:
            return True
        if resource.org is None:
            return False  # org-scoped grants never reach resources outside the org tree
        return resource.org == scope.org or (scope.subtree and scope.org in self.orgs.ancestors(resource.org))

    # --- Authorizer ------------------------------------------------------

    def check(self, principal: Principal, permission: str, resource: Resource | None = None) -> Decision:
        if not PERMISSION.match(permission) or "*" in permission:
            raise ValueError(f"check needs a concrete permission, got {permission!r}")
        decision = Decision(False, permission, "no matching grant")
        for b in self._bindings(principal):
            if not permission_matches(b.rule.permission, permission) or not self._in_scope(b.scope, resource):
                continue
            if b.rule.when is not None:
                # Conditions need the resource; a route-level check can't satisfy them.
                if resource is None or not self.conditions[b.rule.when](principal, resource):
                    continue
            decision = Decision(True, permission, _describe(b))
            break
        self.audit.record(
            AuditEvent(
                at=time.time(),
                user_id=principal.user_id,
                permission=permission,
                resource=str(resource) if resource else None,
                allowed=decision.allowed,
                reason=decision.reason,
            )
        )
        return decision

    def visible(self, principal: Principal, permission: str) -> Visibility:
        orgs: set[str] = set()
        conditional = False
        for b in self._bindings(principal):
            if not permission_matches(b.rule.permission, permission):
                continue
            if b.rule.when is not None:
                conditional = True
            elif b.scope.org is None:
                return Visibility(all=True, orgs=frozenset(), conditional=conditional)
            else:
                orgs.add(b.scope.org)
                if b.scope.subtree:
                    orgs |= self.orgs.descendants(b.scope.org)
        return Visibility(all=False, orgs=frozenset(orgs), conditional=conditional)

    def permissions(self, principal: Principal) -> frozenset[str]:
        return frozenset(b.rule.permission for b in self._bindings(principal))


def _describe(b: _Binding) -> str:
    where = "*" if b.scope.org is None else b.scope.org + ("/*" if b.scope.subtree else "")
    when = f" when {b.rule.when}" if b.rule.when else ""
    return f"{b.source}:{b.rule.permission}@{where}{when}"


def build_authorizer(
    policy: RBACPolicy,
    audit: AuditSink | None = None,
    conditions: Mapping[str, Condition] | None = None,
) -> PolicyAuthorizer:
    """Authorizer with in-memory org directory and grants seeded from the policy file."""
    return PolicyAuthorizer(
        policy,
        InMemoryOrgDirectory.from_policy(policy),
        InMemoryGrantRepository.from_policy(policy),
        audit,
        conditions,
    )
