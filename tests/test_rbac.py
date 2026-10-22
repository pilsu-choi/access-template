"""Access policy validation and authorization decisions (no web layer)."""

from dataclasses import dataclass
from pathlib import Path

import pytest

from access_template.rbac.base import (
    AuditEvent,
    ConfigError,
    Grant,
    Resource,
    Scope,
    permission_matches,
)
from access_template.rbac.config import load_policy, parse_policy
from access_template.rbac.policy import PolicyAuthorizer
from access_template.rbac.stores import InMemoryGrantRepository, InMemoryOrgDirectory

POLICY = {
    "permissions": {
        "report:read": "",
        "report:export": "",
        "document:read": "",
        "document:edit": "",
    },
    "roles": {
        "user": {
            "idp_scope": "member_subtree",
            "permissions": ["document:read", {"permission": "document:edit", "when": "owner"}],
        },
        "lead": {"idp_scope": "member", "inherits": ["user"], "permissions": ["report:read"]},
        "exporter": {"permissions": ["report:*"]},
        "admin": {"permissions": ["*"]},
    },
    "orgs": {
        "hq": {"name": "HQ"},
        "sales": {"name": "Sales", "parent": "hq"},
        "sales-1": {"name": "Sales 1", "parent": "sales"},
        "dev": {"name": "Dev", "parent": "hq"},
    },
    "members": {"t:dir-user": ["sales"]},
}


@dataclass(frozen=True)
class P:
    user_id: str
    roles: frozenset[str] = frozenset()
    orgs: tuple[str, ...] = ()
    # Must never reach audit events.
    email: str = "secret@example.com"


class Recorder:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


def authz(policy=None, grants=(), conditions=None) -> tuple[PolicyAuthorizer, Recorder]:
    pol = parse_policy(policy or POLICY)
    audit = Recorder()
    a = PolicyAuthorizer(
        pol, InMemoryOrgDirectory.from_policy(pol), InMemoryGrantRepository(grants), audit, conditions
    )
    return a, audit


def doc(org: str | None = None, owner: str | None = None) -> Resource:
    return Resource("document", "d1", org=org, owner=owner)


# --- policy validation ------------------------------------------------------


def with_(**changes):
    return {**POLICY, **changes}


@pytest.mark.parametrize(
    "raw, msg",
    [
        (with_(roles={"a": {"inherits": ["missing"]}}), "unknown role"),
        (with_(roles={"a": {"inherits": ["b"]}, "b": {"inherits": ["a"]}}), "cycle in role inheritance"),
        (with_(roles={"a": {"permissions": ["*:read"]}}), "invalid permission"),
        (with_(roles={"a": {"permissions": ["Report:Read"]}}), "invalid permission"),
        (with_(roles={"a": {"permissions": ["reprot:read"]}}), "not in the permission catalog"),
        (with_(roles={"a": {"permissions": ["audit:*"]}}), "matches nothing"),
        (with_(orgs={"a": {"name": "A", "parent": "nope"}}), "unknown parent"),
        (with_(orgs={"a": {"name": "A", "parent": "b"}, "b": {"name": "B", "parent": "a"}}), "cycle in org"),
        (with_(members={"u": ["nope"]}), "unknown org"),
        (with_(grants=[{"user": "u", "role": "nope"}]), "unknown role"),
        (with_(grants=[{"user": "u"}]), "exactly one"),
        (with_(grants=[{"user": "u", "role": "user", "org": "nope"}]), "unknown org"),
        (with_(roles={"a": {"idp_scope": "everywhere"}}), "idp_scope"),
        (with_(rols={}), "Extra inputs"),
    ],
)
def test_policy_rejects(raw, msg):
    with pytest.raises(ConfigError, match=msg):
        parse_policy(raw)


def test_unregistered_condition_rejected():
    raw = with_(roles={"a": {"permissions": [{"permission": "document:edit", "when": "same_branch"}]}})
    with pytest.raises(ConfigError, match="unregistered condition"):
        authz(raw)
    authz(raw, conditions={"same_branch": lambda p, r: True})  # registered: fine


@pytest.mark.parametrize("policy_path", ["config/rbac.yaml", "config/rbac.example.yaml"])
@pytest.mark.parametrize("tenants_path", ["config/tenants.yaml", "config/tenants.example.yaml"])
def test_shipped_configs_fit_together(policy_path, tenants_path):
    import os
    import re

    import yaml

    from access_template.app import check_role_names
    from access_template.config import parse_tenants

    pol = load_policy(Path(policy_path))
    PolicyAuthorizer(pol, InMemoryOrgDirectory.from_policy(pol), InMemoryGrantRepository.from_policy(pol))
    text = Path(tenants_path).read_text(encoding="utf-8")
    env = {**os.environ, **{v: "x" for v in re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", text)}}
    check_role_names(parse_tenants(yaml.safe_load(text), env=env), pol)


# --- matching ---------------------------------------------------------------


@pytest.mark.parametrize(
    "granted, wanted, ok",
    [
        ("report:read", "report:read", True),
        ("report:*", "report:read", True),
        ("report:*", "document:read", False),
        ("*", "anything:goes", True),
        ("report:read", "report:export", False),
        ("rep:*", "report:read", False),
    ],
)
def test_permission_matches(granted, wanted, ok):
    assert permission_matches(granted, wanted) is ok


def test_check_needs_concrete_permission():
    a, _ = authz()
    with pytest.raises(ValueError):
        a.check(P("t:u"), "report:*")


# --- decisions --------------------------------------------------------------


def test_default_deny():
    a, _ = authz()
    assert not a.check(P("t:u"), "report:read")
    assert not a.check(P("t:u", frozenset({"unknown-idp-role"})), "report:read")


def test_wildcards_and_global_roles():
    a, _ = authz()
    admin = P("t:a", frozenset({"admin"}))
    assert a.check(admin, "document:edit", doc(org="dev"))
    assert a.check(admin, "document:edit", doc())  # global reaches resources without an org
    exporter = P("t:e", frozenset({"exporter"}))
    assert a.check(exporter, "report:export")
    assert not a.check(exporter, "document:read")


def test_inheritance():
    a, _ = authz()
    lead = P("t:l", frozenset({"lead"}), orgs=("sales-1",))
    assert a.check(lead, "report:read", Resource("report", "r", org="sales-1"))
    assert a.check(lead, "document:read", doc(org="sales-1"))  # from `user`


def test_idp_scope_member_subtree():
    a, _ = authz()
    u = P("t:u", frozenset({"user"}), orgs=("sales",))
    assert a.check(u, "document:read", doc(org="sales"))
    assert a.check(u, "document:read", doc(org="sales-1"))  # below
    assert not a.check(u, "document:read", doc(org="hq"))  # above
    assert not a.check(u, "document:read", doc(org="dev"))  # sibling
    assert not a.check(u, "document:read", doc())  # outside the org tree


def test_idp_scope_member_only():
    a, _ = authz()
    lead = P("t:l", frozenset({"lead"}), orgs=("sales",))
    assert a.check(lead, "report:read", Resource("report", "r", org="sales"))
    assert not a.check(lead, "report:read", Resource("report", "r", org="sales-1"))


def test_org_scoped_user_without_orgs_gets_nothing_on_resources():
    a, _ = authz()
    u = P("t:u", frozenset({"user"}))
    assert not a.check(u, "document:read", doc(org="sales"))
    assert not a.check(u, "document:read")  # no scope at all


def test_idp_org_claim_overrides_directory():
    a, _ = authz()
    from_dir = P("t:dir-user", frozenset({"user"}))
    assert a.check(from_dir, "document:read", doc(org="sales-1"))
    from_claim = P("t:dir-user", frozenset({"user"}), orgs=("dev",))
    assert a.check(from_claim, "document:read", doc(org="dev"))
    assert not a.check(from_claim, "document:read", doc(org="sales-1"))


def test_scoped_role_grant_with_and_without_subtree():
    a, _ = authz(
        grants=[
            Grant("t:g", role="lead", scope=Scope("sales", subtree=True)),
            Grant("t:h", role="lead", scope=Scope("sales", subtree=False)),
        ]
    )
    sub = Resource("report", "r", org="sales-1")
    assert a.check(P("t:g"), "report:read", sub)
    assert not a.check(P("t:h"), "report:read", sub)
    assert a.check(P("t:h"), "report:read", Resource("report", "r", org="sales"))
    assert not a.check(P("t:g"), "report:read", Resource("report", "r", org="dev"))


def test_direct_permission_grant():
    a, audit = authz(grants=[Grant("t:x", permission="report:export", scope=Scope("dev"))])
    d = a.check(P("t:x"), "report:export", Resource("report", "r", org="dev"))
    assert d and d.reason.startswith("grant:report:export@dev")
    assert not a.check(P("t:x"), "report:read")


def test_grant_rejects_bad_shape():
    with pytest.raises(ValueError):
        Grant("u")
    with pytest.raises(ValueError):
        Grant("u", role="a", permission="b:c")
    with pytest.raises(ValueError):
        Grant("u", permission="nope")


def test_owner_condition():
    a, _ = authz()
    u = P("t:u", frozenset({"user"}), orgs=("sales",))
    assert a.check(u, "document:edit", doc(org="sales", owner="t:u"))
    assert not a.check(u, "document:edit", doc(org="sales", owner="t:other"))
    assert not a.check(u, "document:edit", doc(org="sales"))
    # Conditional permissions never pass a route-level check.
    assert not a.check(u, "document:edit")
    # Condition does not bypass the org scope.
    assert not a.check(u, "document:edit", doc(org="dev", owner="t:u"))


def test_grants_take_effect_immediately():
    a, _ = authz()
    assert not a.check(P("t:n"), "report:read")
    g = Grant("t:n", role="lead", scope=Scope("hq"))
    a.grants.add(g)
    assert a.check(P("t:n"), "report:read", Resource("report", "r", org="dev"))
    a.grants.remove(g)
    assert not a.check(P("t:n"), "report:read")


# --- visibility -------------------------------------------------------------


def test_visible_global():
    a, _ = authz()
    v = a.visible(P("t:a", frozenset({"admin"})), "document:read")
    assert v.all and v.covers(None) and v.covers("dev")


def test_visible_org_subtree_and_conditional():
    a, _ = authz()
    u = P("t:u", frozenset({"user"}), orgs=("sales",))
    v = a.visible(u, "document:read")
    assert not v.all and v.orgs == {"sales", "sales-1"} and not v.conditional
    e = a.visible(u, "document:edit")
    assert e.orgs == frozenset() and e.conditional


def test_visible_none():
    a, _ = authz()
    v = a.visible(P("t:u"), "document:read")
    assert not v.all and not v.orgs and not v.covers("sales")


def test_permissions_listing():
    a, _ = authz()
    assert a.permissions(P("t:l", frozenset({"lead"}), orgs=("sales",))) == {
        "report:read",
        "document:read",
        "document:edit",
    }


# --- audit ------------------------------------------------------------------


def test_audit_records_every_decision_without_pii():
    a, audit = authz()
    u = P("t:u", frozenset({"user"}), orgs=("sales",))
    a.check(u, "document:read", doc(org="sales"))
    a.check(u, "report:read")
    allow, deny = audit.events
    assert (allow.allowed, allow.resource, allow.user_id) == (True, "document:d1", "t:u")
    assert allow.reason == "role:user:document:read@sales/*"
    assert (deny.allowed, deny.resource, deny.reason) == (False, None, "no matching grant")
    assert all("secret@example.com" not in repr(e) for e in audit.events)
