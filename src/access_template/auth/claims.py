"""Normalize protocol-specific claims / attributes into an `Identity`."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from access_template.auth.base import AuthError, Identity, RawIdentity
from access_template.config import ClaimMapping, RoleMapping


def _first(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list | tuple):
        return str(value[0]) if value else None
    return str(value)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list | tuple):
        return [str(v) for v in value]
    return [str(value)]


def normalize(
    tenant: str,
    raw: RawIdentity,
    claims: ClaimMapping,
    roles: RoleMapping,
    allowed_email_domains: Sequence[str] = (),
) -> Identity:
    attrs = raw.attributes

    subject = _first(attrs.get(claims.subject))
    if not subject:
        raise AuthError(f"subject claim {claims.subject!r} missing")

    email = _first(attrs.get(claims.email)) if claims.email else None

    name: str | None = None
    if isinstance(claims.name, list):
        parts = [p for p in (_first(attrs.get(k)) for k in claims.name) if p]
        name = " ".join(parts) or None
    elif claims.name:
        name = _first(attrs.get(claims.name))

    groups = tuple(_as_list(attrs.get(claims.groups))) if claims.groups else ()
    orgs = tuple(_as_list(attrs.get(claims.org))) if claims.org else ()

    if allowed_email_domains:
        domain = email.rsplit("@", 1)[-1].lower() if email and "@" in email else None
        if domain not in {d.lower() for d in allowed_email_domains}:
            raise AuthError(f"email domain {domain!r} not allowed")

    role_set = set(roles.default)
    for g in groups:
        role_set.update(roles.groups.get(g, ()))

    return Identity(
        tenant=tenant,
        subject=subject,
        email=email,
        name=name,
        groups=groups,
        roles=frozenset(role_set),
        orgs=orgs,
    )
