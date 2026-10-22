"""Tenant (IdP) configuration loaded from `config/tenants.yaml`.

String values may reference environment variables as `${VAR}` or `${VAR:-default}`.
Secrets (client secrets, key paths) should always come from the environment.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_TENANT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


class ConfigError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ClaimMapping(_Strict):
    """Which IdP claim / SAML attribute feeds each normalized field.

    `name` may be a list of attributes joined with a space (e.g. firstName + lastName).
    For SAML, `$nameid` refers to the NameID of the subject.
    """

    subject: str = "sub"
    email: str | None = "email"
    name: str | list[str] | None = "name"
    groups: str | None = "groups"
    # Org unit id(s), e.g. a department code. Overrides the RBAC org directory membership when present.
    org: str | None = None


class RoleMapping(_Strict):
    groups: dict[str, list[str]] = Field(default_factory=dict)
    default: list[str] = Field(default_factory=lambda: ["user"])


class _TenantBase(_Strict):
    display_name: str
    roles: RoleMapping = Field(default_factory=RoleMapping)
    # Empty list = any domain. Compared case-insensitively against the email's domain.
    allowed_email_domains: list[str] = Field(default_factory=list)


class OIDCTenant(_TenantBase):
    protocol: Literal["oidc"]
    issuer: str
    client_id: str
    client_secret: SecretStr | None = None  # None = public client (PKCE only)
    discovery_url: str | None = None
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    allowed_algs: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    use_userinfo: bool = False
    extra_auth_params: dict[str, str] = Field(default_factory=dict)
    # Exact-match checks on the validated id_token, e.g. {hd: example.com} for Google Workspace.
    required_claims: dict[str, str] = Field(default_factory=dict)
    # With allowed_email_domains set, the email must be IdP-verified (email_verified == true).
    require_email_verified: bool = True
    claims: ClaimMapping = Field(default_factory=ClaimMapping)

    @field_validator("allowed_algs")
    @classmethod
    def _no_weak_algs(cls, v: list[str]) -> list[str]:
        bad = [a for a in v if a.lower() == "none" or a.upper().startswith("HS")]
        if bad:
            raise ValueError(f"disallowed id_token algorithms: {bad}")
        return v

    @field_validator("scopes")
    @classmethod
    def _needs_openid(cls, v: list[str]) -> list[str]:
        if "openid" not in v:
            raise ValueError("scopes must include 'openid'")
        return v


class SAMLIdP(_Strict):
    entity_id: str
    sso_url: str
    slo_url: str | None = None
    x509cert: str


class SAMLTenant(_TenantBase):
    protocol: Literal["saml"]
    idp_metadata_url: str | None = None
    idp_entity_id: str | None = None  # pick one entity when metadata lists several
    idp: SAMLIdP | None = None
    sp_entity_id: str | None = None  # default: {base_url}/auth/{tenant}/metadata
    sp_cert_file: Path
    sp_key_file: Path
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    sign_authn_requests: bool = True
    want_messages_signed: bool = False  # assertion signature is always required
    claims: ClaimMapping = Field(
        default_factory=lambda: ClaimMapping(subject="$nameid", email="email", name=None)
    )

    @model_validator(mode="after")
    def _idp_source(self) -> SAMLTenant:
        if (self.idp_metadata_url is None) == (self.idp is None):
            raise ValueError("set exactly one of 'idp_metadata_url' or 'idp'")
        return self


TenantConfig = Annotated[OIDCTenant | SAMLTenant, Field(discriminator="protocol")]


class TenantsFile(_Strict):
    tenants: dict[str, TenantConfig]

    @field_validator("tenants")
    @classmethod
    def _ids(cls, v: dict[str, Any]) -> dict[str, Any]:
        for tid in v:
            if not _TENANT_ID.match(tid):
                raise ValueError(f"invalid tenant id {tid!r} (use [a-z0-9-])")
        return v


def _interpolate(value: Any, env: dict[str, str]) -> Any:
    if isinstance(value, str):

        def sub(m: re.Match[str]) -> str:
            name, default = m.group(1), m.group(2)
            if name in env:
                return env[name]
            if default is not None:
                return default
            raise ConfigError(f"environment variable {name} is not set")

        return _ENV_REF.sub(sub, value)
    if isinstance(value, dict):
        return {k: _interpolate(v, env) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v, env) for v in value]
    return value


def parse_tenants(raw: dict[str, Any], env: dict[str, str] | None = None) -> TenantsFile:
    data = _interpolate(raw, dict(os.environ) if env is None else env)
    return TenantsFile.model_validate(data)


def load_tenants(path: Path, env: dict[str, str] | None = None) -> TenantsFile:
    with path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return parse_tenants(raw, env)
