from __future__ import annotations

import httpx

from sso_template.auth.base import AuthProvider
from sso_template.auth.oidc import OIDCProvider
from sso_template.auth.saml import SAMLProvider
from sso_template.config import OIDCTenant, SAMLTenant, TenantsFile
from sso_template.settings import Settings
from sso_template.store import TTLStore


def build_providers(
    tenants: TenantsFile, settings: Settings, http: httpx.AsyncClient, replay_cache: TTLStore
) -> dict[str, AuthProvider]:
    providers: dict[str, AuthProvider] = {}
    for tid, cfg in tenants.tenants.items():
        match cfg:
            case OIDCTenant():
                providers[tid] = OIDCProvider(tid, cfg, settings, http)
            case SAMLTenant():
                providers[tid] = SAMLProvider(tid, cfg, settings, http, replay_cache)
    return providers
