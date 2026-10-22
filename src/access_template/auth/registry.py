from __future__ import annotations

import httpx

from access_template.auth.base import AuthProvider
from access_template.auth.oidc import OIDCProvider
from access_template.auth.saml import SAMLProvider
from access_template.config import OIDCTenant, SAMLTenant, TenantsFile
from access_template.settings import Settings
from access_template.store import TTLStore


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
