"""OpenID Connect relying party: Authorization Code + PKCE.

Token validation is delegated to joserfc. Works with any compliant IdP
(Keycloak, Entra ID, Okta, Google, Kakao, ...).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from access_template.auth.base import AuthError, CallbackData, Identity, RawIdentity, Redirect
from access_template.auth.claims import normalize
from access_template.config import OIDCTenant
from access_template.settings import Settings

log = logging.getLogger(__name__)

_METADATA_TTL = 3600


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class OIDCProvider:
    protocol = "oidc"

    def __init__(self, tenant: str, cfg: OIDCTenant, settings: Settings, http: httpx.AsyncClient) -> None:
        self.tenant = tenant
        self.cfg = cfg
        self.display_name = cfg.display_name
        self.settings = settings
        self.http = http
        self.redirect_uri = f"{settings.base}/auth/{tenant}/callback"
        self._metadata: dict[str, Any] | None = None
        self._metadata_at = 0.0
        self._jwks: KeySet | None = None
        self._lock = asyncio.Lock()

    # --- discovery -------------------------------------------------------

    async def metadata(self) -> dict[str, Any]:
        async with self._lock:
            if self._metadata and time.monotonic() - self._metadata_at < _METADATA_TTL:
                return self._metadata
            url = self.cfg.discovery_url or (
                self.cfg.issuer.rstrip("/") + "/.well-known/openid-configuration"
            )
            resp = await self.http.get(url)
            resp.raise_for_status()
            meta = resp.json()
            if meta.get("issuer") != self.cfg.issuer:
                raise AuthError(f"discovery issuer {meta.get('issuer')!r} != configured {self.cfg.issuer!r}")
            self._metadata, self._metadata_at = meta, time.monotonic()
            self._jwks = None
            return meta

    async def _keyset(self, refresh: bool = False) -> KeySet:
        if self._jwks is None or refresh:
            meta = await self.metadata()
            resp = await self.http.get(meta["jwks_uri"])
            resp.raise_for_status()
            self._jwks = KeySet.import_key_set(resp.json())
        return self._jwks

    # --- login -----------------------------------------------------------

    async def start_login(self, return_to: str) -> Redirect:
        meta = await self.metadata()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier, challenge = _pkce_pair()
        params = {
            **self.cfg.extra_auth_params,
            "response_type": "code",
            "client_id": self.cfg.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.cfg.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        url = f"{meta['authorization_endpoint']}?{urlencode(params)}"
        return Redirect(url, {"state": state, "nonce": nonce, "code_verifier": verifier})

    async def finish_login(self, data: CallbackData, state: dict[str, str]) -> RawIdentity:
        q = data.query
        if "error" in q:
            raise AuthError(f"IdP returned error={q.get('error')!r}")
        if not hmac.compare_digest(q.get("state", ""), state["state"]):
            raise AuthError("state mismatch")
        code = q.get("code")
        if not code:
            raise AuthError("missing authorization code")

        meta = await self.metadata()
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": state["code_verifier"],
        }
        auth: tuple[str, str] | None = None
        if self.cfg.client_secret is not None:
            auth = (self.cfg.client_id, self.cfg.client_secret.get_secret_value())
        else:
            form["client_id"] = self.cfg.client_id
        resp = await self.http.post(meta["token_endpoint"], data=form, auth=auth)
        if resp.status_code != 200:
            # Body may echo the code; log only the status and error code.
            err = resp.json().get("error") if "json" in resp.headers.get("content-type", "") else None
            raise AuthError(f"token endpoint returned {resp.status_code} error={err!r}")
        tokens = resp.json()
        id_token = tokens.get("id_token")
        if not id_token:
            raise AuthError("token response has no id_token")

        claims = await self.validate_id_token(id_token, state["nonce"])

        if self.cfg.use_userinfo and meta.get("userinfo_endpoint"):
            ui = await self.http.get(
                meta["userinfo_endpoint"],
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
            )
            ui.raise_for_status()
            info = ui.json()
            if info.get("sub") != claims["sub"]:
                raise AuthError("userinfo sub does not match id_token sub")
            claims = {**info, **claims}

        for name, expected in self.cfg.required_claims.items():
            if claims.get(name) != expected:
                raise AuthError(f"required claim {name!r} mismatch")
        if self.cfg.allowed_email_domains and self.cfg.require_email_verified:
            if claims.get("email_verified") is not True:
                raise AuthError("email not verified by IdP")

        return RawIdentity(attributes=claims, logout_hint={"id_token": id_token})

    async def validate_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        try:
            try:
                token = jwt.decode(id_token, await self._keyset(), algorithms=self.cfg.allowed_algs)
            except JoseError:
                # Possibly a key rotation: refetch JWKS once and retry.
                token = jwt.decode(
                    id_token, await self._keyset(refresh=True), algorithms=self.cfg.allowed_algs
                )
            registry = jwt.JWTClaimsRegistry(
                leeway=self.settings.clock_skew_seconds,
                iss={"essential": True, "value": self.cfg.issuer},
                aud={"essential": True, "value": self.cfg.client_id},
                sub={"essential": True},
                exp={"essential": True},
                iat={"essential": True},
                nonce={"essential": True, "value": nonce},
            )
            registry.validate(token.claims)
        except JoseError as e:
            raise AuthError(f"id_token rejected: {type(e).__name__}: {e}") from None

        claims = dict(token.claims)
        aud = claims.get("aud")
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.cfg.client_id:
            raise AuthError("id_token has multiple audiences but azp is not this client")
        return claims

    # --- logout ----------------------------------------------------------

    async def start_logout(self, logout_hint: dict[str, str | None]) -> Redirect | None:
        meta = await self.metadata()
        endpoint = meta.get("end_session_endpoint")
        if not endpoint:
            return None
        params = {"client_id": self.cfg.client_id, "post_logout_redirect_uri": self.settings.base + "/"}
        if logout_hint.get("id_token"):
            params["id_token_hint"] = logout_hint["id_token"]
        return Redirect(f"{endpoint}?{urlencode(params)}")

    async def finish_logout(self, data: CallbackData, state: dict[str, str]) -> None:
        return None

    def normalize(self, raw: RawIdentity) -> Identity:
        return normalize(self.tenant, raw, self.cfg.claims, self.cfg.roles, self.cfg.allowed_email_domains)
