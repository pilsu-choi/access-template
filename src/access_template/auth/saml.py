"""SAML 2.0 service provider (SP-initiated SSO + SP-initiated SLO).

All XML signature / condition checks are delegated to python3-saml (xmlsec) in strict mode.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from urllib.parse import urlsplit

import httpx
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants as C
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from access_template.auth.base import AuthError, CallbackData, Identity, RawIdentity, Redirect
from access_template.auth.claims import normalize
from access_template.config import SAMLTenant
from access_template.settings import Settings
from access_template.store import TTLStore

log = logging.getLogger(__name__)

_METADATA_TTL = 3600


class SAMLProvider:
    protocol = "saml"

    def __init__(
        self,
        tenant: str,
        cfg: SAMLTenant,
        settings: Settings,
        http: httpx.AsyncClient,
        replay_cache: TTLStore,
    ) -> None:
        self.tenant = tenant
        self.cfg = cfg
        self.display_name = cfg.display_name
        self.settings = settings
        self.http = http
        self.replay_cache = replay_cache
        base = f"{settings.base}/auth/{tenant}"
        self.acs_url = f"{base}/acs"
        self.sls_url = f"{base}/sls"
        self.sp_entity_id = cfg.sp_entity_id or f"{base}/metadata"
        self._sp_cert = cfg.sp_cert_file.read_text(encoding="utf-8")
        self._sp_key = cfg.sp_key_file.read_text(encoding="utf-8")
        self._idp: dict[str, Any] | None = None
        self._idp_at = 0.0
        self._lock = asyncio.Lock()
        # python3-saml reads this module-level constant for NotBefore / NotOnOrAfter checks.
        C.ALLOWED_CLOCK_DRIFT = settings.clock_skew_seconds

    # --- settings --------------------------------------------------------

    def _sp_settings(self) -> dict[str, Any]:
        return {
            "entityId": self.sp_entity_id,
            "assertionConsumerService": {"url": self.acs_url, "binding": C.BINDING_HTTP_POST},
            "singleLogoutService": {"url": self.sls_url, "binding": C.BINDING_HTTP_REDIRECT},
            "NameIDFormat": self.cfg.name_id_format,
            "x509cert": self._sp_cert,
            "privateKey": self._sp_key,
        }

    def _security(self) -> dict[str, Any]:
        return {
            "authnRequestsSigned": self.cfg.sign_authn_requests,
            "logoutRequestSigned": True,
            "logoutResponseSigned": True,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": self.cfg.want_messages_signed,
            "wantNameId": True,
            "wantAttributeStatement": False,
            "requestedAuthnContext": False,
            "signatureAlgorithm": C.RSA_SHA256,
            "digestAlgorithm": C.SHA256,
            "rejectDeprecatedAlgorithm": True,
            # Some IdPs (Keycloak role_list, ADFS) emit the same attribute name repeatedly.
            "allowRepeatAttributeName": True,
        }

    async def _idp_settings(self) -> dict[str, Any]:
        if self.cfg.idp is not None:
            idp = self.cfg.idp
            out: dict[str, Any] = {
                "entityId": idp.entity_id,
                "singleSignOnService": {"url": idp.sso_url, "binding": C.BINDING_HTTP_REDIRECT},
                "x509cert": idp.x509cert,
            }
            if idp.slo_url:
                out["singleLogoutService"] = {"url": idp.slo_url, "binding": C.BINDING_HTTP_REDIRECT}
            return out
        async with self._lock:
            if self._idp and time.monotonic() - self._idp_at < _METADATA_TTL:
                return self._idp
            assert self.cfg.idp_metadata_url
            resp = await self.http.get(self.cfg.idp_metadata_url)
            resp.raise_for_status()
            parsed = OneLogin_Saml2_IdPMetadataParser.parse(resp.text, entity_id=self.cfg.idp_entity_id)
            if "idp" not in parsed:
                raise AuthError("IdP metadata has no usable IDPSSODescriptor")
            self._idp, self._idp_at = parsed["idp"], time.monotonic()
            return self._idp

    async def _settings(self) -> dict[str, Any]:
        return {
            "strict": True,
            "debug": False,
            "sp": self._sp_settings(),
            "idp": await self._idp_settings(),
            "security": self._security(),
        }

    def _request_data(self, data: CallbackData) -> dict[str, Any]:
        # Build from the configured public URL, not the Host header, so Destination checks
        # work behind reverse proxies and cannot be spoofed by the client.
        base = urlsplit(self.settings.base)
        https = base.scheme == "https"
        return {
            "https": "on" if https else "off",
            "http_host": base.netloc,  # includes the port when non-default
            "script_name": data.path,
            "get_data": data.query,
            "post_data": data.form,
        }

    async def _auth(self, data: CallbackData) -> OneLogin_Saml2_Auth:
        return OneLogin_Saml2_Auth(self._request_data(data), old_settings=await self._settings())

    def sp_metadata(self) -> str:
        s = OneLogin_Saml2_Settings(
            {"strict": True, "sp": self._sp_settings(), "security": self._security()},
            sp_validation_only=True,
        )
        xml = s.get_sp_metadata()
        errors = s.validate_metadata(xml)
        if errors:
            raise AuthError(f"invalid SP metadata: {errors}")
        return xml.decode() if isinstance(xml, bytes) else xml

    # --- login -----------------------------------------------------------

    async def start_login(self, return_to: str) -> Redirect:
        auth = await self._auth(CallbackData(f"/auth/{self.tenant}/login", {}, {}))
        # RelayState is not trusted on the way back; return_to is kept server-side.
        url = auth.login(return_to=return_to)
        return Redirect(url, {"request_id": auth.get_last_request_id()})

    async def finish_login(self, data: CallbackData, state: dict[str, str]) -> RawIdentity:
        if "SAMLResponse" not in data.form:
            raise AuthError("missing SAMLResponse")
        auth = await self._auth(data)
        auth.process_response(request_id=state["request_id"])
        errors = auth.get_errors()
        if errors or not auth.is_authenticated():
            raise AuthError(f"SAML response rejected: {errors} ({auth.get_last_error_reason()})")

        assertion_id = auth.get_last_assertion_id()
        not_after = auth.get_last_assertion_not_on_or_after() or (time.time() + 300)
        ttl = max(60, int(not_after - time.time()) + self.settings.clock_skew_seconds)
        if not assertion_id or not self.replay_cache.add_if_absent(
            f"saml-assertion:{self.tenant}:{assertion_id}", True, ttl
        ):
            raise AuthError("SAML assertion replayed")

        attrs: dict[str, Any] = dict(auth.get_attributes())
        attrs["$nameid"] = auth.get_nameid()
        return RawIdentity(
            attributes=attrs,
            logout_hint={
                "name_id": auth.get_nameid(),
                "name_id_format": auth.get_nameid_format(),
                "name_id_nq": auth.get_nameid_nq(),
                "name_id_spnq": auth.get_nameid_spnq(),
                "session_index": auth.get_session_index(),
            },
        )

    # --- logout ----------------------------------------------------------

    async def start_logout(self, logout_hint: dict[str, str | None]) -> Redirect | None:
        idp = await self._idp_settings()
        if not idp.get("singleLogoutService", {}).get("url"):
            return None
        auth = await self._auth(CallbackData("/logout", {}, {}))
        url = auth.logout(
            return_to=self.settings.base + "/",
            name_id=logout_hint.get("name_id"),
            session_index=logout_hint.get("session_index"),
            nq=logout_hint.get("name_id_nq"),
            name_id_format=logout_hint.get("name_id_format"),
            spnq=logout_hint.get("name_id_spnq"),
        )
        return Redirect(url, {"request_id": auth.get_last_request_id()})

    async def finish_logout(self, data: CallbackData, state: dict[str, str]) -> None:
        if "SAMLResponse" not in data.query:
            # IdP-initiated SLO (SAMLRequest) is out of scope for v1.
            raise AuthError("expected a LogoutResponse")
        auth = await self._auth(data)
        auth.process_slo(keep_local_session=True, request_id=state.get("request_id"))
        errors = auth.get_errors()
        if errors:
            raise AuthError(f"SAML logout response rejected: {errors} ({auth.get_last_error_reason()})")

    def normalize(self, raw: RawIdentity) -> Identity:
        return normalize(self.tenant, raw, self.cfg.claims, self.cfg.roles, self.cfg.allowed_email_domains)
