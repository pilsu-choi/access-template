import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey

from sso_template.auth.base import AuthError, CallbackData
from sso_template.auth.oidc import OIDCProvider
from sso_template.config import OIDCTenant
from sso_template.settings import Settings

ISS = "https://idp.test/realms/r"
CLIENT = "client-1"
IDP_KEY = RSAKey.generate_key(2048, parameters={"kid": "idp-1"})
OTHER_KEY = RSAKey.generate_key(2048, parameters={"kid": "idp-1"})


class FakeIdP:
    def __init__(self) -> None:
        self.claims_override: dict = {}
        self.sign_key = IDP_KEY
        self.header = {"alg": "RS256", "kid": "idp-1"}
        self.nonce = ""
        self.token_form: dict = {}

    def id_token(self) -> str:
        now = int(time.time())
        claims = {
            "iss": ISS,
            "aud": CLIENT,
            "sub": "u1",
            "iat": now,
            "exp": now + 300,
            "nonce": self.nonce,
            "email": "a@example.com",
            "groups": ["admins"],
        }
        claims.update(self.claims_override)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(self.header, claims, self.sign_key)

    def handler(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISS,
                    "authorization_endpoint": f"{ISS}/auth",
                    "token_endpoint": f"{ISS}/token",
                    "jwks_uri": f"{ISS}/certs",
                    "end_session_endpoint": f"{ISS}/logout",
                },
            )
        if path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [IDP_KEY.as_dict(private=False)]})
        if path.endswith("/token"):
            self.token_form = parse_qs(req.content.decode())
            return httpx.Response(200, json={"access_token": "at", "id_token": self.id_token()})
        return httpx.Response(404)


@pytest.fixture
def idp():
    return FakeIdP()


@pytest.fixture
def provider(idp):
    cfg = OIDCTenant(protocol="oidc", display_name="t", issuer=ISS, client_id=CLIENT, client_secret="s")
    http = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    return OIDCProvider("t", cfg, Settings(base_url="http://app.test"), http)


async def _login(provider, idp, query_override=None):
    redirect = await provider.start_login("/")
    q = {k: v[0] for k, v in parse_qs(urlsplit(redirect.url).query).items()}
    idp.nonce = q["nonce"]
    query = {"code": "abc", "state": q["state"], **(query_override or {})}
    return q, await provider.finish_login(CallbackData("/auth/t/callback", query, {}), redirect.state)


async def test_happy_path_uses_pkce(provider, idp):
    q, raw = await _login(provider, idp)
    assert q["code_challenge_method"] == "S256"
    assert q["redirect_uri"] == "http://app.test/auth/t/callback"
    assert "code_verifier" in idp.token_form
    assert raw.attributes["sub"] == "u1"
    assert raw.logout_hint["id_token"]
    assert provider.normalize(raw).email == "a@example.com"


@pytest.mark.parametrize(
    "override",
    [
        {"aud": "someone-else"},
        {"iss": "https://evil"},
        {"nonce": "wrong"},
        {"exp": int(time.time()) - 3600},
        {"exp": None},
        {"sub": None},
        {"aud": [CLIENT, "other"]},  # multiple aud without azp
    ],
)
async def test_rejects_bad_claims(provider, idp, override):
    idp.claims_override = override
    with pytest.raises(AuthError):
        await _login(provider, idp)


async def test_rejects_wrong_signing_key(provider, idp):
    idp.sign_key = OTHER_KEY
    with pytest.raises(AuthError):
        await _login(provider, idp)


async def test_rejects_hs256_with_public_key_confusion(provider, idp):
    idp.header = {"alg": "HS256", "kid": "idp-1"}
    idp.sign_key = OctKey.import_key(b"x" * 32)
    with pytest.raises(AuthError):
        await _login(provider, idp)


async def test_rejects_state_mismatch(provider, idp):
    with pytest.raises(AuthError, match="state"):
        await _login(provider, idp, {"state": "forged"})


async def test_rejects_idp_error(provider, idp):
    with pytest.raises(AuthError):
        await _login(provider, idp, {"error": "access_denied"})


async def test_discovery_issuer_must_match(idp):
    cfg = OIDCTenant(
        protocol="oidc",
        display_name="t",
        issuer=ISS + "/x",
        client_id=CLIENT,
        discovery_url=f"{ISS}/.well-known/openid-configuration",
    )
    http = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    p = OIDCProvider("t", cfg, Settings(), http)
    with pytest.raises(AuthError, match="issuer"):
        await p.start_login("/")


async def test_logout_url(provider, idp):
    r = await provider.start_logout({"id_token": "tok"})
    q = parse_qs(urlsplit(r.url).query)
    assert q["id_token_hint"] == ["tok"]
    assert q["post_logout_redirect_uri"] == ["http://app.test/"]


def _restricted(idp, **cfg_kwargs):
    cfg = OIDCTenant(
        protocol="oidc",
        display_name="g",
        issuer=ISS,
        client_id=CLIENT,
        client_secret="s",
        allowed_email_domains=["example.com"],
        **cfg_kwargs,
    )
    http = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    return OIDCProvider("g", cfg, Settings(base_url="http://app.test"), http)


@pytest.mark.parametrize("hd", [None, "evil.com"])
async def test_required_claim_hd_enforced(idp, hd):
    idp.claims_override = {"hd": hd, "email_verified": True}
    with pytest.raises(AuthError, match="hd"):
        await _login(_restricted(idp, required_claims={"hd": "example.com"}), idp)


async def test_required_claim_hd_ok(idp):
    idp.claims_override = {"hd": "example.com", "email_verified": True}
    _, raw = await _login(_restricted(idp, required_claims={"hd": "example.com"}), idp)
    assert raw.attributes["hd"] == "example.com"


@pytest.mark.parametrize("verified", [False, None, "true"])
async def test_domain_restriction_requires_verified_email(idp, verified):
    idp.claims_override = {"email_verified": verified}
    with pytest.raises(AuthError, match="verified"):
        await _login(_restricted(idp), idp)
