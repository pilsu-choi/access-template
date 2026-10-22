import base64
import datetime as dt
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.constants import OneLogin_Saml2_Constants as C
from onelogin.saml2.utils import OneLogin_Saml2_Utils as U

from sso_template.auth.base import AuthError, CallbackData
from sso_template.auth.saml import SAMLProvider
from sso_template.config import SAMLIdP, SAMLTenant
from sso_template.settings import Settings
from sso_template.store import InMemoryTTLStore

BASE = "http://app.test"
ACS = f"{BASE}/auth/t/acs"
SP_ENTITY = f"{BASE}/auth/t/metadata"
IDP_ENTITY = "https://idp.test/saml"


def _keypair(cn: str) -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return key_pem, cert.public_bytes(serialization.Encoding.PEM).decode()


IDP_KEY, IDP_CERT = _keypair("idp")
EVIL_KEY, EVIL_CERT = _keypair("evil")
SP_KEY, SP_CERT = _keypair("sp")


def _ts(delta_s: int = 0) -> str:
    t = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=delta_s)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_response(
    request_id: str,
    *,
    audience: str = SP_ENTITY,
    not_after: int = 300,
    sign_key: str | None = IDP_KEY,
    sign_cert: str = IDP_CERT,
    assertion_id: str = "_a1",
    tamper: bool = False,
) -> str:
    assertion = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="{_ts()}"><saml:Issuer>{IDP_ENTITY}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{request_id}" NotOnOrAfter="{_ts(not_after)}" Recipient="{ACS}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{_ts(-60)}" NotOnOrAfter="{_ts(not_after)}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{_ts()}" SessionIndex="sess-1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"""  # noqa: E501
    if sign_key:
        signed = U.add_sign(
            assertion, sign_key, sign_cert, sign_algorithm=C.RSA_SHA256, digest_algorithm=C.SHA256
        )
        assertion = signed.decode() if isinstance(signed, bytes) else signed
        assertion = assertion.split("?>", 1)[-1].strip()
    if tamper:
        assertion = assertion.replace("alice@example.com", "mallory@example.com")
    response = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="{_ts()}" Destination="{ACS}" InResponseTo="{request_id}"><saml:Issuer>{IDP_ENTITY}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{assertion}</samlp:Response>"""  # noqa: E501
    return base64.b64encode(response.encode()).decode()


@pytest.fixture
def provider(tmp_path):
    (tmp_path / "sp.crt").write_text(SP_CERT)
    (tmp_path / "sp.key").write_text(SP_KEY)
    cfg = SAMLTenant(
        protocol="saml",
        display_name="t",
        idp=SAMLIdP(
            entity_id=IDP_ENTITY,
            sso_url="https://idp.test/sso",
            slo_url="https://idp.test/slo",
            x509cert=IDP_CERT,
        ),
        sp_cert_file=tmp_path / "sp.crt",
        sp_key_file=tmp_path / "sp.key",
    )
    return SAMLProvider("t", cfg, Settings(base_url=BASE), httpx.AsyncClient(), InMemoryTTLStore())


async def _start(provider):
    redirect = await provider.start_login("/")
    assert parse_qs(urlsplit(redirect.url).query)["Signature"]  # AuthnRequest is signed
    return redirect.state


def _acs(saml_response: str) -> CallbackData:
    return CallbackData("/auth/t/acs", {}, {"SAMLResponse": saml_response})


async def test_valid_response(provider):
    state = await _start(provider)
    raw = await provider.finish_login(_acs(make_response(state["request_id"])), state)
    ident = provider.normalize(raw)
    assert ident.subject == "alice"
    assert ident.email == "alice@example.com"
    assert ident.groups == ("admins",)
    assert raw.logout_hint["session_index"] == "sess-1"


async def test_replay_rejected(provider):
    state = await _start(provider)
    resp = make_response(state["request_id"])
    await provider.finish_login(_acs(resp), state)
    with pytest.raises(AuthError, match="replay"):
        await provider.finish_login(_acs(resp), state)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"sign_key": None},  # unsigned
        {"tamper": True},  # modified after signing
        {"sign_key": EVIL_KEY, "sign_cert": EVIL_CERT},  # signed by someone else
        {"audience": "https://other-sp"},  # wrong audience
        {"not_after": -600},  # expired
    ],
)
async def test_bad_responses_rejected(provider, kwargs):
    state = await _start(provider)
    with pytest.raises(AuthError):
        await provider.finish_login(_acs(make_response(state["request_id"], **kwargs)), state)


async def test_in_response_to_mismatch(provider):
    state = await _start(provider)
    with pytest.raises(AuthError):
        await provider.finish_login(_acs(make_response("_someone-elses-request")), state)


async def test_sp_metadata(provider):
    xml = provider.sp_metadata()
    assert SP_ENTITY in xml and ACS in xml and 'AuthnRequestsSigned="true"' in xml


async def test_logout_request_signed(provider):
    r = await provider.start_logout({"name_id": "alice", "session_index": "sess-1"})
    assert r.url.startswith("https://idp.test/slo?")
    assert "Signature=" in r.url and r.state["request_id"]
