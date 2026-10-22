import pytest
from pydantic import ValidationError

from access_template.app import safe_return_to
from access_template.auth.base import AuthError, RawIdentity
from access_template.auth.claims import normalize
from access_template.config import ClaimMapping, ConfigError, RoleMapping, parse_tenants

OIDC = {"protocol": "oidc", "display_name": "x", "issuer": "https://idp", "client_id": "c"}


def test_env_interpolation_and_default():
    t = parse_tenants(
        {"tenants": {"a": {**OIDC, "issuer": "${ISS:-https://d}", "client_secret": "${SECRET}"}}},
        env={"SECRET": "s3"},
    )
    cfg = t.tenants["a"]
    assert cfg.issuer == "https://d"
    assert cfg.client_secret.get_secret_value() == "s3"
    assert "s3" not in repr(cfg)


def test_missing_env_is_error():
    with pytest.raises(ConfigError):
        parse_tenants({"tenants": {"a": {**OIDC, "client_secret": "${NOPE}"}}}, env={})


@pytest.mark.parametrize("tid", ["Bad", "a/b", "-x", ""])
def test_invalid_tenant_id(tid):
    with pytest.raises(ValidationError):
        parse_tenants({"tenants": {tid: OIDC}}, env={})


@pytest.mark.parametrize("algs", [["none"], ["HS256"], ["RS256", "HS512"]])
def test_weak_algs_rejected(algs):
    with pytest.raises(ValidationError):
        parse_tenants({"tenants": {"a": {**OIDC, "allowed_algs": algs}}}, env={})


def test_unknown_keys_rejected():
    with pytest.raises(ValidationError):
        parse_tenants({"tenants": {"a": {**OIDC, "clientid": "typo"}}}, env={})


def test_saml_needs_exactly_one_idp_source(tmp_path):
    base = {"protocol": "saml", "display_name": "s", "sp_cert_file": "c", "sp_key_file": "k"}
    with pytest.raises(ValidationError):
        parse_tenants({"tenants": {"s": base}}, env={})
    parse_tenants({"tenants": {"s": {**base, "idp_metadata_url": "https://m"}}}, env={})


def test_normalize_oidc_claims_and_roles():
    raw = RawIdentity({"sub": "u1", "email": "a@x.com", "name": "A", "groups": ["admins", "g2"]})
    ident = normalize("t", raw, ClaimMapping(), RoleMapping(groups={"admins": ["admin"]}))
    assert ident.user_id == "t:u1"
    assert ident.groups == ("admins", "g2")
    assert ident.roles == {"user", "admin"}


def test_normalize_saml_lists_and_joined_name():
    raw = RawIdentity({"$nameid": "alice", "email": ["a@x.com"], "firstName": ["Alice"], "lastName": ["Kim"]})
    m = ClaimMapping(subject="$nameid", email="email", name=["firstName", "lastName"], groups=None)
    ident = normalize("t", raw, m, RoleMapping())
    assert (ident.subject, ident.email, ident.name, ident.groups) == ("alice", "a@x.com", "Alice Kim", ())


def test_normalize_missing_subject():
    with pytest.raises(AuthError):
        normalize("t", RawIdentity({"email": "a@x.com"}), ClaimMapping(), RoleMapping())


@pytest.mark.parametrize("email", ["a@evil.com", None, "no-at-sign"])
def test_email_domain_restriction_rejects(email):
    raw = RawIdentity({"sub": "u", "email": email})
    with pytest.raises(AuthError):
        normalize("t", raw, ClaimMapping(), RoleMapping(), ["example.com"])


def test_email_domain_restriction_allows_case_insensitive():
    raw = RawIdentity({"sub": "u", "email": "a@Example.COM"})
    assert normalize("t", raw, ClaimMapping(), RoleMapping(), ["example.com"]).email


@pytest.mark.parametrize(
    "value,expected",
    [
        ("/dash?x=1", "/dash?x=1"),
        (None, "/"),
        ("https://evil.com", "/"),
        ("//evil.com", "/"),
        ("/\\evil.com", "/"),
        ("javascript:alert(1)", "/"),
        ("/ok\r\nSet-Cookie: x", "/"),
    ],
)
def test_safe_return_to(value, expected):
    assert safe_return_to(value) == expected
