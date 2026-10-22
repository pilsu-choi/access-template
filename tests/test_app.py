"""Web-layer wiring tests with a fake provider (no IdP needed)."""

import pytest
from fastapi.testclient import TestClient

from access_template.app import create_app
from access_template.auth.base import AuthError, CallbackData, Identity, RawIdentity, Redirect
from access_template.auth.claims import normalize
from access_template.config import ClaimMapping, RoleMapping
from access_template.settings import Settings


class FakeProvider:
    protocol = "fake"
    display_name = "Fake"

    def __init__(self, tenant: str, groups: list[str]) -> None:
        self.tenant = tenant
        self.groups = groups
        self.logged_out = False

    async def start_login(self, return_to: str) -> Redirect:
        return Redirect("https://idp.test/authorize", {"expect": "good"})

    async def finish_login(self, data: CallbackData, state: dict[str, str]) -> RawIdentity:
        if data.query.get("code") != state["expect"]:
            raise AuthError("bad code")
        return RawIdentity({"sub": "u1", "groups": self.groups}, {"id_token": "t"})

    async def start_logout(self, hint):
        return Redirect("https://idp.test/logout")

    async def finish_logout(self, data, state) -> None:
        return None

    def normalize(self, raw: RawIdentity) -> Identity:
        return normalize(self.tenant, raw, ClaimMapping(), RoleMapping(groups={"admins": ["admin"]}))


def client(groups: list[str]) -> TestClient:
    settings = Settings(base_url="http://testserver", cookie_secure=False, _env_file=None)
    app = create_app(settings, providers={"fake": FakeProvider("fake", groups)})
    return TestClient(app, follow_redirects=False)


@pytest.fixture
def admin():
    with client(["admins"]) as c:
        yield c


def _login(c: TestClient, return_to: str = "/me", code: str = "good"):
    r = c.get("/auth/fake/login", params={"return_to": return_to})
    assert r.status_code == 302
    return c.get("/auth/fake/callback", params={"code": code})


def test_login_flow_and_roles(admin):
    assert admin.get("/me").status_code == 401
    r = _login(admin)
    assert r.status_code == 303 and r.headers["location"] == "/me"
    assert "HttpOnly" in r.headers["set-cookie"]
    assert admin.get("/me").json()["roles"] == ["admin", "user"]
    assert admin.get("/admin").status_code == 200


def test_non_admin_forbidden():
    with client(["users"]) as c:
        _login(c)
        assert c.get("/me").status_code == 200
        assert c.get("/admin").status_code == 403


def test_open_redirect_blocked(admin):
    r = _login(admin, return_to="https://evil.com")
    assert r.headers["location"] == "/"


def test_callback_without_pending_fails(admin):
    r = admin.get("/auth/fake/callback", params={"code": "good"})
    assert r.status_code == 400
    assert admin.get("/me").status_code == 401


def test_pending_is_single_use(admin):
    admin.get("/auth/fake/login")
    pending = admin.cookies.get("sso_pending")
    admin.get("/auth/fake/callback", params={"code": "good"})
    admin.cookies.set("sso_pending", pending, path="/auth")
    assert admin.get("/auth/fake/callback", params={"code": "good"}).status_code == 400


def test_failed_login_shows_generic_error(admin):
    r = _login(admin, code="bad")
    assert r.status_code == 400 and "bad code" not in r.text


def test_session_rotated_on_login(admin):
    _login(admin)
    first = admin.cookies.get("sso_session")
    _login(admin)
    second = admin.cookies.get("sso_session")
    assert first != second
    admin.cookies.set("sso_session", first)
    assert admin.get("/me").status_code == 401


def test_logout_destroys_session_and_redirects_to_idp(admin):
    _login(admin)
    sid = admin.cookies.get("sso_session")
    r = admin.post("/logout")
    assert r.status_code == 303 and r.headers["location"] == "https://idp.test/logout"
    admin.cookies.set("sso_session", sid)
    assert admin.get("/me").status_code == 401


def test_unknown_tenant(admin):
    assert admin.get("/auth/nope/login").status_code == 404
