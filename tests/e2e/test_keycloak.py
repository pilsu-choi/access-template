"""Real-browser E2E against local Keycloak.

Requires: `docker compose up -d` and the app on SSO_BASE_URL (default http://localhost:8000).
Run: uv run pytest -m e2e
"""

import json
import os

import httpx
import pytest
from playwright.sync_api import Page

APP = os.environ.get("SSO_BASE_URL", "http://localhost:8000")
KC = "http://localhost:8080/realms/sso-dev"

pytestmark = pytest.mark.e2e


@pytest.fixture(autouse=True, scope="module")
def _require_stack():
    try:
        httpx.get(f"{APP}/healthz", timeout=2).raise_for_status()
        httpx.get(f"{KC}/.well-known/openid-configuration", timeout=2).raise_for_status()
    except httpx.HTTPError:
        pytest.skip("app or Keycloak not running")


def kc_login(page: Page, user: str) -> None:
    page.fill("#username", user)
    page.fill("#password", user)
    page.click("#kc-login")


def me(page: Page) -> dict:
    page.goto(f"{APP}/me")
    return json.loads(page.inner_text("body"))


@pytest.mark.parametrize("tenant", ["kc-oidc", "kc-saml"])
def test_admin_login_logout(page: Page, tenant: str):
    page.goto(f"{APP}/auth/{tenant}/login?return_to=/me")
    kc_login(page, "alice")
    page.wait_for_url(f"{APP}/me")
    info = me(page)
    assert info["tenant"] == tenant
    assert info["email"] == "alice@example.com"
    assert info["name"] == "Alice Admin"
    assert "admins" in info["groups"]
    assert info["roles"] == ["admin", "user"]
    assert page.goto(f"{APP}/admin").status == 200
    assert page.goto(f"{APP}/reports").status == 200  # admin: "*" globally

    page.goto(f"{APP}/")
    page.click("text=로그아웃")
    page.wait_for_url(f"{APP}/")
    assert page.goto(f"{APP}/me").status == 401

    # IdP session must be gone too: logging in again asks for credentials.
    page.goto(f"{APP}/auth/{tenant}/login")
    assert page.locator("#username").is_visible()


@pytest.mark.parametrize("tenant", ["kc-oidc", "kc-saml"])
def test_non_admin_forbidden(page: Page, tenant: str):
    page.goto(f"{APP}/auth/{tenant}/login?return_to=/me")
    kc_login(page, "bob")
    page.wait_for_url(f"{APP}/me")
    info = me(page)
    assert info["roles"] == ["user"]
    assert info["orgs"] == []  # local Keycloak sends no org claim
    assert page.goto(f"{APP}/admin").status == 403
    assert page.goto(f"{APP}/reports").status == 403
    page.goto(f"{APP}/documents")
    assert json.loads(page.inner_text("body")) == []  # `user` is org-scoped, bob has no org
