"""FastAPI wiring: auth routes, session cookies and app-facing dependencies."""

from __future__ import annotations

import html
import logging
import secrets
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from access_template.auth.base import AuthError, AuthProvider, CallbackData, Identity
from access_template.auth.registry import build_providers
from access_template.auth.saml import SAMLProvider
from access_template.config import ConfigError, TenantsFile, load_tenants
from access_template.rbac.base import Authorizer, Resource, Visibility
from access_template.rbac.config import RBACPolicy, load_policy
from access_template.rbac.policy import build_authorizer
from access_template.session import Session, SessionManager
from access_template.settings import RBACSettings, Settings
from access_template.store import InMemoryTTLStore, TTLStore
from access_template.users import InMemoryUserRepository, UserRepository

log = logging.getLogger("access_template")


def safe_return_to(value: str | None) -> str:
    """Allow only same-origin relative paths; anything else falls back to '/'."""
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or any(ord(c) < 0x20 for c in value):
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return "/"
    return value


def check_role_names(tenants: TenantsFile, policy: RBACPolicy) -> None:
    """Every role a tenant maps IdP groups to must be defined in the access policy."""
    for tid, t in tenants.tenants.items():
        used = set(t.roles.default) | {r for rs in t.roles.groups.values() for r in rs}
        unknown = used - set(policy.roles)
        if unknown:
            raise ConfigError(f"tenant {tid!r} maps to roles not in the access policy: {sorted(unknown)}")


# Demo data for /documents. A real app loads these from its DB and builds a `Resource` per row.
DEMO_DOCUMENTS = (
    Resource("document", "d1", org="sales-1", attrs={"title": "영업1팀 주간 보고"}),
    Resource("document", "d2", org="sales-2", attrs={"title": "영업2팀 실적"}),
    Resource("document", "d3", org="dev", attrs={"title": "개발본부 로드맵"}),
)


def create_app(
    settings: Settings | None = None,
    providers: dict[str, AuthProvider] | None = None,
    store: TTLStore | None = None,
    users: UserRepository | None = None,
    authorizer: Authorizer | None = None,
    rbac_settings: RBACSettings | None = None,
) -> FastAPI:
    settings = settings or Settings()
    rbac_settings = rbac_settings or RBACSettings()
    store = store or InMemoryTTLStore()
    users = users or InMemoryUserRepository()
    sessions = SessionManager(store, settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as http:
            policy = load_policy(rbac_settings.policy_file) if authorizer is None else None
            if providers is None:
                tenants = load_tenants(settings.tenants_file)
                # A custom authorizer built from a policy (e.g. with extra conditions) is checked too.
                known = policy or getattr(authorizer, "policy", None)
                if isinstance(known, RBACPolicy):
                    check_role_names(tenants, known)
                app.state.providers = build_providers(tenants, settings, http, store)
            else:
                app.state.providers = providers
            app.state.authorizer = authorizer if policy is None else build_authorizer(policy)
            yield

    app = FastAPI(title="access-template", lifespan=lifespan)
    app.state.settings = settings
    app.state.sessions = sessions
    app.state.users = users

    # --- helpers ---------------------------------------------------------

    def provider_for(request: Request, tenant: str) -> AuthProvider:
        p = request.app.state.providers.get(tenant)
        if p is None:
            raise HTTPException(404, "unknown tenant")
        return p

    def set_pending(resp: Response, record: dict[str, Any]) -> None:
        key = secrets.token_urlsafe(32)
        store.set(f"pending:{key}", record, settings.pending_login_seconds)
        # SAML responses arrive as a cross-site POST, which needs SameSite=None (+Secure).
        # Plain-http dev falls back to Lax; it works because localhost ports are same-site.
        samesite: Literal["none", "lax"] = "none" if settings.cookie_secure else "lax"
        resp.set_cookie(
            settings.pending_cookie,
            key,
            max_age=settings.pending_login_seconds,
            path="/auth",
            httponly=True,
            secure=settings.cookie_secure,
            samesite=samesite,
        )

    def take_pending(request: Request, tenant: str, kind: str) -> dict[str, Any]:
        key = request.cookies.get(settings.pending_cookie)
        record = store.pop(f"pending:{key}") if key else None
        if not record or record["tenant"] != tenant or record["kind"] != kind:
            raise AuthError(f"no matching pending {kind} for tenant {tenant!r}")
        return record

    def set_session_cookie(resp: Response, sid: str) -> None:
        resp.set_cookie(
            settings.session_cookie,
            sid,
            max_age=settings.session_absolute_seconds,
            path="/",
            httponly=True,
            secure=settings.cookie_secure,
            samesite="lax",
        )

    async def callback_data(request: Request) -> CallbackData:
        form: dict[str, str] = {}
        if request.method == "POST":
            form = {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
        return CallbackData(request.url.path, dict(request.query_params), form)

    def auth_failed(tenant: str, err: AuthError) -> HTMLResponse:
        log.warning("auth failed tenant=%s reason=%s", tenant, err)
        return HTMLResponse("<h1>로그인에 실패했습니다</h1><p><a href='/'>처음으로</a></p>", status_code=400)

    async def finish(request: Request, tenant: str) -> Response:
        provider = provider_for(request, tenant)
        try:
            pending = take_pending(request, tenant, "login")
            raw = await provider.finish_login(await callback_data(request), pending["state"])
            identity = provider.normalize(raw)
        except AuthError as e:
            return auth_failed(tenant, e)
        users.upsert(identity)
        # New session id on every login (session fixation).
        sessions.destroy(request.cookies.get(settings.session_cookie))
        sid = sessions.create(identity, raw.logout_hint)
        log.info("login tenant=%s user=%s", tenant, identity.user_id)
        resp = RedirectResponse(pending["return_to"], status_code=303)
        resp.delete_cookie(settings.pending_cookie, path="/auth")
        set_session_cookie(resp, sid)
        return resp

    # --- auth routes -----------------------------------------------------

    @app.get("/auth/{tenant}/login")
    async def login(request: Request, tenant: str, return_to: str | None = None) -> Response:
        provider = provider_for(request, tenant)
        target = safe_return_to(return_to)
        redirect = await provider.start_login(target)
        resp = RedirectResponse(redirect.url, status_code=302)
        set_pending(resp, {"tenant": tenant, "kind": "login", "return_to": target, "state": redirect.state})
        return resp

    @app.get("/auth/{tenant}/callback")
    async def oidc_callback(request: Request, tenant: str) -> Response:
        return await finish(request, tenant)

    @app.post("/auth/{tenant}/acs")
    async def saml_acs(request: Request, tenant: str) -> Response:
        return await finish(request, tenant)

    @app.get("/auth/{tenant}/metadata")
    async def saml_metadata(request: Request, tenant: str) -> Response:
        provider = provider_for(request, tenant)
        if not isinstance(provider, SAMLProvider):
            raise HTTPException(404)
        return Response(provider.sp_metadata(), media_type="application/samlmetadata+xml")

    @app.get("/auth/{tenant}/sls")
    async def saml_sls(request: Request, tenant: str) -> Response:
        provider = provider_for(request, tenant)
        try:
            pending = take_pending(request, tenant, "logout")
            await provider.finish_logout(await callback_data(request), pending["state"])
        except AuthError as e:
            # Local session is already gone; just report the IdP side failed.
            log.warning("logout response rejected tenant=%s reason=%s", tenant, e)
        resp = RedirectResponse("/", status_code=303)
        resp.delete_cookie(settings.pending_cookie, path="/auth")
        return resp

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        sess = sessions.destroy(request.cookies.get(settings.session_cookie))
        resp: Response = RedirectResponse("/", status_code=303)
        if sess is not None:
            provider = request.app.state.providers.get(sess.identity.tenant)
            redirect = await provider.start_logout(sess.logout_hint) if provider else None
            if redirect is not None:
                resp = RedirectResponse(redirect.url, status_code=303)
                if redirect.state:
                    set_pending(
                        resp,
                        {
                            "tenant": sess.identity.tenant,
                            "kind": "logout",
                            "return_to": "/",
                            "state": redirect.state,
                        },
                    )
        resp.delete_cookie(settings.session_cookie, path="/")
        return resp

    # --- demo app routes -------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request, user: Annotated[Identity | None, Depends(current_user)]):
        if user is None:
            links = "".join(
                f"<li><a href='/auth/{html.escape(t)}/login'>{html.escape(p.display_name)}</a>"
                f" <small>({p.protocol})</small></li>"
                for t, p in request.app.state.providers.items()
            )
            return f"<h1>access-template</h1><p>로그인 방식을 선택하세요</p><ul>{links}</ul>"
        return (
            f"<h1>안녕하세요, {html.escape(user.name or user.subject)}</h1>"
            f"<p>tenant: {html.escape(user.tenant)} / roles: "
            f"{html.escape(', '.join(sorted(user.roles)))}</p>"
            "<p><a href='/me'>/me</a> · <a href='/admin'>/admin</a></p>"
            "<form method='post' action='/logout'><button>로그아웃</button></form>"
        )

    @app.get("/me")
    async def me(access: Annotated[Access, Depends(get_access)]) -> dict[str, Any]:
        user = access.user
        return {
            "user_id": user.user_id,
            "tenant": user.tenant,
            "subject": user.subject,
            "email": user.email,
            "name": user.name,
            "groups": list(user.groups),
            "roles": sorted(user.roles),
            "orgs": list(user.orgs),
            "permissions": sorted(access.authorizer.permissions(user)),
        }

    @app.get("/admin")
    async def admin(user: Annotated[Identity, Depends(require_role("admin"))]) -> dict[str, str]:
        return {"message": f"admin area — hello {user.user_id}"}

    @app.get("/reports")
    async def reports(
        user: Annotated[Identity, Depends(require_permission("report:read"))],
    ) -> dict[str, str]:
        return {"message": f"reports for {user.user_id}"}

    @app.get("/documents")
    async def documents(access: Annotated[Access, Depends(get_access)]) -> list[dict[str, Any]]:
        # List filtering: turn the visible orgs into a query filter (`WHERE org IN (...)` in SQL).
        # Rows reachable only through a condition (e.g. `owner`) need a per-row `access.can()`.
        vis = access.visible("document:read")
        rows = [d for d in DEMO_DOCUMENTS if vis.covers(d.org)]
        if vis.conditional:
            rows += [d for d in DEMO_DOCUMENTS if d not in rows and access.can("document:read", d)]
        return [{"id": d.id, "org": d.org, **d.attrs} for d in rows]

    @app.get("/documents/{doc_id}")
    async def document(doc_id: str, access: Annotated[Access, Depends(get_access)]) -> dict[str, Any]:
        doc = next((d for d in DEMO_DOCUMENTS if d.id == doc_id), None)
        if doc is None:
            raise HTTPException(404)
        access.require("document:read", doc)
        return {"id": doc.id, "org": doc.org, **doc.attrs}

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return app


# --- dependencies for application code -------------------------------------


def current_session(request: Request) -> Session | None:
    settings: Settings = request.app.state.settings
    sessions: SessionManager = request.app.state.sessions
    return sessions.load(request.cookies.get(settings.session_cookie))


def current_user(
    session: Annotated[Session | None, Depends(current_session)],
) -> Identity | None:
    return session.identity if session else None


def require_user(user: Annotated[Identity | None, Depends(current_user)]) -> Identity:
    if user is None:
        raise HTTPException(401, "login required")
    return user


def require_role(*roles: str) -> Callable[[Identity], Identity]:
    def dep(user: Annotated[Identity, Depends(require_user)]) -> Identity:
        if not set(roles) <= user.roles:
            raise HTTPException(403, "insufficient role")
        return user

    return dep


@dataclass(frozen=True)
class Access:
    """The current user bound to the authorizer, for resource-level checks inside handlers."""

    user: Identity
    authorizer: Authorizer

    def can(self, permission: str, resource: Resource | None = None) -> bool:
        return self.authorizer.check(self.user, permission, resource).allowed

    def require(self, permission: str, resource: Resource | None = None) -> None:
        if not self.can(permission, resource):
            raise HTTPException(403, "permission denied")

    def visible(self, permission: str) -> Visibility:
        return self.authorizer.visible(self.user, permission)


def get_access(request: Request, user: Annotated[Identity, Depends(require_user)]) -> Access:
    return Access(user, request.app.state.authorizer)


def require_permission(*permissions: str) -> Callable[[Access], Identity]:
    """Route-level check: the user holds every permission somewhere. Conditional permissions
    (e.g. `when: owner`) never pass here — check those with `Access.require(perm, resource)`."""

    def dep(access: Annotated[Access, Depends(get_access)]) -> Identity:
        for p in permissions:
            access.require(p)
        return access.user

    return dep
