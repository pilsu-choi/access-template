from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process-wide settings. Read from `SSO_*` env vars or `.env`."""

    model_config = SettingsConfigDict(env_prefix="SSO_", env_file=".env", extra="ignore")

    # Public base URL as seen by the browser. Used to build redirect / ACS URLs,
    # so it must match what is registered at the IdP exactly.
    base_url: str = "http://localhost:8000"
    tenants_file: Path = Path("config/tenants.yaml")

    # Must be True in any environment served over https.
    cookie_secure: bool = True
    session_cookie: str = "sso_session"
    pending_cookie: str = "sso_pending"

    session_idle_seconds: int = 30 * 60
    session_absolute_seconds: int = 8 * 60 * 60
    pending_login_seconds: int = 10 * 60
    clock_skew_seconds: int = 60
    http_timeout_seconds: float = 10.0

    @property
    def base(self) -> str:
        return self.base_url.rstrip("/")


class RBACSettings(BaseSettings):
    """Access-control settings. Read from `RBAC_*` env vars or `.env`."""

    model_config = SettingsConfigDict(env_prefix="RBAC_", env_file=".env", extra="ignore")

    policy_file: Path = Path("config/rbac.yaml")
