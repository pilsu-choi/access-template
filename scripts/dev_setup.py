"""Prepare the local dev environment (idempotent).

- generates a self-signed SP signing cert/key into .dev/sp/ (gitignored)
- renders the Keycloak realm import with that cert into .dev/keycloak-import/
- creates .env from .env.example if missing

Usage: uv run python scripts/dev_setup.py
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent
SP_DIR = ROOT / ".dev" / "sp"
IMPORT_DIR = ROOT / ".dev" / "keycloak-import"


def ensure_sp_cert() -> str:
    cert_path, key_path = SP_DIR / "sp.crt", SP_DIR / "sp.key"
    if not cert_path.exists():
        SP_DIR.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sso-template dev SP")])
        now = dt.datetime.now(dt.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=825))
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(key_path, 0o600)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        print(f"generated {cert_path.relative_to(ROOT)}, {key_path.relative_to(ROOT)}")
    pem = cert_path.read_text()
    return "".join(line for line in pem.splitlines() if "-----" not in line)


def ensure_env() -> dict[str, str | None]:
    env_file = ROOT / ".env"
    if not env_file.exists():
        shutil.copy(ROOT / ".env.example", env_file)
        print("created .env from .env.example")
    return dotenv_values(env_file)


def render_realm(sp_cert_b64: str, env: dict[str, str | None]) -> None:
    template = (ROOT / "dev" / "keycloak" / "realm-sso-dev.template.json").read_text()
    out = (
        template.replace("__SP_CERT__", sp_cert_b64)
        .replace("__OIDC_CLIENT_SECRET__", env.get("KC_OIDC_CLIENT_SECRET") or "")
        .replace("__APP_BASE__", (env.get("SSO_BASE_URL") or "http://localhost:8000").rstrip("/"))
    )
    IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    (IMPORT_DIR / "realm-sso-dev.json").write_text(out)
    print(f"rendered {(IMPORT_DIR / 'realm-sso-dev.json').relative_to(ROOT)}")


if __name__ == "__main__":
    env = ensure_env()
    render_realm(ensure_sp_cert(), env)
    print("done. next: docker compose up -d && uv run uvicorn access_template.main:app --reload")
