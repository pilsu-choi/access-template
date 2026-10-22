# sso-template

FastAPI 기반 **OIDC / SAML 2.0 SSO 연동 스타터**. 고객사 IdP(Keycloak, Entra ID, Okta, ADFS, Google 등)에
SP/RP 로 붙는 코드를 설정 파일만으로 구성한다.

- 요구사항: [PRD.md](PRD.md)
- 개발 규칙 (사람·에이전트 공통): [AGENTS.md](AGENTS.md)
- 문서: [wiki/](wiki/README.md)

## 빠른 시작

```bash
uv sync
uv run python scripts/dev_setup.py   # .env, SP 인증서, Keycloak realm 생성
docker compose up -d                 # Keycloak http://localhost:8080 (admin/admin)
uv run uvicorn sso_template.main:app --reload --port 8000
```

http://localhost:8000 에서 `Keycloak (OIDC)` 또는 `Keycloak (SAML)` 선택 → `alice/alice` (admin) 또는 `bob/bob`.

## 앱 코드에서 사용

```python
from typing import Annotated
from fastapi import Depends
from sso_template.app import require_role, require_user
from sso_template.auth.base import Identity


@app.get("/reports")
async def reports(user: Annotated[Identity, Depends(require_role("admin"))]): ...
```

## 테스트

```bash
uv run pytest           # 단위 (IdP 불필요)
uv run pytest -m e2e    # Playwright, Keycloak + 앱 실행 상태에서
```
