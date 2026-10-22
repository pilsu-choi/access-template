# access-template

FastAPI 기반 **SSO 연동 + 접근 제어 스타터**. 고객사 납품 프로젝트의 출발점으로 복사해서 쓴다.

- **인증**: 고객사 IdP(Keycloak, Entra ID, Okta, ADFS, Google 등)에 OIDC / SAML 2.0 SP/RP 로 붙는 코드를 설정 파일만으로 구성
- **접근 제어**: 사용자·조직·역할 기반 권한 판정 (역할 상속, 조직 트리 범위, 소유자 조건, 감사 로그)

- 요구사항: [PRD.md](PRD.md)
- 개발 규칙 (사람·에이전트 공통): [AGENTS.md](AGENTS.md)
- 문서: [wiki/](wiki/README.md)

## 빠른 시작

```bash
uv sync
uv run python scripts/dev_setup.py   # .env, SP 인증서, Keycloak realm 생성
docker compose up -d                 # Keycloak http://localhost:8080 (admin/admin)
uv run uvicorn access_template.main:app --reload --port 8000
```

http://localhost:8000 에서 `Keycloak (OIDC)` 또는 `Keycloak (SAML)` 선택 → `alice/alice` (admin) 또는 `bob/bob`.
로그인 후 `/me`, `/reports`, `/documents` 로 역할·조직별 접근 결과를 볼 수 있다.

## 앱 코드에서 사용

```python
from typing import Annotated
from fastapi import Depends
from access_template.app import Access, get_access, require_permission, require_role
from access_template.auth.base import Identity
from access_template.rbac.base import Resource


@app.get("/admin")
async def admin(user: Annotated[Identity, Depends(require_role("admin"))]): ...


@app.get("/reports")  # 권한 기반 (config/rbac.yaml)
async def reports(user: Annotated[Identity, Depends(require_permission("report:read"))]): ...


@app.patch("/documents/{doc_id}")  # 리소스(조직·소유자) 기반
async def edit(doc_id: str, access: Annotated[Access, Depends(get_access)]):
    row = load(doc_id)
    access.require("document:edit", Resource("document", row.id, org=row.org_id, owner=row.author_id))
```

역할·권한·조직 트리는 `config/rbac.yaml` 에서 정의한다. 자세한 규칙은 [wiki/concepts/rbac.md](wiki/concepts/rbac.md).

## 테스트

```bash
uv run pytest           # 단위 (IdP 불필요)
uv run pytest -m e2e    # Playwright, Keycloak + 앱 실행 상태에서
```
