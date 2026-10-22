# AGENTS.md

OIDC / SAML 2.0 SSO 연동 스타터 (FastAPI). 우리 서비스가 **SP / RP** 로서 고객사 IdP 에 붙는다.
요구사항은 `PRD.md`, 개념·IdP 별 가이드는 `wiki/` 를 본다.

## 명령어

```bash
uv sync                                   # 의존성 설치 (Python 3.12, .python-version)
uv run python scripts/dev_setup.py        # .env, SP 인증서(.dev/sp), Keycloak realm import 생성 (idempotent)
docker compose up -d                      # 로컬 Keycloak :8080 (admin/admin), realm sso-dev
uv run uvicorn sso_template.main:app --reload --port 8000

uv run pytest                             # 단위 테스트 (e2e 제외, IdP 불필요)
uv run pytest -m e2e                      # 실제 브라우저 E2E. Keycloak + 앱이 떠 있어야 함
uv run playwright install chromium        # E2E 최초 1회
uv run ruff check . && uv run ruff format .
```

테스트 계정: `alice/alice` (admins → admin 역할), `bob/bob` (users).

## 구조

```
src/sso_template/
  app.py            # FastAPI 라우트, 쿠키, current_user / require_role 의존성
  main.py           # 엔트리포인트 + 접근 로그 redaction
  settings.py       # SSO_* 환경변수
  config.py         # tenants.yaml 스키마 (pydantic, extra=forbid), ${ENV} 치환
  session.py        # 서버 사이드 세션 (쿠키에는 불투명 id 만)
  store.py          # TTLStore 인터페이스 + InMemory 구현 (pending / session / replay)
  users.py          # JIT 프로비저닝 UserRepository
  auth/
    base.py         # AuthProvider 프로토콜, Identity, RawIdentity, CallbackData, Redirect
    claims.py       # 클레임 → Identity 정규화, 역할 매핑, 이메일 도메인 제한
    oidc.py         # OIDCProvider (httpx + joserfc)
    saml.py         # SAMLProvider (python3-saml)
    registry.py     # protocol → provider 생성
config/tenants.yaml           # 로컬 Keycloak 테넌트 2개 (kc-oidc, kc-saml)
config/tenants.example.yaml   # Google / Entra / 일반 SAML 예시
dev/keycloak/                 # realm import 템플릿 (실제 import 파일은 .dev/ 에 렌더링)
tests/                        # 단위 테스트, tests/e2e/ 는 Playwright
wiki/                         # 개념, IdP 별 가이드, 온보딩 체크리스트, 트러블슈팅
```

라우트: `/auth/{tenant}/login|callback|acs|metadata|sls`, `POST /logout`, `/me`, `/admin`, `/healthz`.

## 핵심 설계 규칙

- 웹 레이어(`app.py`)는 `AuthProvider` 인터페이스만 안다. 프로토콜별 코드는 `auth/` 안에만 둔다.
- 앱 코드는 `Identity` 만 쓴다. IdP 원본 클레임 이름을 앱 코드에 하드코딩하지 말고 `claims` 매핑으로 처리한다.
- 로그인 시작 상태(state, nonce, PKCE verifier, SAML request id, return_to)는 **서버 pending store** 에 저장하고
  `sso_pending` 쿠키로 브라우저와 바인딩한다. 1회용(pop).
- 세션은 서버 사이드. 로그인마다 새 session id 발급(fixation 방지).
- `return_to` 는 반드시 `safe_return_to()` 를 거친다.
- 고객사별 차이는 가능한 한 **설정(tenants.yaml)** 으로 흡수하고, 코드 분기는 최후 수단.

## 새 IdP / 테넌트 추가

1. 표준 OIDC / SAML IdP → 코드 변경 없이 `config/tenants.yaml` 에 블록 추가 (`tenants.example.yaml` 참고). `wiki/adding-a-tenant.md`.
2. 새 프로토콜(예: 순수 OAuth2, 국내 레거시 SSO) → `auth/<name>.py` 에 `AuthProvider` 구현,
   `config.py` 에 `protocol: Literal["<name>"]` 모델 추가 후 `TenantConfig` union 에 등록, `registry.py` 에 매핑.
   거부 케이스 위주 단위 테스트(`tests/test_oidc.py`, `tests/test_saml.py` 패턴)를 반드시 함께 작성.
3. `wiki/providers/<idp>.md` 에 설정 방법 기록.

## 금지 사항

- **암호화·서명·XML 검증 직접 구현 금지.** joserfc / python3-saml(xmlsec) 에 위임한다.
- 검증 완화 금지: `strict: False`, `wantAssertionsSigned: False`, `alg: none`/`HS*` 허용, aud/iss/nonce 검사 생략,
  clock skew 를 크게 늘리기 등은 PR 에서 명시적 합의 없이는 하지 않는다.
- 토큰, authorization code, SAMLResponse/Assertion, client secret, 개인키를 **로그·예외 메시지·응답에 넣지 않는다.**
  `AuthError` 메시지는 서버 로그로만 가고 사용자에게는 일반 오류만 보인다.
- 비밀값·SP 개인키를 커밋하지 않는다 (`.env`, `.dev/` 는 gitignore). 설정에는 `${ENV}` 참조만.
- `InMemoryTTLStore` / `InMemoryUserRepository` 는 단일 프로세스 개발용. 멀티 워커 운영에서는 교체해야 한다.

## 완료 판단

- `uv run pytest` 와 `uv run ruff check .` 통과
- 인증 흐름을 바꿨다면 `uv run pytest -m e2e` 로 OIDC·SAML 로그인/로그아웃을 실제 브라우저에서 확인
