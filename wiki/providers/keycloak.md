# Keycloak (로컬 개발용 mock IdP)

상태: **검증됨** — Keycloak 26.4.7, OIDC/SAML 로그인·로그아웃 E2E (`tests/e2e/test_keycloak.py`)

## 구성

`scripts/dev_setup.py` 가 `dev/keycloak/realm-sso-dev.template.json` 을 렌더링해 `.dev/keycloak-import/` 에 둔다.
`docker compose up` 시 `--import-realm` 으로 자동 import (클릭 설정 불필요).

| 항목 | 값 |
|---|---|
| Admin console | http://localhost:8080/admin (admin/admin) |
| Realm | `sso-dev` |
| OIDC client | `sso-template-oidc` (confidential, PKCE S256, secret = `.env` 의 `KC_OIDC_CLIENT_SECRET`) |
| SAML client | `http://localhost:8000/auth/kc-saml/metadata` (= SP Entity ID) |
| 사용자 | `alice/alice` (groups: admins, users), `bob/bob` (users) |

렌더링 시 치환: `__SP_CERT__`(SP 서명 인증서 — Keycloak 이 AuthnRequest 서명 검증), `__OIDC_CLIENT_SECRET__`, `__APP_BASE__`(`SSO_BASE_URL`).

## 주요 설정 포인트 (운영 Keycloak 에도 동일)

**OIDC**
- 그룹 클레임: `oidc-group-membership-mapper`, `claim.name=groups`, `full.path=false` (true 면 `/admins` 형태)
- `post.logout.redirect.uris` 에 `{BASE_URL}/` 등록해야 RP-initiated logout 후 돌아옴

**SAML**
- `saml.assertion.signature=true` (필수), `saml.server.signature=true`
- `saml.client.signature=true` + SP 인증서 등록 → AuthnRequest 서명 검증
- `saml_force_name_id_format=true`, `saml_name_id_format=username` → NameID = username
- ACS(POST), SLS(Redirect) URL 을 client 속성에 명시
- 속성 매퍼: email / firstName / lastName (user property), groups (`saml-group-membership-mapper`, `single=true`)

## 재설정

realm 은 컨테이너 최초 기동 시에만 import 된다. 템플릿을 바꿨다면:
```bash
uv run python scripts/dev_setup.py && docker compose down && docker compose up -d
```

## 주의

- 앱은 호스트에서 실행한다(`localhost:8000`). 앱을 컨테이너에 넣으면 브라우저가 보는 issuer
  (`localhost:8080`)와 컨테이너 내부 주소(`keycloak:8080`)가 달라 issuer 검증이 실패한다.
  이 경우 `KC_HOSTNAME` 설정 + `extra_hosts` 로 같은 이름을 쓰게 해야 한다.
- SP 인증서를 재생성(`.dev/sp` 삭제)하면 realm 도 다시 import 해야 한다.
