# 테넌트(IdP) 추가하기

표준 OIDC / SAML IdP 는 코드 변경 없이 `config/tenants.yaml` 에 블록을 추가하면 된다.
테넌트 id 는 URL 경로(`/auth/{tenant}/...`)가 되므로 `[a-z0-9-]` 만 쓴다. 바꾸면 IdP 등록 URL 도 바뀐다.

비밀값은 `${ENV_VAR}` 로 참조하고 `.env`(개발) 또는 secret manager(운영)로 주입한다.
`${VAR:-default}` 도 지원한다. 정의되지 않은 변수는 기동 시 오류.

## 공통 필드

| 필드 | 설명 |
|---|---|
| `protocol` | `oidc` 또는 `saml` |
| `display_name` | 로그인 화면 표시명 |
| `claims.subject` | 사용자 고유 식별자로 쓸 클레임/속성. SAML 은 `$nameid` 로 NameID 지정 |
| `claims.email` / `claims.name` / `claims.groups` | 매핑할 클레임 이름. `name` 은 리스트면 공백으로 이어붙임. 없으면 `null` |
| `roles.groups` | 그룹 값 → 역할 리스트 |
| `roles.default` | 모든 사용자에게 주는 역할 (기본 `[user]`) |
| `allowed_email_domains` | 비어있지 않으면 이 도메인 이메일만 로그인 허용 |

알 수 없는 필드는 오류로 처리된다 (오타 방지).

## OIDC 전용

| 필드 | 기본값 | 설명 |
|---|---|---|
| `issuer` | (필수) | discovery 문서의 `issuer` 와 **정확히** 일치해야 함 |
| `client_id` / `client_secret` | | secret 이 없으면 public client (PKCE 만) |
| `discovery_url` | `{issuer}/.well-known/openid-configuration` | |
| `scopes` | `[openid, profile, email]` | `openid` 필수 |
| `allowed_algs` | `[RS256, ES256]` | `none`, `HS*` 는 설정 단계에서 거부 |
| `use_userinfo` | `false` | id_token 에 없는 클레임을 userinfo 에서 보충 |
| `extra_auth_params` | `{}` | 인가 요청에 추가할 파라미터 (예: Google `hd`, `prompt`). 보안 검증 아님 |
| `required_claims` | `{}` | 검증된 id_token 클레임 정확 일치 조건 (예: Google `{hd: example.com}`) |
| `require_email_verified` | `true` | `allowed_email_domains` 사용 시 `email_verified == true` 요구 |

## SAML 전용

| 필드 | 기본값 | 설명 |
|---|---|---|
| `idp_metadata_url` | | 권장. 1시간 캐시 |
| `idp` | | metadata URL 이 없을 때 정적 설정 (`entity_id`, `sso_url`, `slo_url`, `x509cert`). 둘 중 하나만 |
| `idp_entity_id` | | metadata 에 여러 IdP 가 있을 때 선택 |
| `sp_entity_id` | `{BASE_URL}/auth/{tenant}/metadata` | |
| `sp_cert_file` / `sp_key_file` | (필수) | SP 서명 키. 운영은 `/run/secrets/...` 등 |
| `name_id_format` | unspecified | |
| `sign_authn_requests` | `true` | |
| `want_messages_signed` | `false` | Response 전체 서명까지 요구. Assertion 서명은 항상 필수 |

## 순서

1. 블록 추가 → 앱 재시작 → 홈 화면에 표시되는지 확인
2. SAML: `/auth/{tenant}/metadata` 를 IdP 담당자에게 전달
3. 테스트 계정으로 로그인 → `/me` 에서 매핑 결과 확인, 필요하면 `claims` 조정
4. `wiki/providers/` 에 해당 IdP 메모 추가
