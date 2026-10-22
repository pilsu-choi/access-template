# PRD — SSO 연동 템플릿 (sso-template)

- 상태: Draft v0.1
- 작성일: 2026-10-22

## 1. 배경

고객사(주로 엔터프라이즈·금융권)에 서비스를 납품할 때마다 SSO 연동을 처음부터 다시 구현하고 있다.
고객사마다 IdP(Entra ID, Okta, ADFS, Keycloak 등)와 프로토콜(OIDC / SAML 2.0)이 다르고,
클레임 이름·역할 체계·망 구성도 제각각이라 매번 같은 실수(redirect URI 불일치, 시계 오차,
인증서 만료, 서명 검증 누락)가 반복된다.

이 템플릿은 **우리 서비스가 SP / RP 로서 고객사 IdP 에 붙는** 표준 출발점을 제공한다.

## 2. 목표

1. 새 프로젝트가 이 템플릿을 복사해 **설정 파일(tenants.yaml) 수정만으로** OIDC 또는 SAML 로그인을 붙일 수 있다.
2. 프로토콜 차이를 **Provider Adapter** 뒤로 숨기고, 앱 코드는 정규화된 `Identity`(subject, email, name, groups, roles)만 다룬다.
3. 보안 기본값이 안전하다 (아래 §6). 개발자가 별도로 켜지 않아도 서명·issuer·audience·만료·replay 검증이 동작한다.
4. `docker compose up` 한 번으로 로컬 mock IdP(Keycloak)가 OIDC·SAML 클라이언트와 테스트 계정이 갖춰진 상태로 뜬다.
5. 고객사 온보딩 시 요청해야 할 정보와 IdP 별 설정 방법이 wiki 에 정리되어 있다.

## 3. 비목표 (v1 에서 하지 않음)

- 우리가 IdP 가 되는 것 (토큰 발급 서버)
- 국내 레거시 SSO 솔루션 adapter (에이전트/토큰 검증 API 방식) — Adapter 인터페이스로 확장 가능하게만 설계
- SCIM 기반 사용자 동기화
- 영속 DB 기반 사용자 저장소 (인터페이스 + in-memory 구현만 제공)
- Redis 세션 스토어 구현 (인터페이스만 제공, 구현은 프로젝트별)

## 4. 사용자

| 사용자 | 니즈 |
|---|---|
| 서비스 개발자 | 빠르게 SSO 를 붙이고, 앱 코드에서 `current_user`, `require_role` 만 쓰고 싶다 |
| 납품/구축 엔지니어 | 고객사 IdP 담당자와 무엇을 주고받아야 하는지 체크리스트가 필요하다 |
| 코딩 에이전트 | 일관된 구조와 규칙(AGENTS.md)을 따라 새 provider 를 안전하게 추가한다 |

## 5. 기능 요구사항

### 5.1 MVP (v1)

| ID | 요구사항 |
|---|---|
| F-1 | OIDC Authorization Code Flow + PKCE(S256), discovery 기반 엔드포인트 자동 구성 |
| F-2 | OIDC ID Token 검증: 서명(JWKS), `iss`, `aud`, `exp`, `iat`, `nonce`, 허용 알고리즘 화이트리스트 |
| F-3 | SAML 2.0 SP-initiated 로그인 (HTTP-Redirect AuthnRequest → HTTP-POST Response) |
| F-4 | SAML Response 검증: 서명(Assertion 필수), Audience, Destination, InResponseTo, NotBefore/NotOnOrAfter, Assertion ID replay 차단 |
| F-5 | SP metadata 엔드포인트 (`/auth/{tenant}/metadata`) |
| F-6 | IdP metadata URL 또는 정적 설정으로 SAML IdP 구성 |
| F-7 | 클레임/속성 매핑을 테넌트 설정으로 정의 → 정규화된 `Identity` |
| F-8 | 그룹 → 역할 매핑, 기본 역할 |
| F-9 | JIT 프로비저닝 (`UserRepository.upsert`) |
| F-10 | 서버 사이드 세션 (불투명 session id 쿠키 + `SessionStore`), 로그인 시 세션 재발급(fixation 방지), 유휴/절대 만료 |
| F-11 | 로그아웃: OIDC RP-initiated logout, SAML SP-initiated SLO |
| F-12 | 멀티 테넌트: URL 경로 `/auth/{tenant}/...` 로 IdP 설정 분리 |
| F-13 | `return_to` 는 같은 origin 의 상대 경로만 허용 (open redirect 차단) |
| F-14 | 앱용 의존성: `current_user`, `require_role("admin")` |
| F-15 | 소셜/퍼블릭 OIDC IdP(Google, Kakao 등)도 동일 OIDC adapter 로 설정만으로 연동. Google 예시 설정 제공 |
| F-16 | 테넌트별 허용 이메일 도메인 제한(`allowed_email_domains`, OIDC 는 `email_verified` 필수) + 필수 클레임 일치(`required_claims`, 예: Google Workspace `hd`) |

### 5.2 이후 (v2+, 선택)

- SAML IdP-initiated 로그인 (기본 비활성, 켜면 replay·CSRF 리스크 문서화)
- OIDC back-channel logout, SAML IdP-initiated SLO
- Redis `SessionStore`, SQL `UserRepository`
- 국내 레거시 SSO adapter 예시
- 순수 OAuth2(OIDC 미지원) adapter — GitHub, Naver 등. id_token 대신 userinfo API 로 사용자 정보 조회
- IdP 인증서 rotation 자동 감지 (metadata 주기적 refresh)

## 6. 보안 요구사항

| ID | 요구사항 |
|---|---|
| S-1 | 암호화·서명 검증은 검증된 라이브러리(`joserfc`, `python3-saml`/`xmlsec`)에 위임. 직접 구현 금지 |
| S-2 | OIDC `state`, `nonce`, PKCE 필수. 로그인 시작 정보는 서버 사이드 pending store 에 저장하고 브라우저 쿠키로 바인딩 |
| S-3 | 허용 서명 알고리즘 화이트리스트 (OIDC 기본 `RS256`, `ES256`; SAML deprecated 알고리즘(SHA-1) 거부) |
| S-4 | 시계 오차 허용치는 설정값(기본 60초)으로 제한 |
| S-5 | 토큰·Assertion·Authorization code·client secret 은 로그에 남기지 않음 |
| S-6 | 세션 쿠키 `HttpOnly`, `SameSite=Lax`, 운영에서 `Secure` |
| S-7 | SP 개인키·client secret 은 저장소에 커밋하지 않음 (env / secret manager) |
| S-8 | 실패 시 사용자에게는 일반 오류만 노출, 상세 사유는 서버 로그에(민감값 제외) |

## 7. 기술 스택

- Python 3.12, FastAPI, uvicorn, uv
- OIDC: `httpx` + `joserfc` (JWT/JWKS 검증)
- SAML: `python3-saml` (`xmlsec` wheel 포함)
- 로컬 IdP: Keycloak 26.4.7 (docker compose, realm 자동 import)
- 테스트: pytest, Playwright(E2E)

## 8. 완료 기준 (v1)

- [x] `docker compose up` 후 수동 설정 없이 Keycloak realm `sso-dev` 에 OIDC·SAML 클라이언트와 테스트 사용자가 존재
- [x] 로컬 Keycloak 대상으로 **OIDC 로그인 → /me → 로그아웃** 이 실제 브라우저에서 성공
- [x] 로컬 Keycloak 대상으로 **SAML 로그인 → /me → 로그아웃(SLO)** 이 실제 브라우저에서 성공
- [x] 그룹 `admins` 사용자만 `/admin` 접근 가능
- [x] 단위 테스트 통과: 클레임 매핑, 설정 검증, return_to 검증, OIDC ID Token 거부 케이스(서명·aud·iss·nonce·만료), SAML Response 거부 케이스(서명 없음/변조·audience·만료)
- [x] wiki: onboarding-checklist, Keycloak 가이드, 트러블슈팅 작성

## 9. 오픈 이슈

- 운영 배포 형태(컨테이너 이미지 표준)는 프로젝트별로 결정
- 운영 https 환경의 SAML pending 쿠키(`SameSite=None; Secure`) 경로는 아직 미검증 — 로컬은 http + `Lax` 로만 E2E 확인
- Google / Entra / Okta / ADFS 실연동 미검증 (wiki 는 초안)
- 고객사별 국내 SSO 솔루션 목록 수집 필요 → v2 adapter 우선순위 결정
