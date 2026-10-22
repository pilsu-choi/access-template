# OIDC — Authorization Code + PKCE

```
Browser            App (RP)                              IdP
  | GET /auth/t/login |                                   |
  |------------------>| state, nonce, code_verifier 생성   |
  |                   | → pending store, sso_pending 쿠키  |
  |<-- 302 authorize?client_id&redirect_uri&state&nonce&code_challenge(S256)
  |------------------------------------------------------>| 로그인
  |<-- 302 /auth/t/callback?code&state -------------------|
  |------------------>| pending pop, state 비교            |
  |                   |-- POST token (code, code_verifier, client auth) -->|
  |                   |<-- id_token, access_token ---------|
  |                   | id_token 검증 → Identity → 세션 생성 |
  |<-- 303 return_to + sso_session 쿠키                    |
```

## 검증 항목 (`auth/oidc.py`)

- discovery 문서 `issuer` == 설정 `issuer`
- 서명: JWKS 공개키, `allowed_algs` 화이트리스트 (`none`/`HS*` 금지). 알 수 없는 kid 면 JWKS 1회 재조회
- `iss`, `aud`(client_id 포함), `sub`, `exp`, `iat`, `nonce` 필수, leeway = `clock_skew_seconds`
- `aud` 가 여러 개면 `azp` == client_id
- `state` 는 상수 시간 비교, pending 은 1회용
- `use_userinfo` 사용 시 userinfo `sub` == id_token `sub`

## 로그아웃

RP-initiated logout: `end_session_endpoint?id_token_hint&post_logout_redirect_uri&client_id`.
로컬 세션은 리다이렉트 전에 먼저 삭제한다.

## 소셜 / 퍼블릭 IdP

Google, Kakao 처럼 OIDC 를 지원하면 같은 adapter 로 동작한다 ([providers/google.md](../providers/google.md)).
GitHub, Naver 처럼 OIDC 가 아닌 순수 OAuth2 는 id_token 이 없어 별도 adapter 필요 (PRD v2).
