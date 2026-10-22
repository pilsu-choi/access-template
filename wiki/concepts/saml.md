# SAML 2.0 — SP-initiated SSO / SLO

```
Browser            App (SP)                              IdP
  | GET /auth/t/login |                                   |
  |------------------>| 서명된 AuthnRequest 생성, request id → pending
  |<-- 302 IdP SSO URL?SAMLRequest&SigAlg&Signature (HTTP-Redirect)
  |------------------------------------------------------>| 로그인
  |<-- auto-submit form POST /auth/t/acs (SAMLResponse) --|
  |------------------>| pending pop → process_response(request_id)
  |                   | 검증 → replay 체크 → Identity → 세션
  |<-- 303 return_to                                       |
```

## 검증 항목 (`auth/saml.py`, python3-saml strict 모드)

- **Assertion 서명 필수** (`wantAssertionsSigned`), IdP 인증서로 검증, SHA-1 거부
- `InResponseTo` == 우리가 보낸 AuthnRequest ID (unsolicited/IdP-initiated 응답 거부)
- `Destination` / `Recipient` == ACS URL (`SSO_BASE_URL` 기준, Host 헤더 미사용)
- `Audience` == SP Entity ID
- `NotBefore` / `NotOnOrAfter` (허용 오차 `clock_skew_seconds`)
- Assertion ID replay 캐시 (NotOnOrAfter 까지 보관)
- `RelayState` 는 신뢰하지 않음. return_to 는 서버 pending 에 보관

## SLO

`POST /logout` → 로컬 세션 삭제 → 서명된 LogoutRequest(NameID, SessionIndex)로 IdP 리다이렉트 →
IdP 가 `/auth/t/sls?SAMLResponse=...` 로 LogoutResponse → request id 대조 검증.
IdP-initiated LogoutRequest 처리는 v2.

## 쿠키 주의

IdP → ACS 는 **cross-site POST** 다. 운영(https)에서 `sso_pending` 쿠키는 `SameSite=None; Secure` 로 나간다
(`SSO_COOKIE_SECURE=true`). 로컬 http 개발은 `localhost:8080 → localhost:8000` 이 same-site 라 `Lax` 로 동작.
