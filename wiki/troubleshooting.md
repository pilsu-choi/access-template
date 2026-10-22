# 트러블슈팅

실패 상세 사유는 사용자 화면이 아니라 **서버 로그**(`auth failed tenant=... reason=...`)에 남는다.

| 증상 / 로그 | 원인 | 조치 |
|---|---|---|
| IdP 화면에 `Invalid parameter: redirect_uri` | IdP 에 등록된 Redirect URI 와 `{SSO_BASE_URL}/auth/{tenant}/callback` 불일치 | http/https, 포트, 끝 슬래시까지 일치시킨다. 프록시 뒤라면 `SSO_BASE_URL` 은 외부 URL |
| `discovery issuer ... != configured ...` | `issuer` 설정이 discovery 문서와 다름 | discovery 의 `issuer` 값을 그대로 복사 (끝 슬래시 주의, Entra 는 `/v2.0`) |
| `no matching pending login` | `sso_pending` 쿠키 미도착: 10분 초과, 다른 브라우저/탭, 쿠키 차단, **운영인데 `SSO_COOKIE_SECURE=false`** (SAML 은 cross-site POST 라 `SameSite=None; Secure` 필요) | 운영은 https + `SSO_COOKIE_SECURE=true`. 로그인 시작과 콜백 host 가 같은지 확인 |
| `id_token rejected: ExpiredTokenError` / SAML `... NotOnOrAfter ...` | 서버 시계 오차 | 양측 NTP 확인. `SSO_CLOCK_SKEW_SECONDS`(기본 60) 를 크게 늘리는 것은 최후 수단 |
| `id_token rejected: ... aud` | 다른 client 용 토큰 / client_id 오타 | |
| `id_token rejected: InvalidKeyIdError` | IdP 키 교체 직후. JWKS 는 1회 자동 재조회함 | 계속되면 discovery 의 jwks_uri 접근 가능한지(방화벽) 확인 |
| `token endpoint returned 401 error='invalid_client'` | client_secret 오류/만료, 인증 방식 불일치 | secret 재발급. 템플릿은 `client_secret_basic` 사용 |
| SAML `Signature validation failed` | IdP 인증서 교체됨, 잘못된 인증서, Assertion 미서명 | metadata URL 사용 시 앱 재시작(캐시 1시간). IdP 에서 **Assertion 서명** 켜기 |
| SAML `The response was received at ... instead of ...` | Destination 불일치 — `SSO_BASE_URL` 과 IdP 의 ACS URL 이 다름 | |
| SAML `Invalid audience` | IdP 에 등록된 SP Entity ID 와 `sp_entity_id` 불일치 | |
| SAML `Deprecated signature algorithm` | IdP 가 SHA-1 로 서명 | IdP 에서 RSA-SHA256 으로 변경 요청 (완화하지 말 것) |
| SAML `SAML assertion replayed` | 같은 Response 재전송 (뒤로가기 후 재제출 등) | 정상 차단. 새로 로그인 |
| `email domain ... not allowed` | `allowed_email_domains` 제한 | 의도된 동작인지 확인 |
| 로그아웃 후 바로 다시 로그인됨 | IdP 세션이 남아있음 (IdP 가 end_session/SLO 미지원 또는 미설정) | IdP SLO URL / end_session_endpoint 확인 |
| 멀티 워커에서 간헐적 로그인 실패 | `InMemoryTTLStore` 는 프로세스 로컬 | Redis 등 공유 스토어로 교체 |
