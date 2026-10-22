# Google (OIDC)

상태: **초안** — 설정 예시는 `config/tenants.example.yaml` 의 `google`. 이 저장소에서 실제 Google 계정 연동은 아직 미검증.

Google 은 표준 OIDC 를 지원하므로 코드 변경 없이 OIDC adapter 로 붙는다.

## 설정

1. Google Cloud Console → APIs & Services → OAuth consent screen 구성
2. Credentials → Create OAuth client ID → *Web application*
3. Authorized redirect URI: `{SSO_BASE_URL}/auth/google/callback`
4. client id / secret → `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`

```yaml
google:
  protocol: oidc
  display_name: Google
  issuer: https://accounts.google.com
  client_id: ${GOOGLE_CLIENT_ID}
  client_secret: ${GOOGLE_CLIENT_SECRET}
  scopes: [openid, email, profile]
  extra_auth_params: { hd: example.com }   # 계정 선택 화면만 좁힘 (UX)
  required_claims: { hd: example.com }     # 서버 검증: Workspace 도메인
  allowed_email_domains: [example.com]
  claims: { subject: sub, email: email, name: name, groups: null }
```

## 주의

- **사내 Workspace 계정만 허용하려면 `required_claims: {hd: ...}` 필수.** `extra_auth_params.hd` 는 계정 선택 화면만
  좁힐 뿐 우회 가능하므로 서버 검증이 아니다. 일반 Gmail 계정이나 다른 도메인 계정에는 `hd` 클레임이 없거나 다르다.
- `allowed_email_domains` 를 설정하면 `email_verified == true` 도 함께 요구한다 (`require_email_verified`, 기본 true).
- id_token 에 그룹 정보가 없다. 역할은 `roles.default` 로만 주거나, 앱 DB 에서 관리.
- Google 은 end_session_endpoint 가 없다 → 로그아웃은 로컬 세션만 삭제된다.
- 고유 식별자는 `sub` 사용 (이메일은 변경 가능).
