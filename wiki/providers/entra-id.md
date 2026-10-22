# Microsoft Entra ID (Azure AD)

상태: **초안** — 실제 연동 후 갱신 필요. 예시: `config/tenants.example.yaml` 의 `entra`.

## OIDC (권장)
- App registrations → New registration → Redirect URI(Web): `{BASE_URL}/auth/{tenant}/callback`
- Certificates & secrets → client secret (만료일 관리!)
- issuer: `https://login.microsoftonline.com/<tenant-id>/v2.0` (단일 테넌트)
- 식별자: `sub` 는 앱별로 달라짐 → 앱 간 공통 식별이 필요하면 `oid`
- 그룹: Token configuration → groups claim 추가. 값은 기본적으로 **그룹 Object ID(GUID)** → `roles.groups` 키도 GUID.
  사용자 그룹이 많으면(200+) groups 대신 overage 클레임이 와서 Graph API 조회가 필요 — App roles 사용 검토
- 이메일: `email` 이 비어있는 경우가 많아 `preferred_username` 사용 고려

## SAML
- Enterprise applications → New → Non-gallery → Single sign-on → SAML
- SP metadata 업로드 가능. Federation Metadata URL 을 `idp_metadata_url` 로
