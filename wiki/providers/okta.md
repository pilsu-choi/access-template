# Okta

상태: **초안** — 실제 연동 후 갱신 필요.

## OIDC
- Applications → Create App Integration → OIDC / Web Application
- Sign-in redirect URI: `{BASE_URL}/auth/{tenant}/callback`, Sign-out redirect URI: `{BASE_URL}/`
- issuer: Org authorization server `https://<org>.okta.com` 또는 Custom AS `https://<org>.okta.com/oauth2/default`
  (어느 쪽인지에 따라 discovery 가 다름 — discovery 의 `issuer` 값을 그대로 사용)
- 그룹: authorization server 의 claims 에 `groups` 추가 + scope 에 `groups` (설정에 따라)

## SAML
- Create App Integration → SAML 2.0, Single sign-on URL = ACS, Audience URI = SP Entity ID
- Attribute statements 로 email 등 매핑, Group attribute statements 로 groups
- Metadata URL → `idp_metadata_url`
