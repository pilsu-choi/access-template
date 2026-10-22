# ADFS

상태: **초안** — 실제 연동 후 갱신 필요. 금융권/공공 고객사에서 자주 만남.

## SAML (일반적)
- Relying Party Trust 추가 → SP metadata URL 또는 파일 import
- Claim Issuance Policy: LDAP Attributes → E-Mail, Name, Token-Groups 등 송출 규칙
- NameID 는 별도 Transform 규칙 필요 (Name ID 형식 지정)
- IdP metadata: `https://<adfs-host>/FederationMetadata/2007-06/FederationMetadata.xml`
- 속성 이름이 URI 형식: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` 등 →
  `claims` 매핑에 URI 그대로 사용 (`tenants.example.yaml` 의 `customer-saml` 참고)
- 서명 알고리즘 기본값이 SHA-256 인지 확인 (구형 설정은 SHA-1 → 템플릿이 거부함)
- 토큰 서명 인증서 자동 롤오버 시 metadata URL 사용을 권장

## OIDC
ADFS 2016+ 는 OIDC 지원 (Application Group → Server application). 사내 정책상 SAML 만 허용하는 경우가 많음.
