# 고객사 SSO 온보딩 체크리스트

연동 착수 미팅 전에 이 문서를 고객사 IdP 담당자에게 공유한다.
**우리가 받을 것 / 우리가 줄 것** 을 한 번에 정리해야 왕복이 줄어든다.

## 0. 먼저 확인할 것

- [ ] IdP 제품과 버전 (Entra ID, Okta, ADFS, Keycloak, 국내 솔루션명 등)
- [ ] 프로토콜: OIDC 가능? 안 되면 SAML 2.0? 둘 다 아니면 벤더 방식(v2 범위, 별도 협의)
- [ ] 환경 구분: 개발 / 스테이징 / 운영 IdP 가 분리되어 있는지, 각각 따로 등록해야 하는지
- [ ] 망 구성: 우리 서버 → IdP (discovery, JWKS, token endpoint, metadata URL) **아웃바운드 통신 가능 여부**.
      폐쇄망이면 OIDC 는 token endpoint 접근이 필수라 방화벽 오픈 필요. SAML 은 metadata 를 파일로 받아 정적 설정 가능
- [ ] 사용자 브라우저 → IdP 접근 가능 여부 (VPN, 내부망 전용 IdP 인지)

## 1. OIDC 인 경우

### 우리가 받을 것
- [ ] Issuer URL (예: `https://login.microsoftonline.com/<tenant-id>/v2.0`)
- [ ] client_id
- [ ] client_secret — **메일/메신저 평문 금지**, 비밀번호 전달 채널 사용. 만료일 확인
- [ ] 사용 가능한 scope, 그룹/역할 클레임 이름과 형식 (이름? GUID? 경로?)
- [ ] 사용자 고유 식별자로 쓸 클레임 (sub / oid / 사번 클레임). **이메일은 변경될 수 있어 식별자로 비권장**
- [ ] logout(end_session_endpoint) 지원 여부

### 우리가 줄 것
- [ ] Redirect URI: `{BASE_URL}/auth/{tenant}/callback` (환경별, **한 글자도 틀리면 안 됨**: http/https, 끝 슬래시, 포트)
- [ ] Post logout redirect URI: `{BASE_URL}/`
- [ ] Grant: Authorization Code + PKCE(S256), Confidential client

## 2. SAML 인 경우

### 우리가 받을 것
- [ ] IdP metadata URL (권장) 또는 metadata XML 파일
      - 정적 설정 시: IdP Entity ID, SSO URL (HTTP-Redirect), SLO URL, 서명 인증서
- [ ] NameID 형식과 값 (persistent / email / 사번 / username)
- [ ] 속성(Attribute) 이름 목록: 이메일, 이름, 그룹/부서. ADFS 는 URI 형태 이름이 많음
- [ ] IdP 서명 인증서 **만료일과 교체(rollover) 절차**
- [ ] Assertion 암호화 요구 여부 (v1 템플릿은 미지원 — 요구 시 별도 협의)

### 우리가 줄 것
- [ ] SP metadata: `{BASE_URL}/auth/{tenant}/metadata` (URL 또는 다운로드한 XML)
      - SP Entity ID: 기본값 `{BASE_URL}/auth/{tenant}/metadata`
      - ACS URL: `{BASE_URL}/auth/{tenant}/acs` (HTTP-POST)
      - SLO URL: `{BASE_URL}/auth/{tenant}/sls` (HTTP-Redirect)
      - SP 서명 인증서 (AuthnRequest / LogoutRequest 서명용)
- [ ] 요구사항: **Assertion 서명 필수**, SHA-256 이상 (SHA-1 거부)

## 3. 공통

- [ ] 테스트 계정 최소 2개: 관리자 그룹 소속 1, 일반 1
- [ ] 그룹 → 우리 서비스 역할 매핑표 (예: `SSO-AppAdmins` → `admin`)
- [ ] 허용 사용자 범위 (전 직원? 특정 그룹만? IdP 측에서 앱 할당으로 제한하는지)
- [ ] 세션 정책: 유휴/절대 만료 요구사항, SLO 필요 여부
- [ ] 시각 동기화: 양측 서버 NTP 사용 확인 (시계 오차 허용치 기본 60초)
- [ ] 장애 시 연락처, IdP 점검 일정 공유 채널

## 4. 연동 후 확인

- [ ] 관리자/일반 계정 각각 로그인 → `/me` 에서 subject, email, groups, roles 확인
- [ ] 권한 없는 계정 `/admin` 403 확인
- [ ] 로그아웃 후 재로그인 시 IdP 비밀번호 재요구 (SLO 사용 시)
- [ ] 운영 전환 시 Redirect/ACS URL, 인증서, secret 을 운영 값으로 교체했는지
