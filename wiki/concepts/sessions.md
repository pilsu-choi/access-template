# 세션과 쿠키

| 쿠키 | 값 | 속성 | 수명 |
|---|---|---|---|
| `sso_pending` | 불투명 키 → 서버 pending store | HttpOnly, Path=/auth, SameSite=None+Secure(운영) / Lax(dev http) | 10분, 1회용 |
| `sso_session` | 불투명 session id → 서버 SessionStore | HttpOnly, Path=/, SameSite=Lax, Secure(운영) | 유휴 30분(슬라이딩), 절대 8시간 |

- 쿠키에는 토큰/클레임을 담지 않는다. id_token, NameID/SessionIndex 같은 로그아웃 힌트는 서버 세션에만.
- 로그인 성공 시 기존 세션 삭제 후 새 id 발급 (session fixation 방지).
- `POST /logout` 은 SameSite=Lax 쿠키라 cross-site POST 로는 세션이 실리지 않아 CSRF 로 로그아웃시킬 수 없다.
- 저장소는 `TTLStore` 인터페이스. 기본 `InMemoryTTLStore` 는 단일 프로세스 전용 —
  멀티 워커/멀티 인스턴스는 Redis 구현으로 교체 (`get/set/pop/delete/add_if_absent`, `add_if_absent` 는 원자적이어야 replay 차단이 유효).
- 설정: `SSO_SESSION_IDLE_SECONDS`, `SSO_SESSION_ABSOLUTE_SECONDS`, `SSO_PENDING_LOGIN_SECONDS`.
