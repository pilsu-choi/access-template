# 접근 제어 (사용자 · 조직 · 역할)

인증(`auth/`)이 "누구인가"를 `Identity` 로 정규화하면, 접근 제어(`rbac/`)는 "무엇을, 어디서 할 수 있나"를 판정한다.
`rbac/` 는 `auth/` 를 import 하지 않는다. `user_id` · `roles` · `orgs` 만 있으면 `Principal` 로 쓸 수 있다.

```
IdP 그룹 ──(tenants.yaml roles.groups)──▶ 역할 ──(rbac.yaml roles)──▶ 권한
IdP 조직 클레임 / OrgDirectory ──────────▶ 사용자 소속 조직 ──▶ 역할의 적용 범위
앱에서 부여한 Grant (역할 or 권한 + 조직 범위) ─────────────────▶ 추가 권한
```

## 개념

| 개념 | 설명 | 어디에 |
|---|---|---|
| 권한 | `resource:action` (`report:read`). 와일드카드는 `resource:*`, `*` 만 (`*:read` 불가) | `rbac.yaml` `permissions` (카탈로그) |
| 역할 | 권한 묶음. `inherits` 로 상속 | `rbac.yaml` `roles` |
| 조직 | 트리 (`parent`). 상위 조직 범위는 하위 조직을 포함할 수 있다 | `rbac.yaml` `orgs` 또는 `OrgDirectory` 구현 |
| 소속 | 사용자 → 조직 (복수 가능, 겸직) | IdP 클레임(`claims.org`) 우선, 없으면 `OrgDirectory.memberships` |
| Grant | 앱이 사용자에게 부여한 역할 또는 단일 권한 + 범위(`Scope(org, subtree)`) | `GrantRepository` (seed: `rbac.yaml` `grants`) |
| 조건 | `when: owner` 처럼 리소스를 봐야 하는 규칙. 코드에서 등록 | `PolicyAuthorizer(conditions=...)` |
| 리소스 | `Resource(type, id, org, owner, attrs)` | 앱 코드가 DB 행에서 생성 |

## 권한이 생기는 경로

1. **IdP 역할** — `Identity.roles`. 범위는 역할의 `idp_scope`:
   - `global`: 전사
   - `member`: 자기 소속 조직만
   - `member_subtree`: 자기 소속 조직 + 하위 조직
2. **앱 Grant** — `Grant(user_id, role=... | permission=..., scope=Scope("sales", subtree=True))`.
   `Scope()` (org 없음) 는 전사. 역할을 Grant 로 주면 `idp_scope` 는 무시되고 Grant 의 범위를 쓴다.
   Grant 는 요청마다 조회하므로 재로그인 없이 바로 반영된다.

`idp_scope` 가 `member*` 인 역할인데 사용자 소속 조직이 없으면 그 역할로는 아무 리소스에도 접근할 수 없다.

## 판정 규칙

- **기본 거부.** 매칭되는 규칙이 없으면 거부. 정책에 없는 IdP 역할은 아무 권한도 주지 않는다.
- 리소스 없이 `check(user, "report:read")` → "어딘가에서든 이 권한이 있는가" (라우트 수준 검사).
- 리소스가 있으면 범위 확인: 전사 범위는 항상 통과, 조직 범위는 `resource.org` 가 그 조직(또는 `subtree` 면 하위)일 때만.
  `org` 가 없는 리소스는 전사 범위로만 접근 가능.
- 조건부 규칙(`when`)은 **리소스가 있을 때만** 평가한다. 라우트 수준 검사(`require_permission`)는 조건부 권한으로는 통과하지 않는다.
- 조건은 범위를 우회하지 않는다 (owner 여도 범위 밖 조직의 리소스는 거부).

## 앱 코드에서

```python
from access_template.app import Access, get_access, require_permission
from access_template.rbac.base import Resource


# 라우트 수준
@app.get("/reports")
async def reports(user: Annotated[Identity, Depends(require_permission("report:read"))]): ...


# 리소스 수준
@app.patch("/documents/{doc_id}")
async def edit(doc_id: str, access: Annotated[Access, Depends(get_access)]):
    row = repo.get(doc_id)
    access.require("document:edit", Resource("document", row.id, org=row.org_id, owner=row.author_id))
    ...


# 목록 필터 — 조직 범위를 쿼리 조건으로
vis = access.visible("document:read")
q = select(Document) if vis.all else select(Document).where(Document.org_id.in_(vis.orgs))
# vis.conditional 이면 조건부 규칙(owner 등)으로만 보이는 행이 더 있을 수 있다 → 별도 쿼리 + access.can()
```

조건 추가:

```python
def same_branch(p: Principal, r: Resource) -> bool:
    return r.attrs.get("branch") in p.orgs


authorizer = build_authorizer(policy, conditions={"same_branch": same_branch})
# rbac.yaml: - { permission: loan:approve, when: same_branch }
```

## 감사 로그

`check()` 마다 `AuditEvent(user_id, permission, resource, allowed, reason)` 를 `AuditSink` 로 보낸다.
기본 `LoggingAuditSink` 는 `access_template.audit` 로거에 한 줄씩 남긴다:

```
authz allow user=kc-oidc:ed64… permission=report:read resource=- reason=role:admin:*@*
authz deny user=kc-saml:bob  permission=document:read resource=document:d3 reason=no matching grant
```

이메일·이름·토큰은 넣지 않는다 (`user_id` 만). 금융권 감사 요건이 있으면 DB/SIEM 으로 보내는 `AuditSink` 를 구현해 교체한다.

## 시작 시 검증

`rbac.yaml` 은 로드 시 검증되고, 실패하면 앱이 뜨지 않는다:
상속/조직 트리 순환, 없는 역할·조직 참조, 권한 형식 오류, 카탈로그에 없는 권한(오타),
등록되지 않은 조건, `tenants.yaml` 이 매핑하는 역할이 `rbac.yaml` 에 없는 경우.

## 교체 지점

| 인터페이스 | 기본 구현 | 운영에서 |
|---|---|---|
| `OrgDirectory` | `InMemoryOrgDirectory` (rbac.yaml `orgs`/`members`) | 앱 DB, 인사 시스템 연동 |
| `GrantRepository` | `InMemoryGrantRepository` (단일 프로세스) | 앱 DB (+ 부여 이력) |
| `AuditSink` | `LoggingAuditSink` | DB / SIEM |
| `Authorizer` | `PolicyAuthorizer` | 고객사 EAM/IAM, OpenFGA·Cerbos 등 외부 PDP 어댑터 |

## 아직 없는 것

명시적 deny 규칙, 테넌트별 정책 오버라이드, 관리 UI, SQL 구현체.
