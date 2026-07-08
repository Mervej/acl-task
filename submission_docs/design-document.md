# Design Document — Access Control Across Microservices

## 1. Goals

Build a reference implementation of access control for a multi-tenant SaaS platform, proving —
with working code, not a whitepaper — four things at once:

1. **Authentication**: users log in per-tenant and receive a signed, time-bound credential.
2. **Fine-grained authorization**: every mutating or sensitive read is gated by an explicit
   permission key, resolved from a role/permission model that a tenant admin can change at
   runtime (create roles, attach permissions, assign roles to users) without a code deploy.
3. **Hard tenant isolation**: one tenant can never read or write another tenant's data, and the
   isolation guarantee should not rest solely on every developer remembering a `WHERE tenant_id`
   clause.
4. **Cross-service trust**: when Service A needs to call Service B on behalf of a user (not just
   serve a client directly), both the calling _service's_ identity and the acting _user's_
   permission must be verified independently.
5. **Auditability**: every access decision (allow or deny) is recorded, asynchronously, without
   blocking the request path.

## 2. Service inventory

| Service            | Port | Status          | Owns                                                                                                                 |
| ------------------ | ---- | --------------- | -------------------------------------------------------------------------------------------------------------------- |
| Gateway            | 3000 | Implemented     | Single external entry point; coarse JWT validation; routes `/api/<service>/...` to the target service by path prefix |
| Access Control     | 3001 | **Implemented** | Identity, login, JWT/refresh-token/API-key issuance, RBAC engine, org units, tenant registry                         |
| User Management    | 3002 | **Implemented** | Employee profile data (job title, manager, org unit), provisions identities via Access Control                       |
| Expense Management | 3003 | **Implemented** | Expenses and approvals; approval triggers a cross-service call to Payroll                                            |
| Payroll            | 3004 | **Implemented** | Payroll runs, payslips, reimbursement recording                                                                      |
| Audit              | 3009 | **Implemented** | Consumes every service's audit events from Redis Streams, persists them per-tenant, exposes a query API              |
| Reporting          | 3005 | Stub            | Report definitions/runs — guarded routes, no persistence                                                             |
| Workflow           | 3006 | Stub            | Workflow instances — guarded routes, no persistence                                                                  |
| Notification       | 3007 | Stub            | Notifications — guarded routes, no persistence                                                                       |
| Invoice Management | 3008 | Stub            | Invoices — guarded routes, no persistence                                                                            |

Plus `@platform/auth-kit`, a shared internal package imported by all 10 services so JWT
verification, permission checking, tenant-DB connection routing, and audit emission are written
and tested once, never duplicated.

## 3. Multi-tenancy model

**Two tiers of database:**

1. **Control-plane database** (one shared instance, the only non-tenant-isolated data in the
   system): `tenants` (id, name, slug, status), `tenant_db_registry` (which physical
   host/port/database/credentials serve a given `tenantId` + `serviceName` pair), and
   `permissions` (the global, system-defined permission catalog — identical across every tenant;
   seeded once with 16 keys such as `expense:approve`, `payroll:run`, `role:manage`).
2. **One Postgres database per tenant, per service.** Not a shared table with a `tenant_id`
   filter column — a physically separate logical database (e.g. `expense_management_acme`,
   `payroll_globex`). `scripts/provision-tenant.ts` creates the database, registers it in
   `tenant_db_registry`, and runs that service's migrations against it, for every
   (tenant, service) pair.

**Why physical isolation instead of row-level filtering:** a forgotten `WHERE tenant_id = ?`
clause in a shared-schema design is a live cross-tenant data breach that compiles and runs fine.
With DB-per-tenant-per-service, a missing tenant-scope check would need to somehow connect to a
database the process was never even told about — the failure mode changes from "silent data
leak" to "connection error." This is provable, not just asserted: a tenant-isolation test
confirms that a valid token from Tenant A, holding the _real_ database ID of a resource created
by Tenant B, gets a 404 (not a 403) — because Tenant A's connection is pointed at a different
physical database where that row simply doesn't exist.

**Connection routing** is handled by `auth-kit`'s `TenantConnectionResolver`, shared by every
service: an in-memory, LRU-capped (default 100) map of TypeORM `DataSource`s keyed by
`tenantId`, with an `inFlight` map to de-dupe concurrent connection creation for the same
uncached tenant (fixes a real connection-leak bug found during the build — two simultaneous
first-requests for a tenant would otherwise each open their own `DataSource` and orphan one).
Looking up _which_ physical database to connect to is delegated to a per-service
`lookupTenantDb` callback, which reads `tenant_db_registry` (directly for Access Control, which
already holds a live control-plane connection; via a fresh short-lived `pg` client for every
other service, cached in Redis for 60s to avoid a connection-per-request).

**Practical shortcut, stated explicitly:** all ~20-25 of these logical databases run inside a
single Postgres container for this reference implementation, rather than one Postgres instance
per tenant. See [assumptions-and-tradeoffs.md](./assumptions-and-tradeoffs.md).

## 4. Authentication & authorization model, end to end

**Login** (`POST /auth/login {tenantSlug, email, password}`):

1. Resolve `tenantSlug` → `tenantId` via the control-plane `tenants` table (must be
   `status: 'active'`).
2. Open that tenant's Access Control database, find the `User` filtered on
   `tenantId + email + status: 'active'` in a single query — a disabled user is excluded by the
   query itself, not a separate post-lookup check.
3. Verify the password hash.
4. Resolve **effective permissions**: load all of the user's `RoleAssignment` rows, fetch those
   `Role`s and their `RolePermission`s, flatten to a deduped permission-key set. The org-unit
   scope carried into the token is the first assignment with a non-null `orgUnitId` (a
   single-scope-per-user simplification — see tradeoffs doc).
5. Issue a short-lived (15 min) **access JWT** with claims `sub, tenantId, roles, permissions,
orgUnitId, iat, exp` (HS256, one shared secret used to both sign and verify — no per-service
   asymmetric keys), plus an opaque refresh token (32 random bytes, only its hash persisted,
   30-day expiry — no `/auth/refresh` endpoint exists yet to redeem it).
6. Emit an audit event (`auth.login`, allow or deny) on both success and failure.

**Authenticated request — two guards, composed:**

- `AuthGuard` verifies the JWT signature and expiry, then stashes the decoded claims on the
  request as `request.authContext`. This is authentication only — no permission is checked here.
- `PermissionGuard` reads an `@RequirePermission('resource:action')` decorator off the route
  handler (via `Reflector`) and calls `PermissionCheckClient.check()`.

**Fast path vs. slow path — the central design tradeoff:**

- **Fast path** (`PermissionCheckClient.check()`, used by every guarded route in the system):
  pure, synchronous, zero network calls — checks `claims.permissions.includes(permission)` plus
  an org-unit comparison, entirely from the JWT already on the request. No database or Redis
  round-trip on the common path.
- **Slow path** (`PermissionCheckClient.checkLive()` → `POST /authz/check` on Access Control):
  re-queries the tenant database fresh on every call, so a role change or revocation is reflected
  immediately rather than waiting for the token to expire. `AuthzService.evaluate()` on the
  receiving end also performs a genuine org-unit **subtree** check (walking the `org_units` tree
  via `parentId`), not just an exact match.
- **Accepted tradeoff:** a role revoked mid-session stays valid on the fast path until the
  15-minute token naturally expires. This bounded staleness window, traded for not hitting a
  database on every request, is a deliberate design decision — see the tradeoffs doc for the
  precise gap between what's designed and what's actually enforced today (the fast path only ever
  does an _exact_ org-unit match, never the subtree walk the slow path supports).

**Service-to-service (machine) auth** is a separate lane entirely: an `x-service-api-key` header,
hashed and compared against a tenant-scoped `api_keys` table, with no JWT or gateway involved.
This is the mechanism behind every cross-service call in the system.

**The Gateway's role is deliberately narrow.** It does coarse JWT validation (signature + expiry)
and nothing else, then forwards the original bearer token unchanged to the target service. It
injects no trusted internal headers — every downstream service independently re-verifies the
full JWT itself. A compromised or buggy gateway cannot silently grant access downstream, because
downstream never trusts it blindly.

## 5. Cross-service authorization — the worked example

A user approves an expense; Expense Management needs Payroll to record the reimbursement.
Expense Management is acting _on behalf of a user_ while calling _another service_, and Payroll
needs to verify both facts independently:

1. The user (holding `expense:approve`) calls `POST /expenses/:id/approve` on Expense Management.
   Guarded normally: `AuthGuard` + `PermissionGuard`.
2. `ExpensesService.approve()` calls `POST {PAYROLL_BASE_URL}/reimbursements`, forwarding the same
   user's original `Authorization: Bearer <JWT>` header unchanged, plus Expense Management's own
   service API key as a separate `x-service-api-key` header.
3. Payroll's `reimbursements.controller.ts` runs two independent checks:
   - **Layer 1 (user identity)**: the normal `AuthGuard` + `PermissionGuard` chain validates the
     forwarded JWT and confirms the _original user_ has `payroll:run`.
   - **Layer 2 (service identity)**: the handler separately reads `x-service-api-key` — missing
     or invalid → 401, independent of whether layer 1 passed.
4. Only once both pass does Payroll emit an audit event tagged `viaService: 'expense-management'`
   — the audit trail records both who initiated the action and which service actually performed
   it.
5. If Payroll's response is not OK, the expense **stays `pending`**, never optimistically flipped
   to `approved` — a failure in the downstream call is not swallowed.

**Why both checks, not just one:** the JWT alone doesn't prove the _calling service_ is
legitimate (a compromised third-party service could replay a stolen user token). The API key
alone doesn't prove the _specific user_ has permission for this action, and would lose the
original actor's identity from the audit trail.

## 6. Auditability

Every service constructs its own `AuditEventEmitter` (backed by `ioredis`) and calls `.emit()` on
every access decision — logins, permission checks, resource mutations. Each event is written to
a per-tenant Redis Stream (`XADD audit:<tenantId>`). The Audit service polls the control-plane
`tenants` table every 2 seconds, discovers active tenants, and consumes each tenant's stream via
a consumer group, persisting entries into that tenant's own `audit_events` table and exposing
`GET /audit-events?service=&decision=` to query them back.

Audit emission is fire-and-forget from the caller's perspective — it never blocks or fails the
request that triggered it.
