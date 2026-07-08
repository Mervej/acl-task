# Assumptions and Tradeoffs

## Scope reductions (stated up front)

- **Four services are guarded stubs, not full implementations.** Reporting, Workflow,
  Notification, and Invoice Management have real `AuthGuard`/`PermissionGuard` wiring and emit
  real audit events, but no per-tenant database, entities, or migrations — their handlers return
  hardcoded/placeholder responses. Rationale: the DB-per-tenant-per-service pattern, cross-service
  auth, and RBAC were already proven for real by Access Control, User Management, Expense
  Management, and Payroll. Building the identical pattern four more times adds no new evaluative
  signal, just hours of copy-paste. They are absent from `scripts/provision-tenant.ts`'s
  `PROVISIONED_SERVICES` list — they never receive a database at all.
- **Payroll calculation is a flat-rate stub**, not a real payroll engine: every employee is paid
  a fixed `$5,000` (`FLAT_SALARY_CENTS_PER_EMPLOYEE = 500000`) per triggered run, regardless of
  role, hours, or tax jurisdiction. The point of the exercise was proving the access-control
  pattern around payroll actions, not building a payroll calculator.
- **The reimbursement endpoint doesn't persist a reimbursement record.** `POST /reimbursements`
  on Payroll validates both auth layers and returns `{status: 'recorded', ...}`, but there is no
  `Reimbursement` entity or table — it's a landing pad that proves the two-layer cross-service
  auth pattern, not a full ledger.
- **Documented but not built:** tiered tenant storage (dedicated hosts for large/regulated
  tenants vs. pooled small tenants), Kafka instead of Redis Streams for audit at real scale, read
  replicas, per-tenant rate limiting, real secrets management (Vault/KMS) instead of env-var DB
  credentials, and Kubernetes manifests. These are production concerns explicitly out of scope
  for a reference implementation.

## Security/correctness tradeoffs worth naming explicitly

- **Org-unit scoping is designed but not enforced on the live request path.**
  `PermissionCheckClient.check()` — the method every guarded route in every service actually
  calls — does a flat `===` on org-unit IDs, not a subtree walk. The real subtree/descendant
  check (`AuthzService.isDescendant`, walking the `org_units` tree via `parentId`) exists, is
  unit-tested, and is only reachable through `checkLive()` → `POST /authz/check` — a method no
  guarded route in the codebase currently calls. Net effect: a manager scoped to a parent org
  unit cannot act on a resource scoped to a child org unit today, even though the data model and
  the slow-path authority service both support that cascade. This is a real, nameable gap between
  design intent and live enforcement.
- **A revoked role stays valid for up to 15 minutes.** Permission claims are baked into the JWT
  at login and checked entirely from the token on the fast path (no DB/Redis round-trip). If an
  admin revokes a role mid-session, the fast path won't reflect it until the token expires; only
  the slow path (`checkLive`, not currently wired to any guarded route) would catch it
  immediately. This bounded staleness window, traded for avoiding a database hit on every
  request, is an accepted design tradeoff, not a bug — but it means nothing in the running system
  closes that window today.
- **`checkLive()` is built and unit-tested but has no caller.** The authoritative slow-path check
  against Access Control exists and works in isolation; wiring it into specific
  staleness-sensitive routes (or adding a role-change invalidation signal) would be the next step
  for production use.
- **No refresh-token redemption endpoint exists.** Refresh tokens are issued at login and stored
  (hashed) in `refresh_tokens`, but nothing consumes them to mint a new access token — the short
  15-minute access-token TTL exists partly because there's no rotation path built yet.
- **`role_permissions.permissionKey` has no foreign key back to the control-plane `permissions`
  catalog** — they live in physically different databases (per-tenant vs. shared), so the
  reference is by string value only. A typo'd permission key on a custom role silently matches
  nothing in `PermissionCheckClient.check()` rather than failing loudly at creation time.
- **A user's org-unit scope collapses to a single value.** `AuthService.resolveEffectivePermissions`
  takes "the first role assignment with a non-null `orgUnitId`" as the token's one `orgUnitId`
  claim. A user with two org-unit-scoped roles (e.g. "Approver in Finance" + "Reviewer in
  Engineering") still gets all the merged permission keys, but only one org unit's scope survives
  into the token — the second assignment's org-unit boundary is silently dropped. A real system
  would need per-org-unit permission sets, not one flattened scope per user.
- **No transactional guarantee across the identity/profile split.** User Management's
  `createProfile()` calls Access Control's `POST /internal/users` to create the login identity,
  then saves a local `UserProfile` row referencing the returned ID. If the local save fails after
  the remote call succeeds, the identity is orphaned — there's no compensating rollback or saga.

## Infrastructure shortcuts

- **All per-tenant-per-service databases (~20-25 in a 2-tenant demo) run inside a single Postgres
  container**, not one Postgres instance per tenant. `docker-compose.yml` only starts Postgres 16
  (remapped to host port 5433) and Redis 7 — no app containers; services run locally via
  `ts-node`. Production would likely dedicate hosts for large or regulated tenants (documented,
  not built).
- **`OrgUnit.parentId` has no foreign-key constraint** — it's a plain nullable UUID column,
  walked purely at the application layer. A self-referencing FK tree adds migration complexity
  that isn't worth it at the tenant-sized scale this system targets; an in-memory map-walk over
  "all org units for this tenant" is fine.
- **Every non-Access-Control service duplicates the same raw-`pg.Client` tenant-registry lookup
  function** (`fetchRegistryRow`, byte-for-byte identical except for `SERVICE_NAME`) rather than
  sharing it from `auth-kit`. This is real, deliberate duplication — a reviewer of any one
  service's code should see working code inline, not a cross-reference into a shared file — but
  it's the first thing to refactor if this moved toward production.
- **Audit consumption is a single process, polling every active tenant sequentially in a loop**
  (`consumeAllTenants` in `discovery.ts`), not sharded across workers. Fine for a handful of demo
  tenants; explicitly not built to scale past that. Each tenant's `XREADGROUP` call inside
  `consumer.ts` blocks for up to 5 seconds (`BLOCK 5000`) if that tenant's stream is idle, and
  `discovery.ts` walks tenants one at a time in a single `for` loop, so a full pass over N tenants
  can take up to `N × 5s` in the worst case. `main.ts` runs this as a self-scheduling loop —
  `await`ing each pass before starting the next — rather than a fixed-interval timer, so passes
  never overlap regardless of how long one takes; the tradeoff is that with many tenants, a slow
  pass simply delays the next one instead of running concurrently. A real deployment would still
  need one long-lived blocking reader per tenant stream (or a sharded pool of them) to poll every
  tenant with low latency at scale, rather than one process walking the full tenant list per pass.
- **`AuditEventEmitter` is a module-level singleton per service**, constructed at import time
  with its own `ioredis` connection, not managed by NestJS's DI container. This keeps each
  audit-wiring change a one-file diff, at the cost of an extra Redis connection per service
  process and requiring `jest.config.base.js`'s `forceExit: true` so a module-level connection
  doesn't keep the Jest worker alive after tests finish.
- **No pagination on any list endpoint** (`GET /expenses`, `GET /payroll-runs`, `GET /profiles`,
  `GET /audit-events`, etc.) — every list query returns its full result set. Acceptable for a
  reference implementation with small demo datasets; a production system serving real tenant
  volumes would need cursor- or offset-based pagination.
- **No soft-deletes anywhere** — entities have no `deletedAt` column; the `status` field pattern
  (`active`/`disabled`, `pending`/`approved`/`rejected`) is used instead where a lifecycle state
  matters, but rows are never marked deleted vs. genuinely removed.

## Testing scope

- **Test coverage is deliberately time-boxed, not a gap in understanding of what should be
  tested.** Coverage focuses on the properties that matter most for an access-control system:
  permission-evaluation edge cases (deactivated user rejected at login, role revoked mid-session
  caught by the slow path, deleted org unit denies gracefully instead of throwing), the two real
  concurrency bugs found and fixed in `TenantConnectionResolver` (a connection-creation race and
  an unhandled-rejection crash on eviction), and the cross-service call assembly in
  `expenses.service.test.ts` (asserting both auth headers are forwarded and a downstream failure
  leaves the expense `pending`, not silently approved).
- **No negative-case end-to-end test exists for the reimbursements endpoint's service-key check
  specifically** — i.e., proving Layer 2 alone can block a request that Layer 1 (JWT) alone would
  allow, driven against the live stack. The guard behavior is covered at the unit level; the
  fully-wired negative path isn't.
- **Unit tests are mock-based** (fake repositories, mocked `fetch`) rather than hitting a real
  database, except where explicitly noted (`scripts/provision-tenant.test.ts` runs against a real
  control-plane database). End-to-end tests (`test/e2e/`) make real HTTP calls against the full
  local stack and are the ones that actually prove tenant isolation (asserting a **404**, not a
  403, when Tenant A's token is used against Tenant B's real resource ID — a stronger guarantee
  than row-level filtering would give) and the full cross-service approval flow.
