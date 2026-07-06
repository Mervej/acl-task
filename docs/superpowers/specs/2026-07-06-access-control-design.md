# Access Control Across Microservices in a Multi-Tenant Architecture — Design Spec

**Date:** 2026-07-06
**Status:** Approved (pending user review of this document)
**Source:** `ACL.pdf` take-home assignment

## 1. Problem Statement

Design and build a reference implementation of an enterprise-grade access control system for a multi-tenant, microservices-based SaaS platform consisting of: User Management, Expense Management, Payroll, Reporting, Workflow, Notification, and Invoice Management. The platform must support authentication and authorization, fine-grained access control, tenant isolation, cross-service authorization, service-to-service communication, dynamic role/permission management, and auditability — at a scale of thousands of tenants, millions of users, and high request throughput.

## 2. Scope

This is fundamentally a systems-design exercise; the deliverable is a design doc plus a **reference implementation**, not seven production-grade business applications.

**In scope, built end-to-end:**
- API Gateway
- Access Control Service (the core subject of this assignment: identity, RBAC engine, org hierarchy, tenant registry, token issuance)
- All 7 resource services listed in the PRD, each with: real tenant-scoped DB schema, real API endpoints, and real access-control enforcement (authentication, permission checks, tenant isolation, service-to-service auth)
- Audit Service (async, event-driven)

**Explicitly out of scope / stubbed:**
- Domain-specific business logic inside each resource service (e.g. actual payroll tax calculation, actual email/SMS delivery in Notification, actual workflow execution engine). Each service has believable data models and endpoints but simplified internal logic — the goal is to prove the access control system works uniformly everywhere, not to build seven complete products.
- Tiered tenant database strategy (small tenants pooled, large tenants dedicated) — documented as a scaling consideration only (§9).
- Real secrets management for per-tenant DB credentials (uses an env/naming convention in the reference implementation; §10 notes the production alternative).
- Kubernetes deployment manifests — local docker-compose only.

## 3. Assumptions

1. Login requires an explicit tenant identifier (`tenant_slug`) alongside email/password — avoids needing a global cross-tenant email index and matches common enterprise SaaS UX (workspace-scoped login).
2. "Different database per tenant" is satisfied by separate logical Postgres databases within one Postgres server for the reference implementation; production would place large/regulated tenants on dedicated hosts (§9).
3. The permission catalog (e.g. `expense:approve`) is system-defined and identical across all tenants; only **roles** (including custom ones) and **role assignments** are tenant-specific.
4. A short (~15 min) staleness window between a role change and it taking effect for an already-issued access token is acceptable, given a bounded JWT TTL and audit visibility into what happened during that window.
5. User Management (business service, HR-style profile data) and Access Control (identity/auth) are deliberately separate services with separate data ownership, linked by `user_id` reference and synced via API call at user-creation time — a deliberate example of cross-service data-ownership boundaries, not an oversight.

## 4. High-Level Architecture

**Services (9, all NestJS + TypeORM):**

| Service | Responsibility |
|---|---|
| API Gateway | Single external entry point. Terminates TLS, does coarse JWT validation (signature/expiry only), routes to target service, forwards trusted user-context headers. |
| Access Control | Identity (login, password hashing), token issuance (JWT + refresh + API keys), RBAC engine (permissions catalog, roles, role assignments), org unit hierarchy, tenant registry, custom role management. |
| User Management | Employee/user profile data (job title, manager, hire date, org unit membership). |
| Expense Management | Expense records, categories, approval records. |
| Payroll | Payroll runs, payslip records (calculation stubbed). |
| Reporting | Report definitions and report run records (report generation stubbed). |
| Workflow | Workflow definitions and workflow instance/step records (execution engine stubbed). |
| Notification | Notification records and templates (delivery stubbed). |
| Invoice Management | Invoices and line items. |
| Audit | Consumes audit events from all services, persists and exposes a query API. |

**Cross-cutting infrastructure:** Postgres (DB-per-tenant-per-service), Redis (permission cache + audit event streams), and a shared internal package `@platform/auth-kit` (JWT verification, permission-check client, tenant-connection resolver, audit-event emitter) used by every service to avoid duplicating security logic 9 times.

**Request flow (happy path):** Client → API Gateway (authenticates) → target service (authorizes, using JWT claims / Redis cache / Access Control DB as a last resort) → resolves its tenant-specific DB via the tenant registry → executes → emits an audit event → responds.

## 5. Data Model & Multi-Tenancy

**Global control-plane database** (shared, not tenant-scoped — the only non-tenant-isolated data in the system):
- `tenants` (id, name, slug, status)
- `tenant_db_registry` (tenant_id, service_name → db connection info)
- `permissions` (system-defined catalog, e.g. `expense:approve`, `payroll:run`)

**DB-per-tenant-per-service** (everything else): each of the 8 non-Audit services owns one database per tenant; Audit owns one per tenant too.

- **Access Control's per-tenant DB:** `users`, `org_units` (tree via `parent_id`), `roles` + `role_permissions` (tenant's roles, including custom ones, referencing the global permission catalog), `role_assignments` (user_id, role_id, org_unit_id — null = tenant-wide), `api_keys`, `refresh_tokens`.
- **Each resource service's per-tenant DB:** its own domain tables (e.g. Expense → `expenses`, `approval_records`).
- **Audit's per-tenant DB:** `audit_events` (actor, service, action, resource, decision, timestamp, metadata).

**Reference implementation practicality:** all logical databases run in one Postgres container via docker-compose (~20-25 databases across 2-3 seeded tenants × 8 services + control plane) rather than one container per tenant — see §9 for the production alternative.

**Connection routing:** tenant registry lookups are cached in Redis (short TTL); each service keeps an LRU-capped in-memory map of TypeORM connection pools keyed by `tenant_id`, evicting idle tenants.

## 6. Authentication & Authorization Flow

**Login:**
1. `POST /auth/login {tenant_slug, email, password}` → Access Control resolves `tenant_slug` → `tenant_id` via the global registry, opens that tenant's DB, verifies the password hash.
2. Resolves the user's role assignments (with org-unit scope) into a flat permission set.
3. Issues a short-lived access JWT (`user_id`, `tenant_id`, `roles`, `permissions`, `org_unit_id`, ~15 min TTL) and a longer-lived refresh token (opaque, stored hashed).

**Authenticated request:**
1. API Gateway verifies the JWT signature/expiry only, forwards claims as trusted headers.
2. The target service does the fine-grained check itself: does the token's `permissions` include the required key? Is the target resource's `org_unit_id` within the token's `org_unit_id` subtree?
3. Fast path: answered from JWT claims + a Redis-cached org-unit subtree check. Slow path: `POST /authz/check` to Access Control (Redis policy cache, then tenant DB) for cases requiring a live check.
4. Every decision (allow or deny) emits an audit event.

**API-key auth** (service/machine clients) is validated directly by the target service against its own tenant's `api_keys` table — no gateway JWT involved.

## 7. Service-to-Service Security & Cross-Service Authorization

When one service calls another on a user's behalf (e.g. Expense Management → Payroll):
1. The calling service forwards the original user's JWT **and** its own service API key in a separate header, bypassing the gateway.
2. The downstream service validates the API key first (coarse "is this a legit calling service" allowlist check), then validates the JWT and runs the same fine-grained permission check it would for a direct client call. Full user context survives the hop.
3. The downstream service's audit event is tagged with `via_service` to show both who initiated the action and which service performed it.

## 8. Auditability

- Every service emits one audit event per significant action/decision to a per-tenant Redis Stream (`audit:{tenant_id}`), asynchronously — a slow/down audit path never blocks a request.
- The Audit Service consumes each tenant's stream via a consumer group (safe to run multiple instances) and persists events to that tenant's `audit_events` table.
- Audit exposes a query API, itself access-controlled (e.g. only tenant Admins can read their tenant's log).
- Known limitation: if Audit is down, events queue in the bounded Redis Stream (max-length trim policy); production at real scale would use Kafka for longer retention (§9).

## 9. Scalability & Production Considerations (documented, not built)

- **Tiered tenant storage:** pool small tenants into shared databases (schema- or row-level separated); reserve fully dedicated DB hosts for large/regulated tenants.
- **Dedicated DB hosts per tenant** (rather than logical databases on one server) for tenants with strict data-residency/compliance requirements.
- **Kafka instead of Redis Streams** for audit events at real throughput/retention requirements.
- **Read replicas** for reporting/analytics workloads to avoid impacting transactional traffic.
- **Rate limiting and quota enforcement** at the API Gateway, per tenant.
- **Secrets management** (e.g. Vault/cloud KMS) for per-tenant DB credentials, replacing the naming-convention approach used in the reference implementation.
- **Kubernetes deployment** with horizontal pod autoscaling per service, service mesh (mTLS) as a defense-in-depth alternative/complement to the API-key approach in §7.

## 10. Repository Structure & Local Deployment

npm workspaces monorepo:

```
/
├── package.json
├── docker-compose.yml           (Postgres + Redis only)
├── packages/
│   ├── auth-kit/                (shared security logic)
│   ├── gateway/
│   ├── access-control/
│   ├── user-management/
│   ├── expense-management/
│   ├── payroll/
│   ├── reporting/
│   ├── workflow/
│   ├── notification/
│   ├── invoice-management/
│   └── audit/
├── scripts/
│   ├── seed.ts                  (provisions tenant DBs, seeds 2-3 tenants)
│   └── dev.ts                   (runs all services concurrently)
└── docs/superpowers/specs/
```

`docker-compose up` starts Postgres + Redis. `npm run seed` provisions per-tenant-per-service databases and seed data. `npm run dev` runs all 9 services concurrently.

## 11a. Scope Reduction (2026-07-06, mid-build)

This is an interview take-home submission, not a production deployment — after Access Control (full RBAC), the Gateway, User Management, Expense Management, and a Payroll stub were built and verified actually booting end-to-end (proving the DB-per-tenant-per-service pattern, cross-service auth, and org-unit scoping all work), the remaining 4 resource services were intentionally reduced in scope to keep effort proportional to what an interview evaluation needs:

- **Reporting, Workflow, Notification, Invoice Management**: minimal stub endpoints only (guarded routes returning simple in-memory/placeholder responses) — no dedicated per-tenant DB schema, entities, or migrations for these 4. The DB-per-tenant-per-service pattern, cross-service auth, and RBAC enforcement are already proven for real by User Management, Expense Management, and Payroll; repeating the identical scaffold 4 more times adds no new evaluative signal.
- **Payroll** gets its full entity-backed implementation (per the original plan) since it's part of the core "prove the pattern end-to-end" flow with Expense Management.
- **Audit service** is still built for real (it's an explicitly named requirement of the assignment), but implemented directly rather than via heavy multi-agent orchestration.

## 11. Testing Strategy

- **Unit tests:** permission-evaluation logic (org-unit subtree matching, role→permission resolution), edge cases (deactivated user, expired token, role removed mid-session, org unit deleted while users still assigned).
- **Integration tests (Access Control):** login → token → role assignment → permission check round-trip against a real test tenant DB.
- **Cross-service integration test:** Expense Management → Payroll call, proving both the service API-key check and the forwarded-user-permission check independently reject when either is missing.
- **Tenant isolation test:** a user/token from Tenant A can never read/write Tenant B's data, even via a crafted request (e.g. altered resource ID) — the core promise of the system.
