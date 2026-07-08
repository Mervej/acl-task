# Access Control Across Microservices — Reference Implementation

A reference implementation of access control for a multi-tenant SaaS platform, proving with
working code — not a whitepaper — four things at once: per-tenant **authentication**,
**fine-grained RBAC** (permission keys resolved from roles a tenant admin can change at runtime),
**hard tenant isolation** via one physical Postgres database per tenant per service (not a shared
schema with a `tenant_id` filter), and **cross-service trust** (a calling service's identity and
the acting user's permission are both verified independently when Service A calls Service B on a
user's behalf).

Ten services sit behind a single API Gateway: **Access Control** (identity/RBAC/org units),
**User Management**, **Expense Management**, **Payroll**, and **Audit** are fully implemented
end to end (real per-tenant DBs, migrations, tests); **Reporting**, **Workflow**, **Notification**,
and **Invoice Management** are guarded stubs that prove the auth wiring without duplicating the
same pattern four more times. See the [Scope note](#scope-note) below and
`submission_docs/assumptions-and-tradeoffs.md` for exactly what's real vs. stubbed and why.

## Run locally

1. `npm install`
2. `docker-compose up -d` — starts Postgres (host port `5433`) and Redis
3. `cp .env.example .env` and set `SERVICE_API_KEY=dev-shared-service-key` (matches what the seed script uses by default), then export it into your shell: `set -a && source .env && set +a`. Nothing in this repo loads `.env` automatically — every service reads `process.env` directly — so skipping this step means everything falls back to the default `DATABASE_PORT=5432`, which doesn't match the Postgres container above.
4. Create the control-plane database and run its migration (same shell as step 3, so the exported vars are in scope):
   ```bash
   PGPASSWORD=postgres psql -h localhost -p 5433 -U postgres -c "CREATE DATABASE control_plane;"
   npx typeorm-ts-node-commonjs migration:run -d packages/access-control/src/control-plane/data-source.ts
   ```
   (run this from inside `packages/access-control` — see that migration's own notes for why)
5. `npm run dev` — starts all 9 services plus the API Gateway (same shell as steps 3-4)
6. Seed two demo tenants (after the services above are running): `npm run seed`
7. Log in: `curl -X POST http://localhost:3001/auth/login -H 'content-type: application/json' -d '{"tenantSlug":"acme","email":"admin@acme.example.com","password":"hunter22"}'`

## Run tests

- `npm test` — unit tests across every workspace
- `npx jest --config jest.config.base.js test/e2e` — end-to-end cross-service and tenant-isolation tests (requires the full local stack running, per step 5 above)

## Scope note

Reporting, Workflow, Notification, and Invoice Management are minimal stub services (guarded routes, placeholder responses, no per-tenant database) — the DB-per-tenant-per-service pattern, cross-service auth, and org-unit-scoped RBAC are proven for real by Access Control, User Management, Expense Management, Payroll, and Audit. See design spec §11a for why.

## What could be added next

Named explicitly in `submission_docs/assumptions-and-tradeoffs.md` as out of scope for this
reference implementation, roughly in priority order:

- **Wire `checkLive()` into the live request path.** The authoritative slow-path permission check
  (org-unit subtree walk, immediate revocation) exists and is unit-tested but has no caller today
  — every guarded route uses the fast, flat JWT-claim check instead.
- **Refresh-token redemption endpoint.** Refresh tokens are issued and stored hashed but nothing
  consumes them yet; access tokens can't be renewed without a fresh login.
- **A real `Reimbursement` entity/table in Payroll**, instead of `POST /reimbursements` returning
  an unpersisted acknowledgement.
- **Per-org-unit permission sets** instead of collapsing a user's multiple org-unit-scoped role
  assignments into a single `orgUnitId` claim.
- **Foreign-key integrity** between `role_permissions.permissionKey` and the control-plane
  permissions catalog, and between `OrgUnit.parentId` and its parent row.
- **Production infra concerns**: tiered tenant storage (dedicated hosts for large/regulated
  tenants), Kafka instead of Redis Streams for audit at scale, read replicas, per-tenant rate
  limiting, real secrets management (Vault/KMS) instead of env-var DB credentials, and Kubernetes
  manifests.
- **Build out the four stub services** (Reporting, Workflow, Notification, Invoice Management)
  with real per-tenant persistence, once/if their business logic is actually needed.
