# Access Control Across Microservices — Reference Implementation

See `docs/superpowers/specs/2026-07-06-access-control-design.md` for the full design (including the §11a interview-scope reduction) and `docs/superpowers/plans/2026-07-06-access-control-implementation.md` for how it was built.

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
