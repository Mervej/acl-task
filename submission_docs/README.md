# Submission Docs — Access Control Across Microservices

This is the design/documentation package for the take-home assignment: *"design and build a
reference implementation of an enterprise-grade access control system"* for a multi-tenant,
microservices SaaS platform.

## Contents

| Doc | What's in it |
| --- | --- |
| [design-document.md](./design-document.md) | Goals, multi-tenancy model, auth/authz model end-to-end, service inventory, key decisions |
| [architecture-diagram.md](./architecture-diagram.md) | System topology — services, shared lib, data stores, request flow |
| [sequence-diagrams.md](./sequence-diagrams.md) | Login, permission-checked request, cross-service expense→payroll call, tenant provisioning, audit consumption |
| [schema-diagram.md](./schema-diagram.md) | ER diagrams for the control-plane DB and every per-tenant service DB |
| [api-examples.md](./api-examples.md) | curl request/response examples for every real (non-stub) endpoint, including a 403 and a service-to-service call |
| [assumptions-and-tradeoffs.md](./assumptions-and-tradeoffs.md) | Explicit, honest list of what was simplified, stubbed, or deliberately left out, and why |

## What's actually built vs. stubbed

**Fully implemented, end-to-end, with real per-tenant persistence:** Access Control (identity,
JWT issuance, RBAC engine, org units, tenant registry — the actual subject of the assignment),
User Management, Expense Management, Payroll, and Audit (the event sink that consumes and serves
every service's audit trail). These five together exercise every piece of the access-control
pattern for real: login, permission checks, tenant isolation via a dedicated database per
tenant per service, a genuine cross-service call (expense approval → payroll reimbursement) with
two independent auth checks, and asynchronous audit logging.

**Intentionally reduced to guarded stubs:** Reporting, Workflow, Notification, and Invoice
Management. Each has real `AuthGuard`/`PermissionGuard` wiring, real `@RequirePermission`
decorators, and emits real audit events — but no database, entities, or business logic behind
the endpoints. This was a deliberate scope call, not an oversight: the DB-per-tenant-per-service
pattern, cross-service auth, and RBAC were already proven for real by the five services above,
so building the identical pattern four more times would have added copy-paste hours without new
evaluative signal. See [assumptions-and-tradeoffs.md](./assumptions-and-tradeoffs.md) for the
full reasoning and every other scope decision made along the way.

This is a take-home submission, scoped for a systems-design interview exercise rather than a
production system — the tradeoffs doc is explicit about where production hardening was
deliberately skipped and what would be done differently at scale.
