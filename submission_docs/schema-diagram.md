# Schema Diagrams

Every entity below is taken directly from the TypeORM entity definitions in the codebase. Column
names match the actual `@Column()` declarations.

## Control-plane database (one shared instance, all tenants)

```mermaid
erDiagram
    TENANTS {
        uuid id PK
        varchar name
        varchar slug UK
        varchar status "active | suspended"
    }
    TENANT_DB_REGISTRY {
        uuid id PK
        uuid tenantId FK "logical FK to tenants.id"
        varchar serviceName
        varchar host
        int port
        varchar database
        varchar username
        varchar password
    }
    PERMISSIONS {
        uuid id PK
        varchar key UK "e.g. expense:approve, payroll:run"
        varchar description
    }

    TENANTS ||--o{ TENANT_DB_REGISTRY : "one row per service the tenant is provisioned in"
```

`PERMISSIONS` is a global catalog, identical for every tenant, seeded once by migration (16 keys:
`user:manage`, `expense:create/approve/read`, `payroll:run/read`, `report:create/read`,
`workflow:create/advance`, `notification:send/read`, `invoice:create/read`, `role:manage`,
`audit:read`). There is **no foreign key** from a tenant DB's `role_permissions.permissionKey`
back to this table — they live in physically different databases, so the reference is by string
value only.

## Access Control — per-tenant database

```mermaid
erDiagram
    USERS {
        uuid id PK
        uuid tenantId
        varchar email "unique with tenantId"
        varchar passwordHash
        varchar status "active | disabled"
    }
    ORG_UNITS {
        uuid id PK
        uuid tenantId
        varchar name
        uuid parentId FK "nullable, self-referencing, no DB FK constraint — walked in app code"
    }
    ROLES {
        uuid id PK
        uuid tenantId
        varchar name
        varchar description
        boolean isSystemRole
    }
    ROLE_PERMISSIONS {
        uuid id PK
        uuid roleId FK
        varchar permissionKey "string reference to control-plane permissions.key, no FK"
    }
    ROLE_ASSIGNMENTS {
        uuid id PK
        uuid tenantId
        uuid userId FK
        uuid roleId FK
        uuid orgUnitId FK "nullable — null means tenant-wide"
    }
    API_KEYS {
        uuid id PK
        uuid tenantId
        varchar ownerService
        varchar keyHash
        timestamptz revokedAt "nullable"
    }
    REFRESH_TOKENS {
        uuid id PK
        uuid tenantId
        uuid userId FK
        varchar tokenHash
        timestamptz expiresAt
        timestamptz revokedAt "nullable"
    }

    USERS ||--o{ ROLE_ASSIGNMENTS : "assigned via"
    ROLES ||--o{ ROLE_ASSIGNMENTS : "granted by"
    ROLES ||--o{ ROLE_PERMISSIONS : "has"
    USERS ||--o{ REFRESH_TOKENS : "issued to"
    ORG_UNITS ||--o{ ORG_UNITS : "parentId (tree, app-level walk)"
    ORG_UNITS ||--o{ ROLE_ASSIGNMENTS : "optionally scopes"
```

## User Management — per-tenant database

```mermaid
erDiagram
    USER_PROFILES {
        uuid id PK
        uuid tenantId
        uuid userId FK "identity provisioned via Access Control's /internal/users"
        varchar fullName
        varchar jobTitle
        uuid managerId "nullable"
        uuid orgUnitId "nullable, no cross-DB FK to Access Control's org_units"
        date hireDate
    }
```

## Expense Management — per-tenant database

```mermaid
erDiagram
    EXPENSES {
        uuid id PK
        uuid tenantId
        uuid orgUnitId "nullable"
        uuid createdByUserId
        int amountCents
        varchar description
        varchar status "pending | approved | rejected"
    }
```

## Payroll — per-tenant database

```mermaid
erDiagram
    PAYROLL_RUNS {
        uuid id PK
        uuid tenantId
        uuid orgUnitId "nullable"
        uuid triggeredByUserId
        varchar status "pending | completed"
        int totalAmountCents
    }
    PAYSLIPS {
        uuid id PK
        uuid tenantId
        uuid payrollRunId FK
        uuid employeeUserId
        int amountCents
    }

    PAYROLL_RUNS ||--o{ PAYSLIPS : "generates one per employee"
```

## Audit — per-tenant database

```mermaid
erDiagram
    AUDIT_EVENTS {
        uuid id PK
        uuid tenantId
        uuid actorUserId "nullable — null for machine-initiated actions"
        varchar service "which service emitted the event"
        varchar action "e.g. auth.login, expense.approve, authz.check:payroll:run"
        varchar resourceType
        varchar resourceId "nullable"
        varchar decision "allow | deny"
        varchar viaService "nullable — set when a service acted on another's behalf"
        text metadata "nullable, JSON-stringified"
        timestamptz occurredAt
    }
```

## Cross-database relationships (by value, not by FK)

Because every service owns a physically separate database, several logical relationships exist
only as matching UUID/string values, never as enforced foreign keys:

- `role_permissions.permissionKey` (Access Control tenant DB) ↔ `permissions.key` (control-plane
  DB) — a typo'd key silently matches nothing rather than failing a constraint.
- `user_profiles.userId` (User Management) ↔ `users.id` (Access Control) — set once at profile
  creation via a cross-service call; no distributed transaction, so a `UserProfile` save failure
  after a successful identity call would orphan the identity.
- `expenses.orgUnitId` / `payroll_runs.orgUnitId` / `user_profiles.orgUnitId` ↔ `org_units.id`
  (Access Control) — referenced by value only.
- `tenant_db_registry.tenantId` (control-plane) ↔ `tenants.id` (control-plane, same DB but no
  declared FK).
