# Sequence Diagrams

## 1. Login / JWT issuance

```mermaid
sequenceDiagram
    participant C as Client
    participant AC as Access Control
    participant CP as Control-plane DB
    participant TDB as Tenant DB (Access Control)
    participant R as Redis (audit stream)

    C->>AC: POST /auth/login {tenantSlug, email, password}
    AC->>CP: SELECT tenant WHERE slug=? AND status='active'
    CP-->>AC: tenant row (or none)
    alt tenant not found
        AC-->>C: 401 Unknown tenant
    end
    AC->>TDB: SELECT user WHERE tenantId=? AND email=? AND status='active'
    TDB-->>AC: user row (or none)
    AC->>AC: verify password hash (bcrypt)
    alt invalid credentials
        AC->>R: XADD audit:<tenantId> {action: auth.login, decision: deny}
        AC-->>C: 401 Invalid credentials
    end
    AC->>TDB: load RoleAssignments, Roles, RolePermissions for user
    TDB-->>AC: assignments + flattened, deduped permission set + orgUnitId
    AC->>AC: signAccessToken({sub, tenantId, roles, permissions, orgUnitId}, 15min)
    AC->>TDB: INSERT refresh_token (hash only, 30d expiry)
    AC->>R: XADD audit:<tenantId> {action: auth.login, decision: allow}
    AC-->>C: 200 {accessToken, refreshToken}
```

## 2. Authenticated request → permission check (fast path)

```mermaid
sequenceDiagram
    participant C as Client
    participant Svc as Any resource service<br/>(e.g. Expense Management)
    participant AG as AuthGuard (auth-kit)
    participant PG as PermissionGuard (auth-kit)
    participant PCC as PermissionCheckClient (auth-kit)
    participant TDB as Service's tenant DB

    C->>Svc: GET /expenses/:id  Authorization: Bearer <JWT>
    Svc->>AG: canActivate()
    AG->>AG: verifyAccessToken(jwt, JWT_SECRET)
    AG->>Svc: request.authContext = decoded claims
    Svc->>PG: canActivate()
    PG->>PG: read @RequirePermission metadata via Reflector
    PG->>PCC: check(authContext, "expense:read", targetOrgUnitId)
    PCC->>PCC: claims.permissions.includes("expense:read")?
    PCC->>PCC: org-unit exact-match check (no DB call)
    PCC-->>PG: true / false
    alt denied
        PG-->>C: 403 Forbidden "Missing permission: expense:read"
    else allowed
        Svc->>TDB: resolve tenant DB via TenantConnectionResolver, query expense
        TDB-->>Svc: expense row
        Svc-->>C: 200 expense
    end
```

## 3. Cross-service call: expense approval → payroll reimbursement

```mermaid
sequenceDiagram
    participant U as User
    participant EM as Expense Management
    participant PR as Payroll
    participant AC as Access Control
    participant R as Redis (audit stream)

    U->>EM: POST /expenses/:id/approve  Authorization: Bearer <user JWT>
    EM->>EM: AuthGuard + PermissionGuard ("expense:approve")
    EM->>EM: load expense from its own tenant DB
    EM->>PR: POST /reimbursements<br/>Authorization: Bearer <same user JWT, forwarded><br/>x-service-api-key: <expense-management's own key>
    PR->>PR: AuthGuard + PermissionGuard ("payroll:run")<br/>— validates the forwarded user JWT (Layer 1)
    alt user lacks payroll:run
        PR-->>EM: 403 Forbidden
        EM-->>U: propagate failure — expense stays "pending"
    end
    PR->>PR: read x-service-api-key header (Layer 2)
    alt header missing
        PR-->>EM: 401 Missing x-service-api-key header
        EM-->>U: propagate failure — expense stays "pending"
    end
    PR->>AC: POST /authz/verify-service-key {tenantId, key}
    AC-->>PR: {valid: true/false}
    alt key invalid
        PR-->>EM: 401 Invalid service API key
        EM-->>U: propagate failure — expense stays "pending"
    end
    PR->>R: XADD audit:<tenantId> {action: payroll.reimbursement.record,<br/>viaService: "expense-management"}
    PR-->>EM: 200 {status: "recorded", expenseId, amountCents}
    EM->>EM: expense.status = "approved"
    EM->>EM: save expense
    EM->>R: XADD audit:<tenantId> {action: expense.approve, viaService: "payroll"}
    EM-->>U: 200 approved expense
```

## 4. Tenant provisioning (`scripts/provision-tenant.ts`)

```mermaid
sequenceDiagram
    participant Op as Operator (script)
    participant CP as Control-plane DB
    participant PG as Postgres (admin connection)
    participant SvcDB as New per-service DB<br/>(e.g. expense_management_acme)

    Op->>CP: INSERT tenants (name, slug, status: active)
    CP-->>Op: tenant.id
    loop for each provisioned service<br/>(access-control, user-management,<br/>expense-management, payroll, audit)
        Op->>PG: CREATE DATABASE <service>_<slug> (if not exists)
        Op->>CP: INSERT tenant_db_registry (tenantId, serviceName, host, port, database, ...)
        Op->>SvcDB: initialize DataSource, runMigrations()
        alt serviceName == "access-control"
            Op->>SvcDB: INSERT api_keys for every registered service<br/>(hashed service API keys)
        end
    end
    Op-->>Op: return {tenantId, serviceApiKeys}
```

_Reporting, Workflow, Notification, and Invoice Management are absent from the provisioned-service
list — they never receive a database, which is why they remain stubs._

## 5. Audit event consumption

```mermaid
sequenceDiagram
    participant Any as Any service
    participant R as Redis (per-tenant Stream)
    participant Disc as Audit: discovery loop (every 2s)
    participant CP as Control-plane DB
    participant Cons as Audit: consumer
    participant TDB as Tenant's Audit DB

    Any->>R: XADD audit:<tenantId> {payload: <event JSON>}
    loop every 2 seconds
        Disc->>CP: SELECT id FROM tenants WHERE status='active'
        CP-->>Disc: active tenant IDs
        loop for each active tenant
            Disc->>Cons: consumeTenantStream(tenantId)
            Cons->>R: XGROUP CREATE audit:<tenantId> audit-service (if absent)
            Cons->>R: XREADGROUP audit-service <consumer> COUNT 10 BLOCK 5000
            R-->>Cons: up to 10 new stream entries
            loop for each entry
                Cons->>TDB: INSERT audit_events row
                Cons->>R: XACK audit:<tenantId> audit-service <entryId>
            end
        end
    end
```
