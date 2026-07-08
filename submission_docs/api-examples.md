# API Examples

All examples call services directly on their local port (matching the README's local-run
instructions). The same requests can go through the Gateway (`:3000`) at
`/api/<service-slug>/<rest-of-path>` — e.g. `POST http://localhost:3000/api/expense-management/expenses` —
with an identical body and an unchanged `Authorization` header.

Field names below match the actual `class-validator` DTOs in the codebase exactly — nothing here
is invented.

---

## 1. Login

```bash
curl -X POST http://localhost:3001/auth/login \
  -H 'content-type: application/json' \
  -d '{
    "tenantSlug": "acme",
    "email": "admin@acme.example.com",
    "password": "hunter22"
  }'
```

**200 response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "9f1b2c...64-hex-chars"
}
```

**401 response (unknown tenant or bad credentials):**
```json
{ "statusCode": 401, "message": "Invalid credentials" }
```

The decoded access token carries: `{ sub, tenantId, roles, permissions, orgUnitId, iat, exp }`.
All examples below assume `$TOKEN` holds this `accessToken`.

---

## 2. Org units (Access Control)

```bash
curl -X POST http://localhost:3001/org-units \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{ "name": "Engineering", "parentId": null }'
```

Requires permission `role:manage`. `tenantId` is never accepted from the body — it's always
`auth.tenantId` from the JWT.

```bash
curl http://localhost:3001/org-units -H "authorization: Bearer $TOKEN"
```

---

## 3. Roles and role assignments (Access Control)

```bash
curl -X POST http://localhost:3001/roles \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name": "Expense Approver",
    "description": "Can approve team expenses",
    "permissionKeys": ["expense:read", "expense:approve"]
  }'
```

```bash
curl -X POST http://localhost:3001/role-assignments \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "userId": "3f2b1a10-...",
    "roleId": "8e7d6c50-...",
    "orgUnitId": "1a2b3c40-..."
  }'
```

**200 response:**
```json
{ "status": "assigned" }
```

Both routes require `role:manage`.

---

## 4. Employee profile (User Management)

```bash
curl -X POST http://localhost:3002/profiles \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "email": "new.hire@acme.example.com",
    "password": "a-strong-password",
    "fullName": "Jamie Rivera",
    "jobTitle": "Software Engineer",
    "orgUnitId": "1a2b3c40-...",
    "managerId": "3f2b1a10-...",
    "hireDate": "2026-07-08"
  }'
```

Requires `user:manage`. Internally, User Management first calls Access Control's
`POST /internal/users` (service-key-only, see §8) to create the login identity, then persists the
profile row locally with the returned `userId`.

```bash
curl "http://localhost:3002/profiles?orgUnitId=1a2b3c40-..." -H "authorization: Bearer $TOKEN"
```

---

## 5. Expenses (Expense Management)

**Create:**
```bash
curl -X POST http://localhost:3003/expenses \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{ "orgUnitId": "1a2b3c40-...", "amountCents": 4599, "description": "Client dinner" }'
```
Requires `expense:create`.

**200 response:**
```json
{
  "id": "9c8b7a60-...",
  "tenantId": "b1a0f2e0-...",
  "orgUnitId": "1a2b3c40-...",
  "createdByUserId": "3f2b1a10-...",
  "amountCents": 4599,
  "description": "Client dinner",
  "status": "pending"
}
```

**Get / list** (requires `expense:read`):
```bash
curl http://localhost:3003/expenses/9c8b7a60-... -H "authorization: Bearer $TOKEN"
curl "http://localhost:3003/expenses?orgUnitId=1a2b3c40-..." -H "authorization: Bearer $TOKEN"
```

**Approve** (requires `expense:approve`; triggers the cross-service call to Payroll described in
[sequence-diagrams.md](./sequence-diagrams.md) §3):
```bash
curl -X POST http://localhost:3003/expenses/9c8b7a60-.../approve \
  -H "authorization: Bearer $TOKEN"
```

**200 response:**
```json
{
  "id": "9c8b7a60-...",
  "status": "approved",
  "amountCents": 4599,
  "orgUnitId": "1a2b3c40-...",
  "createdByUserId": "3f2b1a10-...",
  "description": "Client dinner"
}
```

**403 — permission denied example** (caller's JWT lacks `expense:approve`):
```bash
curl -i -X POST http://localhost:3003/expenses/9c8b7a60-.../approve \
  -H "authorization: Bearer $TOKEN_WITHOUT_APPROVE_PERMISSION"
```
```
HTTP/1.1 403 Forbidden
content-type: application/json

{ "statusCode": 403, "message": "Missing permission: expense:approve", "error": "Forbidden" }
```

---

## 6. Payroll runs (Payroll)

**Trigger a run** (requires `payroll:run`):
```bash
curl -X POST http://localhost:3004/payroll-runs \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "orgUnitId": "1a2b3c40-...",
    "employeeUserIds": ["3f2b1a10-...", "5e4d3c20-..."]
  }'
```

**200 response** (flat-rate stub calculation — see tradeoffs doc):
```json
{
  "id": "7a6b5c40-...",
  "tenantId": "b1a0f2e0-...",
  "orgUnitId": "1a2b3c40-...",
  "triggeredByUserId": "admin-user-id",
  "status": "completed",
  "totalAmountCents": 1000000
}
```

**Get / list** (requires `payroll:read`):
```bash
curl http://localhost:3004/payroll-runs/7a6b5c40-... -H "authorization: Bearer $TOKEN"
curl "http://localhost:3004/payroll-runs?orgUnitId=1a2b3c40-..." -H "authorization: Bearer $TOKEN"
```

---

## 7. Reimbursements — service-to-service example (Payroll)

This endpoint is the receiving side of the Expense→Payroll cross-service call. It is normally
invoked by Expense Management's own code, but can be called directly for testing — it still
requires a valid user JWT with `payroll:run` **and** a valid service API key:

```bash
curl -X POST http://localhost:3004/reimbursements \
  -H "authorization: Bearer $TOKEN" \
  -H "x-service-api-key: $SERVICE_API_KEY_EXPENSE_MANAGEMENT" \
  -H 'content-type: application/json' \
  -d '{ "expenseId": "9c8b7a60-...", "amountCents": 4599 }'
```

**200 response:**
```json
{ "status": "recorded", "expenseId": "9c8b7a60-...", "amountCents": 4599 }
```

**401 — missing service key** (JWT is valid and has `payroll:run`, but the header is absent):
```bash
curl -i -X POST http://localhost:3004/reimbursements \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{ "expenseId": "9c8b7a60-...", "amountCents": 4599 }'
```
```
HTTP/1.1 401 Unauthorized
{ "statusCode": 401, "message": "Missing x-service-api-key header" }
```

---

## 8. Internal user provisioning — machine-only endpoint (Access Control)

Not JWT-guarded at all — gated purely by `x-service-api-key`. This is what User Management calls
internally when creating a new profile:

```bash
curl -X POST http://localhost:3001/internal/users \
  -H "x-service-api-key: $SERVICE_API_KEY_USER_MANAGEMENT" \
  -H 'content-type: application/json' \
  -d '{
    "tenantId": "b1a0f2e0-...",
    "email": "new.hire@acme.example.com",
    "password": "a-strong-password"
  }'
```

**200 response:**
```json
{ "id": "3f2b1a10-...", "email": "new.hire@acme.example.com" }
```

---

## 9. Audit events (Audit)

```bash
curl "http://localhost:3009/audit-events?service=expense-management&decision=allow" \
  -H "authorization: Bearer $TOKEN"
```

Requires `audit:read`. Both query filters are optional.

**200 response:**
```json
[
  {
    "id": "af3e2d10-...",
    "tenantId": "b1a0f2e0-...",
    "actorUserId": "3f2b1a10-...",
    "service": "expense-management",
    "action": "expense.approve",
    "resourceType": "expense",
    "resourceId": "9c8b7a60-...",
    "decision": "allow",
    "viaService": "payroll",
    "metadata": null,
    "occurredAt": "2026-07-08T14:32:01.000Z"
  }
]
```

Note: there is no pagination on this endpoint — it returns the full matching set, ordered by
`occurredAt DESC`.

---

## 10. Stub service endpoints (Reporting / Workflow / Notification / Invoice Management)

These are fully guarded (JWT + permission check) but return hardcoded/placeholder data — no
database backs them.

```bash
curl -X POST http://localhost:3008/invoices \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{ "totalAmountCents": 250000 }'
```
```json
{ "id": "stub-invoice", "totalAmountCents": 250000, "status": "draft" }
```

```bash
curl -X POST http://localhost:3007/notifications \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{ "recipientUserId": "3f2b1a10-...", "message": "Your expense was approved" }'
```
```json
{ "id": "stub-notification", "recipientUserId": "3f2b1a10-...", "message": "Your expense was approved", "status": "sent" }
```
