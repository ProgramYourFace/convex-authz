---
name: convex-authz
description: Add production-ready authorization (RBAC, ABAC, ReBAC) to Convex apps with O(1) permission checks. Use when implementing roles, permissions, access control, multi-tenancy, or relationship-based authorization in a Convex project. Inspired by Google Zanzibar / SpiceDB.
license: Apache-2.0
compatibility:
  agents:
    - claude-code
    - cursor
    - github-copilot
    - cline
    - windsurf
  languages:
    - typescript
  frameworks:
    - convex
    - react
    - next.js
metadata:
  tags: convex, authorization, rbac, abac, rebac, permissions, roles, zanzibar, multi-tenant, access-control
  author: djpanda
  npm: "@djpanda/convex-authz"
  repository: https://github.com/dbjpanda/convex-authz
---

# @djpanda/convex-authz — Authorization for Convex

A production-ready RBAC/ABAC/ReBAC authorization component for Convex with O(1) indexed permission checks, inspired by Google Zanzibar.

## When to Use This Skill

- Setting up **roles and permissions** in a Convex app
- Implementing **multi-tenant authorization** with tenant isolation
- Adding **relationship-based access control** (ReBAC) — e.g., "members of team X can read document Y"
- Implementing **attribute-based policies** (ABAC) — e.g., "only verified users can manage billing"
- Needing **O(1) permission checks** at scale (not scan-based)
- Building **scoped permissions** — e.g., "admin of org:acme" vs global "admin"
- Adding **permission expiration**, **audit logging**, or **user offboarding**

## Installation

```bash
npm install @djpanda/convex-authz
```

## Setup (3 Steps)

### Step 1: Register the component

```typescript
// convex/convex.config.ts
import { defineApp } from "convex/server";
import authz from "@djpanda/convex-authz/convex.config";

const app = defineApp();
app.use(authz);
export default app;
```

### Step 2: Define permissions and roles

```typescript
// convex/authz.ts
import { Authz, definePermissions, defineRoles } from "@djpanda/convex-authz";
import { components } from "./_generated/api";

const permissions = definePermissions({
  documents: { create: true, read: true, update: true, delete: true },
  settings: { view: true, manage: true },
});

const roles = defineRoles(permissions, {
  viewer: { documents: ["read"] },
  editor: { inherits: "viewer", documents: ["create", "update"] },
  admin: { inherits: "editor", documents: ["delete"], settings: ["view", "manage"] },
});

export const authz = new Authz(components.authz, {
  permissions,
  roles,
  tenantId: "my-app", // required — use org ID for multi-tenant
});
```

### Step 3: Use in functions

```typescript
// convex/documents.ts
import { mutation } from "./_generated/server";
import { authz } from "./authz";

export const deleteDocument = mutation({
  args: { docId: v.id("documents") },
  handler: async (ctx, args) => {
    const userId = await getAuthUserId(ctx);
    await authz.require(ctx, userId, "documents:delete");
    await ctx.db.delete(args.docId);
  },
});
```

## Core API

### Permission Checks (O(1))

```typescript
// Boolean check
const canEdit = await authz.can(ctx, userId, "documents:update");

// Throws if denied
await authz.require(ctx, userId, "documents:update");

// Check any of multiple permissions
const canAccess = await authz.canAny(ctx, userId, ["documents:read", "documents:update"]);

// With scope (resource-level)
const canEditInOrg = await authz.can(ctx, userId, "documents:update", { type: "org", id: orgId });
```

### Role Management

```typescript
// Assign
await authz.assignRole(ctx, userId, "editor");
await authz.assignRole(ctx, userId, "admin", { type: "org", id: orgId }); // scoped
await authz.assignRole(ctx, userId, "editor", undefined, Date.now() + 86400000); // expires in 24h

// Revoke
await authz.revokeRole(ctx, userId, "editor");

// Bulk
await authz.assignRoles(ctx, userId, [{ role: "admin" }, { role: "editor", scope: { type: "org", id: orgId } }]);
await authz.revokeAllRoles(ctx, userId);

// Query
const roles = await authz.getUserRoles(ctx, userId);
const isAdmin = await authz.hasRole(ctx, userId, "admin");
```

### Role Inheritance

```typescript
const roles = defineRoles(permissions, {
  viewer: { documents: ["read"] },
  editor: { inherits: "viewer", documents: ["create", "update"] },
  admin: { inherits: "editor", documents: ["delete"], settings: ["manage"] },
});
// admin gets: read + create + update + delete + manage (inherited chain)
```

### Direct Grant/Deny Overrides

```typescript
await authz.grantPermission(ctx, userId, "documents:delete"); // direct allow
await authz.denyPermission(ctx, userId, "documents:delete");  // deny wins over role-based allow
```

### Wildcard Patterns

```typescript
await authz.grantPermission(ctx, userId, "documents:*");  // all document actions
await authz.denyPermission(ctx, userId, "*:delete");       // deny delete on all resources
```

### ReBAC (Relationship-Based Access Control)

```typescript
import { defineRelationPermissions } from "@djpanda/convex-authz";

const authz = new Authz(components.authz, {
  permissions, roles, tenantId: "my-app",
  relationPermissions: defineRelationPermissions({
    "document:viewer": ["documents:read"],
    "document:editor": ["documents:read", "documents:update"],
    "document:owner": ["documents:read", "documents:update", "documents:delete"],
  }),
});

// Add relationship — automatically grants scoped permissions
await authz.addRelation(ctx, { type: "user", id: userId }, "editor", { type: "document", id: docId });

// can() returns true for relation-derived permissions
await authz.can(ctx, userId, "documents:update", { type: "document", id: docId }); // true

// Remove relationship — revokes permissions
await authz.removeRelation(ctx, { type: "user", id: userId }, "editor", { type: "document", id: docId });

// Direct relationship check
await authz.hasRelation(ctx, { type: "user", id: userId }, "member", { type: "team", id: teamId });
```

### ABAC (Attribute-Based Policies)

```typescript
import { definePolicies } from "@djpanda/convex-authz";

const policies = definePolicies({
  "billing:manage": {
    type: "deferred",
    condition: (ctx) => ctx.getAttribute("verified") === true,
    message: "Only verified users can manage billing",
  },
});

const authz = new Authz(components.authz, { permissions, roles, policies, tenantId: "my-app" });

// Set attributes
await authz.setAttribute(ctx, userId, "verified", true);

// Policies are evaluated at read time
await authz.can(ctx, userId, "billing:manage"); // true if verified

// With request context
await authz.canWithContext(ctx, userId, "billing:manage", undefined, { ip: clientIp });
```

### Multi-Tenancy

```typescript
// tenantId is required — isolates all data at the index level
const authz = new Authz(components.authz, { permissions, roles, tenantId: orgId });

// Cross-tenant admin operations
const otherTenant = authz.withTenant("other-org-id");
await otherTenant.can(ctx, userId, "documents:read");
```

### Offboarding & Lifecycle

```typescript
await authz.offboardUser(ctx, userId, {
  removeAttributes: true,
  removeOverrides: true,
  removeRelationships: true,
});

await authz.deprovisionUser(ctx, userId); // wipes everything

await authz.recomputeUser(ctx, userId); // rebuild effective tables after deploy
```

### Audit Log

```typescript
const logs = await authz.getAuditLog(ctx, { userId, limit: 50 });
// Actions: role_assigned, role_revoked, permission_granted, permission_denied,
//          attribute_set, attribute_removed, relation_added, relation_removed
```

### React Integration

```tsx
import { AuthzProvider, useCanUser, PermissionGate } from "@djpanda/convex-authz/react";

<AuthzProvider queryRefs={{ checkPermission: api.app.checkPermission, getUserRoles: api.app.getRoles }}>
  <PermissionGate permission="documents:update" fallback={<p>No access</p>}>
    <EditButton />
  </PermissionGate>
</AuthzProvider>
```

## Type Safety

Permission strings are type-checked at compile time:

```typescript
await authz.can(ctx, userId, "documents:read");    // OK
await authz.can(ctx, userId, "documets:read");     // TypeScript error — typo caught
await authz.can(ctx, userId, "documents:archive"); // TypeScript error — action doesn't exist
```

## Architecture

- **Dual-layer design**: Source tables (roleAssignments, relationships) + pre-computed effective tables (effectivePermissions, effectiveRoles, effectiveRelationships)
- **O(1) reads**: Every `can()` call is a single indexed lookup
- **Atomic dual-write**: All mutations write to both layers in one transaction
- **1ms permission checks** at 10K+ user scale on real Convex infrastructure

## Common Patterns

### Global singleton (recommended)

Create one `authz` instance in `convex/authz.ts` and import it everywhere.

### Check before mutate

```typescript
await authz.require(ctx, userId, "documents:update");
await ctx.db.patch(docId, { content: newContent });
```

### Scoped roles for multi-tenancy

```typescript
await authz.assignRole(ctx, userId, "admin", { type: "org", id: orgId });
await authz.can(ctx, userId, "settings:manage", { type: "org", id: orgId });
```

## Validation

All inputs are validated. Invalid arguments throw clear error messages:

- Empty userId, permission, or role → throws
- Invalid permission format (must be "resource:action") → throws
- Bulk arrays exceeding limits (20 roles, 100 permissions) → throws

## Links

- npm: https://www.npmjs.com/package/@djpanda/convex-authz
- GitHub: https://github.com/dbjpanda/convex-authz
- Demo: https://convex-authz.vercel.app
