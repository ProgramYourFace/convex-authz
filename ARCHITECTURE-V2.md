# convex-authz v2 Architecture

## 1. Problem Statement

The current library exposes **two client classes** that users must choose between:

| Capability | `Authz` | `IndexedAuthz` |
|---|---|---|
| Permission checks | Scan-based (role assignments + overrides every call) | O(1) via `effectivePermissions` table |
| ABAC policies | Yes (`definePolicies`, `PolicyContext`) | **No** |
| ReBAC relations | Only via `rebac.ts` queries (traversal-based) | O(1) via `effectiveRelationships` + materialized transitive closure |
| Write path | Simple inserts into `roleAssignments` / `permissionOverrides` | Must recompute `effectivePermissions` / `effectiveRoles` on every write |
| User attributes | Full support | No direct support (must fall back to `Authz`) |

This forces users into an uncomfortable trade-off: fast reads **or** rich policy evaluation, never both. The v2 architecture unifies everything into a single `Authz` class.

---

## 2. Design Principles

1. **Single class, always O(1) reads** -- the hot path (`can()`) always hits the materialized `effectivePermissions` table first.
2. **Policies run on the write path** -- ABAC conditions are evaluated during materialization (when roles/attributes/relations change), not on every `can()` call. This is the only way to guarantee O(1) reads AND support policies.
3. **Policies can optionally run on the read path** -- for conditions that depend on request-time context (IP address, time-of-day), a `canWithContext()` method evaluates the cached permission plus a lightweight policy check.
4. **Source-of-truth tables remain normalized** -- `roleAssignments`, `relationships`, `permissionOverrides`, `userAttributes` are canonical. The `effective*` tables are derived caches.
5. **One schema, backward-compatible migration** -- v2 adds columns to existing tables; no tables are removed.

---

## 3. Schema Design

### 3.1 Decision: Keep Separate Tables (Not a Unified Tuples Table)

A single `tuples` table (SpiceDB-style) was considered but rejected for Convex:

- Convex indexes are compound equality chains, not arbitrary composite keys. A single table with `(subjectType, subjectId, relation, objectType, objectId)` needs many distinct index permutations for different access patterns (subject-first, object-first, relation-first). Separate tables let each table have purpose-built indexes.
- Type safety: Convex validators are per-table. Separate tables give each record type its own shape and validation.
- Operational clarity: reading `roleAssignments` vs `relationships` vs `permissionOverrides` is immediately understandable.

### 3.2 Source-of-Truth Tables (Unchanged)

These tables are canonical. Writes go here first, then effective tables are recomputed.

```typescript
// schema.ts (v2)

import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

const scopeValidator = v.optional(
  v.object({ type: v.string(), id: v.string() })
);

export default defineSchema({
  // ── Source of Truth ─────────────────────────────────────────────

  roleAssignments: defineTable({
    tenantId: v.string(),
    userId: v.string(),
    role: v.string(),
    scope: scopeValidator,
    metadata: v.optional(v.any()),
    assignedBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
  })
    .index("by_tenant_user", ["tenantId", "userId"])
    .index("by_tenant_role", ["tenantId", "role"])
    .index("by_tenant_user_role", ["tenantId", "userId", "role"]),

  userAttributes: defineTable({
    tenantId: v.string(),
    userId: v.string(),
    key: v.string(),
    value: v.any(),
  })
    .index("by_tenant_user", ["tenantId", "userId"])
    .index("by_tenant_user_key", ["tenantId", "userId", "key"]),

  permissionOverrides: defineTable({
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    effect: v.union(v.literal("allow"), v.literal("deny")),
    scope: scopeValidator,
    reason: v.optional(v.string()),
    createdBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
  })
    .index("by_tenant_user", ["tenantId", "userId"])
    .index("by_tenant_user_permission", ["tenantId", "userId", "permission"]),

  relationships: defineTable({
    tenantId: v.string(),
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
    // v2: optional caveat (ABAC condition on an edge)
    caveat: v.optional(v.string()),    // name of a registered caveat function
    caveatContext: v.optional(v.any()), // static context passed to caveat at eval time
    createdBy: v.optional(v.string()),
    createdAt: v.number(),
  })
    .index("by_tenant_subject", ["tenantId", "subjectType", "subjectId"])
    .index("by_tenant_object", ["tenantId", "objectType", "objectId"])
    .index("by_tenant_subject_relation_object", [
      "tenantId", "subjectType", "subjectId",
      "relation", "objectType", "objectId",
    ])
    .index("by_tenant_object_relation", [
      "tenantId", "objectType", "objectId", "relation",
    ]),

  // ── Materialized Caches ────────────────────────────────────────

  effectivePermissions: defineTable({
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    scopeKey: v.string(),             // "global" | "objectType:objectId"
    scope: scopeValidator,
    effect: v.string(),               // "allow" | "deny"
    sources: v.array(v.string()),     // role names that grant this
    directGrant: v.optional(v.boolean()),
    directDeny: v.optional(v.boolean()),
    // v2: policy evaluation result
    policyResult: v.optional(v.union(
      v.literal("allow"),
      v.literal("deny"),
      v.literal("deferred"),          // must re-evaluate at read time
    )),
    policyName: v.optional(v.string()),
    reason: v.optional(v.string()),
    grantedBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_tenant_user", ["tenantId", "userId"])
    .index("by_tenant_user_scope", ["tenantId", "userId", "scopeKey"])
    .index("by_tenant_user_permission_scope", [
      "tenantId", "userId", "permission", "scopeKey",
    ]),

  effectiveRoles: defineTable({
    tenantId: v.string(),
    userId: v.string(),
    role: v.string(),
    scopeKey: v.string(),
    scope: scopeValidator,
    assignedBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_tenant_user", ["tenantId", "userId"])
    .index("by_tenant_user_scope", ["tenantId", "userId", "scopeKey"])
    .index("by_tenant_user_role_scope", [
      "tenantId", "userId", "role", "scopeKey",
    ]),

  effectiveRelationships: defineTable({
    tenantId: v.string(),
    subjectKey: v.string(),           // "subjectType:subjectId"
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectKey: v.string(),            // "objectType:objectId"
    objectType: v.string(),
    objectId: v.string(),
    isDirect: v.boolean(),
    inheritedFrom: v.union(v.string(), v.null()),
    // v2: depth for traversal debugging
    depth: v.optional(v.number()),
    createdBy: v.optional(v.string()),
    createdAt: v.number(),
  })
    .index("by_tenant_subject", ["tenantId", "subjectKey"])
    .index("by_tenant_object", ["tenantId", "objectKey"])
    .index("by_tenant_subject_relation", [
      "tenantId", "subjectKey", "relation",
    ])
    .index("by_tenant_subject_relation_object", [
      "tenantId", "subjectKey", "relation", "objectKey",
    ])
    .index("by_tenant_inherited_from", ["tenantId", "inheritedFrom"]),

  // ── Audit ──────────────────────────────────────────────────────

  auditLog: defineTable({
    tenantId: v.string(),
    timestamp: v.number(),
    action: v.union(
      v.literal("permission_check"),
      v.literal("role_assigned"),
      v.literal("role_revoked"),
      v.literal("permission_granted"),
      v.literal("permission_denied"),
      v.literal("attribute_set"),
      v.literal("attribute_removed"),
      // v2:
      v.literal("relation_added"),
      v.literal("relation_removed"),
      v.literal("policy_evaluated"),
    ),
    userId: v.string(),
    actorId: v.optional(v.string()),
    details: v.any(),
  })
    .index("by_tenant_user", ["tenantId", "userId"])
    .index("by_tenant_action", ["tenantId", "action"])
    .index("by_tenant_timestamp", ["tenantId", "timestamp"]),
});
```

### 3.3 Key Schema Changes in v2

| Change | Rationale |
|---|---|
| `relationships.caveat` / `relationships.caveatContext` | Allows ABAC conditions on graph edges (e.g., "user is viewer of document IF document.status == 'published'"). This is the Zanzibar "caveat" concept. |
| `effectivePermissions.policyResult` / `policyName` | When a permission is materialized but has an associated ABAC policy, `policyResult = "deferred"` signals that `can()` must evaluate the policy condition at read time. Static policies evaluated at write time store `"allow"` or `"deny"`. |
| `effectiveRelationships.depth` | For debugging and limiting transitive closure depth. |
| New audit actions | `relation_added`, `relation_removed`, `policy_evaluated` for comprehensive audit trail. |

---

## 4. Permission Resolution Engine

### 4.1 Two Categories of Policies

Policies are classified at definition time:

```typescript
const policies = definePolicies({
  // STATIC policy: depends only on user attributes, roles, resource metadata
  // Can be fully evaluated at write time (when role/attribute changes)
  "documents:delete": {
    type: "static",   // DEFAULT
    condition: (ctx) => ctx.subject.attributes.department === "engineering",
    message: "Only engineering department can delete documents",
  },

  // DEFERRED policy: depends on request-time context
  // Cannot be evaluated at write time; checked at read time
  "billing:export": {
    type: "deferred",
    condition: (ctx) => {
      const hour = new Date().getUTCHours();
      return hour >= 9 && hour <= 17; // business hours only
    },
    message: "Billing exports only during business hours",
  },
});
```

### 4.2 `can()` Resolution Algorithm

```
can(userId, permission, scope?) -> boolean
  |
  |-- Step 1: O(1) indexed lookup in effectivePermissions
  |    query effectivePermissions WHERE
  |      tenantId = T AND userId = U AND permission = P AND scopeKey = S
  |
  |-- if not found:
  |    return false
  |
  |-- if found AND expired:
  |    return false
  |
  |-- if found AND effect == "deny":
  |    return false
  |
  |-- if found AND effect == "allow" AND policyResult is null or "allow":
  |    return true                     <-- pure O(1) path
  |
  |-- if found AND policyResult == "deferred":
  |    |-- Step 2: evaluate deferred policy
  |    |    load user attributes (1 indexed query)
  |    |    load user roles from effectiveRoles (1 indexed query)
  |    |    build PolicyContext
  |    |    run policy condition function
  |    |    return condition result
  |
  |-- fallback: check wildcard patterns in effectivePermissions
  |    (query by user+scope, filter for pattern matches)
  |    same logic as above for each matching row
```

**Pseudocode:**

```typescript
async function can(ctx, userId, permission, scope?) {
  const scopeKey = scope ? `${scope.type}:${scope.id}` : "global";

  // Step 1: exact O(1) lookup
  const cached = await db.query("effectivePermissions")
    .withIndex("by_tenant_user_permission_scope",
      q => q.eq("tenantId", T).eq("userId", userId)
            .eq("permission", permission).eq("scopeKey", scopeKey))
    .unique();

  if (cached && !isExpired(cached.expiresAt)) {
    if (cached.effect === "deny") return false;
    if (cached.effect === "allow") {
      if (!cached.policyResult || cached.policyResult === "allow") {
        return true;  // O(1) !!!
      }
      if (cached.policyResult === "deferred") {
        return await evaluateDeferredPolicy(ctx, cached.policyName, userId, permission, scope);
      }
    }
  }

  // Step 2: wildcard fallback (still uses index, filters client-side)
  const allPerms = await db.query("effectivePermissions")
    .withIndex("by_tenant_user_scope",
      q => q.eq("tenantId", T).eq("userId", userId).eq("scopeKey", scopeKey))
    .collect();

  // Check deny patterns first
  for (const p of allPerms) {
    if (p.effect === "deny" && matchesPattern(permission, p.permission)) {
      return false;
    }
  }
  // Check allow patterns
  for (const p of allPerms) {
    if (p.effect === "allow" && matchesPattern(permission, p.permission)) {
      if (!p.policyResult || p.policyResult === "allow") return true;
      if (p.policyResult === "deferred") {
        const result = await evaluateDeferredPolicy(ctx, p.policyName, userId, permission, scope);
        if (result) return true;
      }
    }
  }

  return false;
}
```

### 4.3 Cache Invalidation Strategy

**Trigger: role assignment / revocation changes**

When `assignRole(userId, "editor")` is called:
1. Write to `roleAssignments` table (source of truth)
2. Upsert into `effectiveRoles` table
3. Look up `rolePermissions["editor"]` from the client-provided role definitions
4. For each permission the role grants:
   a. Check if a static policy exists for this permission
   b. If yes, evaluate the policy with current user context
      - If policy returns false -> skip (don't materialize this permission)
      - If policy returns true -> materialize with `policyResult = "allow"`
   c. If a deferred policy exists -> materialize with `policyResult = "deferred"`
   d. If no policy -> materialize with `policyResult = null` (pure RBAC)
   e. Upsert into `effectivePermissions`, tracking `sources` array

When `revokeRole(userId, "editor")` is called:
1. Delete from `roleAssignments`
2. Delete from `effectiveRoles`
3. For each permission the role granted:
   a. Remove "editor" from the `sources` array
   b. If `sources` is now empty AND no `directGrant` -> delete the row
   c. If other sources remain -> patch the row

**Trigger: attribute changes**

When `setAttribute(userId, "department", "sales")` is called:
1. Write to `userAttributes` (source of truth)
2. Re-evaluate ALL static policies for this user:
   a. Get all effectivePermissions where `policyResult = "allow"` or `policyResult = "deny"`
   b. For each, re-run the static policy with updated attributes
   c. If result changed -> update the `effectivePermissions` row
3. This is O(policies * permissions) but only runs on attribute change, not on every read

**Trigger: relationship changes**

When `addRelation(user:123, "member", team:456)` is called:
1. Write to `relationships` (source of truth)
2. Upsert into `effectiveRelationships` (direct)
3. Run transitive closure to compute inherited relationships
4. For each new effective relationship, check if it grants permissions
   (based on `defineRelationPermissions` config)

**Trigger: permission override changes**

When `grantPermission(userId, "documents:delete")` is called:
1. Write to `permissionOverrides` (source of truth)
2. Upsert into `effectivePermissions` with `directGrant = true`

When `denyPermission(userId, "documents:delete")` is called:
1. Write to `permissionOverrides` (source of truth)
2. Upsert into `effectivePermissions` with `effect = "deny"`, `directDeny = true`
   - This overrides any role-based "allow" for this permission

---

## 5. Write Path Algorithms

### 5.1 `assignRole(userId, role, scope?, expiresAt?)`

```
assignRole(userId, role, scope?, expiresAt?)
  |
  |-- 1. Check for duplicate in roleAssignments
  |     (query by_tenant_user_role, filter by scope + not expired)
  |     if duplicate: throw ALREADY_EXISTS
  |
  |-- 2. Insert into roleAssignments (source of truth)
  |
  |-- 3. Upsert into effectiveRoles
  |     (query by_tenant_user_role_scope for existing)
  |     if exists: patch expiresAt/updatedAt
  |     else: insert new row
  |
  |-- 4. Resolve permissions for this role
  |     perms = flattenRolePermissions(roles, roleName)
  |     (follows inherits/includes chains with cycle detection)
  |
  |-- 5. For each permission in perms:
  |     |-- Check if static policy exists for this permission
  |     |   policy = policies[permission]
  |     |   if policy && policy.type == "static":
  |     |     attrs = loadUserAttributes(userId)
  |     |     roles = loadEffectiveRoles(userId)
  |     |     ctx = buildPolicyContext(userId, roles, attrs, permission)
  |     |     result = policy.condition(ctx)
  |     |     if !result: skip this permission (policy denies)
  |     |     policyResult = "allow"
  |     |   elif policy && policy.type == "deferred":
  |     |     policyResult = "deferred"
  |     |   else:
  |     |     policyResult = null
  |     |
  |     |-- Upsert into effectivePermissions
  |         (query by_tenant_user_permission_scope)
  |         if exists:
  |           add roleName to sources[] if not already present
  |           patch updatedAt
  |         else:
  |           insert with effect="allow", sources=[roleName], policyResult
  |
  |-- 6. Write audit log entry
  |
  |-- return assignmentId
```

### 5.2 `addRelation(subjectType, subjectId, relation, objectType, objectId)`

```
addRelation(subject, relation, object)
  |
  |-- 1. Check for duplicate in relationships
  |     (query by_tenant_subject_relation_object)
  |     if exists: return existing._id (idempotent)
  |
  |-- 2. Insert into relationships (source of truth)
  |
  |-- 3. Insert into effectiveRelationships (direct, isDirect=true)
  |
  |-- 4. Compute transitive closure (if traversalRules configured):
  |     |-- BFS from the new relationship
  |     |-- For each edge in traversalRules:
  |     |     find related objects that this new edge connects to
  |     |     for each discovered transitive relation:
  |     |       insert into effectiveRelationships (isDirect=false, inheritedFrom=directRelId)
  |     |
  |     |-- Also: check if any EXISTING relationships now gain
  |     |   transitive connections through this new edge
  |     |   (reverse traversal from the object side)
  |
  |-- 5. (Optional) If relation-to-permission mapping exists:
  |     for each permission implied by this relation:
  |       upsert into effectivePermissions
  |
  |-- 6. Write audit log entry
  |
  |-- return relationId
```

### 5.3 `setAttribute(userId, key, value)`

```
setAttribute(userId, key, value)
  |
  |-- 1. Upsert into userAttributes (source of truth)
  |
  |-- 2. Re-evaluate static policies for this user:
  |     |-- Load all effectivePermissions for user
  |     |     where policyResult in ("allow", "deny") AND policyName is not null
  |     |
  |     |-- For each such permission:
  |     |     load current attributes (including new value)
  |     |     load current roles
  |     |     build PolicyContext
  |     |     newResult = policy.condition(ctx)
  |     |
  |     |     if newResult != (cached.policyResult == "allow"):
  |     |       if newResult == true:
  |     |         patch effect="allow", policyResult="allow"
  |     |       else:
  |     |         if sources.length > 0:
  |     |           patch effect="deny", policyResult="deny" (role grants but policy denies)
  |     |         else:
  |     |           delete the effectivePermission row
  |
  |-- 3. Write audit log entry
```

### 5.4 `grantPermission(userId, permission, scope?)`

```
grantPermission(userId, permission, scope?)
  |
  |-- 1. Insert/upsert into permissionOverrides (source of truth)
  |     effect="allow"
  |
  |-- 2. Upsert into effectivePermissions
  |     directGrant=true, effect="allow"
  |     NOTE: directGrant overrides any policyResult
  |     (explicit grants bypass policy evaluation)
  |
  |-- 3. Write audit log entry
```

### 5.5 `denyPermission(userId, permission, scope?)`

```
denyPermission(userId, permission, scope?)
  |
  |-- 1. Insert/upsert into permissionOverrides (source of truth)
  |     effect="deny"
  |
  |-- 2. Upsert into effectivePermissions
  |     directDeny=true, effect="deny"
  |     NOTE: explicit deny ALWAYS wins (deny-overrides model)
  |
  |-- 3. Write audit log entry
```

---

## 6. Read Path Algorithms

### 6.1 `can(userId, permission, scope?)` -- the hot path

See Section 4.2 above for the full algorithm. Summary:

- **Best case (no policies, exact match)**: 1 index lookup -> O(1)
- **With deferred policy**: 1 index lookup + 2 attribute/role loads + 1 function call -> O(1) + policy eval
- **With wildcard patterns**: 1 range query on user+scope, filter for pattern match -> O(permissions per user in scope)
- **Worst case**: all of the above combined

### 6.2 `hasRole(userId, role, scope?)`

```
O(1): query effectiveRoles by_tenant_user_role_scope
  -> unique()
  -> check expiry
  -> return exists && !expired
```

### 6.3 `hasRelation(subjectType, subjectId, relation, objectType, objectId)`

```
O(1): query effectiveRelationships by_tenant_subject_relation_object
  -> unique()
  -> return exists
```

### 6.4 `getUserPermissions(userId, scope?)`

```
query effectivePermissions by_tenant_user_scope
  -> collect()
  -> filter expired
  -> for each with policyResult=="deferred":
       evaluate policy (lazy, only if caller needs full list)
  -> return { permissions: [...], deniedPermissions: [...], roles: [...] }
```

### 6.5 `getUserRoles(userId, scope?)`

```
query effectiveRoles by_tenant_user_scope (or by_tenant_user for all scopes)
  -> collect()
  -> filter expired
  -> return [{ role, scopeKey, scope }]
```

### 6.6 `canWithContext(userId, permission, scope?, requestContext?)`

New method for cases where deferred policies need explicit request context:

```
canWithContext(userId, permission, scope?, { ip?, headers?, time? })
  |
  |-- same as can() but passes requestContext into PolicyContext
  |-- useful for: IP allowlists, time-of-day restrictions, request metadata
```

---

## 7. Graph Traversal Engine

### 7.1 Design

The current `checkRelationWithTraversal` in `rebac.ts` performs BFS at read time. In v2, transitive closure is pre-computed at write time (stored in `effectiveRelationships`), so **read-time traversal is not needed for `hasRelation()`**.

Traversal is only needed:
1. **At write time**: when a relationship is added/removed, to update `effectiveRelationships`
2. **For `listAccessibleObjects()`**: to enumerate all objects a user can access (uses `effectiveRelationships` index)
3. **For `checkRelationWithTraversal()`**: kept as a fallback/diagnostic tool

### 7.2 Write-Time Transitive Closure

```typescript
async function computeTransitiveClosure(
  ctx: MutationCtx,
  tenantId: string,
  newRelation: { subjectType, subjectId, relation, objectType, objectId },
  traversalRules: TraversalRules,
  maxDepth: number = 10,
) {
  const visited = new Set<string>();
  const queue: TraversalItem[] = [];

  // Seed: the new direct relation
  const directKey = `${newRelation.subjectType}:${newRelation.subjectId}:${newRelation.relation}:${newRelation.objectType}:${newRelation.objectId}`;
  visited.add(directKey);

  // Forward expansion: what does this new edge connect to?
  // Look up rules for "objectType:relation" -> inherited relations
  const ruleKey = `${newRelation.objectType}:${newRelation.relation}`;
  const rules = traversalRules[ruleKey] || [];

  for (const rule of rules) {
    // Find objects connected to the target via rule.via
    const connected = await ctx.db.query("effectiveRelationships")
      .withIndex("by_tenant_subject_relation", q =>
        q.eq("tenantId", tenantId)
         .eq("subjectKey", `${newRelation.objectType}:${newRelation.objectId}`)
         .eq("relation", rule.via))
      .collect();

    for (const conn of connected.filter(c => c.objectType === rule.through)) {
      queue.push({
        subjectType: newRelation.subjectType,
        subjectId: newRelation.subjectId,
        relation: rule.inherit,
        objectType: conn.objectType,
        objectId: conn.objectId,
        depth: 1,
        inheritedFrom: directRelId,
      });
    }
  }

  // BFS to find all transitive relations
  while (queue.length > 0) {
    const item = queue.shift()!;
    if (item.depth > maxDepth) continue;

    const key = `${item.subjectType}:${item.subjectId}:${item.relation}:${item.objectType}:${item.objectId}`;
    if (visited.has(key)) continue;
    visited.add(key);

    // Materialize this transitive relation
    await upsertEffectiveRelationship(ctx, tenantId, {
      ...item,
      isDirect: false,
      depth: item.depth,
    });

    // Continue expanding
    const nextRuleKey = `${item.objectType}:${item.relation}`;
    const nextRules = traversalRules[nextRuleKey] || [];
    for (const rule of nextRules) {
      // ... same pattern, push to queue with depth+1
    }
  }
}
```

### 7.3 Cycle Detection

- **Visited set**: keyed by `subjectType:subjectId:relation:objectType:objectId` -- each unique (subject, relation, object) triple is processed at most once.
- **Max depth**: configurable, default 10. Nodes beyond max depth are not expanded.
- **At definition time**: role `inherits`/`includes` chains are validated for cycles by `resolveRolePermissions()` (throws on cycle).

### 7.4 Caveats on Edges (ABAC + ReBAC Composition)

```typescript
// Example: user can view document IF they are a team member AND the document is published
await authz.addRelation(ctx, {
  subject: { type: "user", id: "123" },
  relation: "viewer",
  object: { type: "document", id: "456" },
  caveat: "document_is_published",
  caveatContext: { requiredStatus: "published" },
});

// The caveat is evaluated at write time if static,
// or stored as "deferred" on the effectiveRelationship
```

---

## 8. Client API Surface

### 8.1 Unified `Authz` Class

```typescript
import type {
  GenericQueryCtx, GenericMutationCtx, GenericActionCtx, GenericDataModel,
} from "convex/server";

type QueryCtx = Pick<GenericQueryCtx<GenericDataModel>, "runQuery">;
type MutationCtx = Pick<GenericMutationCtx<GenericDataModel>, "runMutation">;
type ActionCtx = Pick<
  GenericActionCtx<GenericDataModel>,
  "runQuery" | "runMutation" | "runAction"
>;

export class Authz<
  P extends PermissionDefinition,
  R extends RoleDefinition<P>,
  Policy extends PolicyDefinition = Record<string, never>,
> {
  constructor(
    component: ComponentApi,
    options: {
      permissions: P;
      roles: R;
      policies?: Policy;
      tenantId: string;
      defaultActorId?: string;
      // v2: relation-based permission mappings
      relationPermissions?: RelationPermissionMap;
      // v2: traversal rules for transitive closure
      traversalRules?: TraversalRules;
      // v2: caveat functions for conditional edges
      caveats?: Record<string, CaveatFunction>;
    },
  );

  // ── Tenant Scoping ────────────────────────────────────────────

  /** Return a new Authz instance bound to a different tenant. */
  withTenant(tenantId: string): Authz<P, R, Policy>;

  // ── Permission Checks (Read Path) ─────────────────────────────

  /**
   * O(1) permission check.
   * Hits effectivePermissions table directly.
   * For permissions with deferred policies, evaluates policy inline.
   */
  can(ctx: QueryCtx | ActionCtx, userId: string, permission: string, scope?: Scope): Promise<boolean>;

  /**
   * O(1) permission check or throw.
   */
  require(ctx: QueryCtx | ActionCtx, userId: string, permission: string, scope?: Scope): Promise<void>;

  /**
   * Check if user has ANY of the given permissions.
   * Single indexed query + client-side filter.
   */
  canAny(ctx: QueryCtx | ActionCtx, userId: string, permissions: string[], scope?: Scope): Promise<boolean>;

  /**
   * Check permission with explicit request-time context (for deferred policies).
   * Use when policies depend on IP, time, request headers, etc.
   */
  canWithContext(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    requestContext?: { ip?: string; time?: number; [key: string]: unknown },
  ): Promise<boolean>;

  // ── Role Queries ──────────────────────────────────────────────

  /** O(1) role check via effectiveRoles index. */
  hasRole(ctx: QueryCtx | ActionCtx, userId: string, role: keyof R & string, scope?: Scope): Promise<boolean>;

  /** List all roles for a user (optionally scoped). */
  getUserRoles(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope): Promise<Array<{
    role: string;
    scopeKey: string;
    scope?: Scope;
  }>>;

  /** List all users with a specific role. */
  getUsersWithRole(ctx: QueryCtx | ActionCtx, role: keyof R & string, scope?: Scope): Promise<Array<{
    userId: string;
    assignedAt: number;
    expiresAt?: number;
  }>>;

  // ── Permission Queries ────────────────────────────────────────

  /** List all effective permissions for a user. */
  getUserPermissions(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope): Promise<{
    permissions: string[];
    roles: string[];
    deniedPermissions: string[];
  }>;

  // ── Relationship Queries (ReBAC) ──────────────────────────────

  /** O(1) relationship check via effectiveRelationships index. */
  hasRelation(
    ctx: QueryCtx | ActionCtx,
    subject: { type: string; id: string },
    relation: string,
    object: { type: string; id: string },
  ): Promise<boolean>;

  /** Check relationship with full BFS traversal (diagnostic/fallback). */
  checkRelation(
    ctx: QueryCtx | ActionCtx,
    subject: { type: string; id: string },
    relation: string,
    object: { type: string; id: string },
    options?: { maxDepth?: number },
  ): Promise<{ allowed: boolean; path: string[]; reason: string }>;

  /** List all objects a subject can access via a relation. */
  listAccessibleObjects(
    ctx: QueryCtx | ActionCtx,
    subject: { type: string; id: string },
    relation: string,
    objectType: string,
  ): Promise<Array<{ objectId: string; via: string }>>;

  /** List all subjects with a relation to an object. */
  listSubjectsWithAccess(
    ctx: QueryCtx | ActionCtx,
    object: { type: string; id: string },
    relation: string,
  ): Promise<Array<{ subjectType: string; subjectId: string; via: string }>>;

  // ── Attribute Queries ─────────────────────────────────────────

  /** Get all attributes for a user. */
  getUserAttributes(ctx: QueryCtx | ActionCtx, userId: string): Promise<Array<{
    key: string;
    value: unknown;
  }>>;

  /** Get a single attribute value. */
  getUserAttribute(ctx: QueryCtx | ActionCtx, userId: string, key: string): Promise<unknown | null>;

  // ── Role Mutations ────────────────────────────────────────────

  /**
   * Assign a role to a user.
   * Writes to roleAssignments + effectiveRoles + effectivePermissions.
   * Evaluates static policies during materialization.
   */
  assignRole(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: keyof R & string,
    scope?: Scope,
    expiresAt?: number,
    actorId?: string,
  ): Promise<string>;

  /** Revoke a role and recompute effective permissions. */
  revokeRole(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: keyof R & string,
    scope?: Scope,
    actorId?: string,
  ): Promise<boolean>;

  /** Assign multiple roles in a single transaction. */
  assignRoles(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    roles: RoleAssignItem[],
    actorId?: string,
  ): Promise<{ assigned: number; assignmentIds: string[] }>;

  /** Revoke multiple roles in a single transaction. */
  revokeRoles(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    roles: RoleScopeItem[],
    actorId?: string,
  ): Promise<{ revoked: number }>;

  /** Revoke all roles (optionally scoped). */
  revokeAllRoles(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    scope?: Scope,
    actorId?: string,
  ): Promise<number>;

  // ── Permission Override Mutations ─────────────────────────────

  /** Grant a direct permission (bypasses policies). */
  grantPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    actorId?: string,
  ): Promise<string>;

  /** Deny a permission (overrides any role-based allow). */
  denyPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    actorId?: string,
  ): Promise<string>;

  // ── Relationship Mutations (ReBAC) ────────────────────────────

  /** Add a relationship and compute transitive closure. */
  addRelation(
    ctx: MutationCtx | ActionCtx,
    subject: { type: string; id: string },
    relation: string,
    object: { type: string; id: string },
    options?: {
      caveat?: string;
      caveatContext?: unknown;
      createdBy?: string;
    },
  ): Promise<string>;

  /** Remove a relationship and cascade-delete inherited edges. */
  removeRelation(
    ctx: MutationCtx | ActionCtx,
    subject: { type: string; id: string },
    relation: string,
    object: { type: string; id: string },
  ): Promise<boolean>;

  // ── Attribute Mutations ───────────────────────────────────────

  /**
   * Set a user attribute.
   * Triggers re-evaluation of static policies for this user.
   */
  setAttribute(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    key: string,
    value: unknown,
    actorId?: string,
  ): Promise<string>;

  /** Remove a user attribute. Triggers policy re-evaluation. */
  removeAttribute(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    key: string,
    actorId?: string,
  ): Promise<boolean>;

  // ── Lifecycle ─────────────────────────────────────────────────

  /** Remove all roles, overrides, attributes, and optionally relationships. */
  offboardUser(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    options?: {
      scope?: Scope;
      actorId?: string;
      removeAttributes?: boolean;
      removeOverrides?: boolean;
      removeRelationships?: boolean;
    },
  ): Promise<OffboardResult>;

  /** Complete user deprovisioning (all data, all scopes). */
  deprovisionUser(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    options?: { actorId?: string; enableAudit?: boolean },
  ): Promise<OffboardResult>;

  // ── Audit ─────────────────────────────────────────────────────

  /** Query audit log with optional filters and pagination. */
  getAuditLog(
    ctx: QueryCtx | ActionCtx,
    options?: {
      userId?: string;
      action?: AuditAction;
      limit?: number;
      numItems?: number;
      cursor?: string | null;
    },
  ): Promise<AuditLogResult>;

  // ── Maintenance ───────────────────────────────────────────────

  /** Clean up expired effective entries. Run periodically via cron. */
  cleanupExpired(ctx: MutationCtx | ActionCtx): Promise<{
    expiredPermissions: number;
    expiredRoles: number;
  }>;

  /**
   * Full recomputation of all effective tables for a user.
   * Use after schema migration or to fix inconsistencies.
   */
  recomputeUser(ctx: MutationCtx | ActionCtx, userId: string): Promise<void>;
}

// ── Types ─────────────────────────────────────────────────────

interface OffboardResult {
  rolesRevoked: number;
  overridesRemoved: number;
  attributesRemoved: number;
  relationshipsRemoved: number;
  effectiveRolesRemoved: number;
  effectivePermissionsRemoved: number;
  effectiveRelationshipsRemoved: number;
}

type AuditAction =
  | "permission_check" | "role_assigned" | "role_revoked"
  | "permission_granted" | "permission_denied"
  | "attribute_set" | "attribute_removed"
  | "relation_added" | "relation_removed" | "policy_evaluated";
```

### 8.2 Definition Helpers (Unchanged + New)

```typescript
// Unchanged from v1
export function definePermissions<P extends PermissionDefinition>(p: P): P;
export function definePermissions<P1, P2>(p1: P1, p2: P2): P1 & P2;

export function defineRoles<P extends PermissionDefinition, R extends RoleDefinition<P>>(
  permissions: P, roles: R,
): R;

// Enhanced in v2: policies have a `type` field
export function definePolicies<Policy extends PolicyDefinition>(
  policies: Policy,
): Policy;

// New in v2
export function defineTraversalRules(rules: TraversalRules): TraversalRules;
export function defineRelationPermissions(map: RelationPermissionMap): RelationPermissionMap;
export function defineCaveats(caveats: Record<string, CaveatFunction>): Record<string, CaveatFunction>;

// Types
type PolicyDefinition = Record<string, {
  type?: "static" | "deferred";   // default: "static"
  condition: (ctx: PolicyContext) => boolean | Promise<boolean>;
  message?: string;
}>;

type TraversalRules = Record<string, Array<{
  through: string;    // intermediate object type
  via: string;        // relation from current object to intermediate
  inherit: string;    // relation to check on intermediate
}>>;

type RelationPermissionMap = Record<string, string[]>;
// e.g., { "document:viewer": ["documents:read"], "document:editor": ["documents:read", "documents:update"] }

type CaveatFunction = (context: {
  subject: { type: string; id: string };
  object: { type: string; id: string };
  relation: string;
  caveatContext: unknown;
}) => boolean | Promise<boolean>;
```

### 8.3 `hasRelation` API Change

The v1 `IndexedAuthz.hasRelation` takes 5 positional string arguments. The v2 API uses structured objects for clarity:

```typescript
// v1 (IndexedAuthz)
await authz.hasRelation(ctx, "user", "123", "member", "team", "456");

// v2
await authz.hasRelation(ctx,
  { type: "user", id: "123" },
  "member",
  { type: "team", id: "456" },
);
```

Similarly for `addRelation` and `removeRelation`.

---

## 9. Data Flow Diagrams

### 9.1 Read Flow: `can(ctx, userId, "documents:update")`

```
Client code
  |
  v
Authz.can(ctx, userId, "documents:update")
  |
  |-- validate inputs
  |
  v
ctx.runQuery(component.unified.checkPermission, {
  tenantId, userId, permission: "documents:update", scopeKey: "global"
})
  |
  v
[Component Query Handler]
  |
  |-- db.query("effectivePermissions")
  |     .withIndex("by_tenant_user_permission_scope", ...)
  |     .unique()
  |
  |-- FOUND, effect="allow", policyResult=null
  |     => return { allowed: true }        <-- O(1), done
  |
  |-- OR: FOUND, effect="allow", policyResult="deferred"
  |     |-- db.query("userAttributes").withIndex(...)
  |     |-- db.query("effectiveRoles").withIndex(...)
  |     |-- evaluate policy function
  |     |-- return { allowed: policyResult }
  |
  |-- OR: NOT FOUND
  |     |-- wildcard check (query by user+scope, pattern match)
  |     |-- return { allowed: false }
```

### 9.2 Write Flow: `assignRole(ctx, userId, "editor")`

```
Client code
  |
  v
Authz.assignRole(ctx, userId, "editor", scope)
  |
  |-- validate inputs
  |-- resolve permissions: flattenRolePermissions(roles, "editor")
  |     => ["documents:read", "documents:update"]
  |-- classify policies for each permission
  |
  v
ctx.runMutation(component.unified.assignRoleWithCompute, {
  tenantId, userId, role: "editor",
  rolePermissions: ["documents:read", "documents:update"],
  policyClassifications: {
    "documents:read": null,         // no policy
    "documents:update": "deferred", // has deferred policy
  },
  scope, expiresAt, assignedBy
})
  |
  v
[Component Mutation Handler]
  |
  |-- 1. Check duplicate in roleAssignments -> throw if exists
  |-- 2. INSERT roleAssignments { tenantId, userId, role:"editor", scope }
  |-- 3. UPSERT effectiveRoles { tenantId, userId, role:"editor", scopeKey }
  |-- 4. For "documents:read" (no policy):
  |     UPSERT effectivePermissions {
  |       permission: "documents:read", effect: "allow",
  |       sources: ["editor"], policyResult: null
  |     }
  |-- 5. For "documents:update" (deferred policy):
  |     UPSERT effectivePermissions {
  |       permission: "documents:update", effect: "allow",
  |       sources: ["editor"], policyResult: "deferred",
  |       policyName: "documents:update"
  |     }
  |-- 6. INSERT auditLog { action: "role_assigned", ... }
  |
  v
Return assignmentId to client
```

### 9.3 Write Flow: `setAttribute(ctx, userId, "department", "sales")`

```
Client code
  |
  v
Authz.setAttribute(ctx, userId, "department", "sales")
  |
  |-- validate inputs
  |-- identify which static policies exist
  |
  v
ctx.runMutation(component.unified.setAttributeWithRecompute, {
  tenantId, userId, key: "department", value: "sales",
  staticPolicies: ["documents:delete"],  // policies that reference attributes
  rolePermissionsMap: { admin: [...], editor: [...] }
})
  |
  v
[Component Mutation Handler]
  |
  |-- 1. UPSERT userAttributes { tenantId, userId, key:"department", value:"sales" }
  |-- 2. Load all effectivePermissions where policyName in staticPolicies
  |-- 3. For each, re-evaluate:
  |     policy = lookup("documents:delete")
  |     attrs = loadAttributes(userId)  // includes new "department"="sales"
  |     roles = loadRoles(userId)
  |     result = policy.condition({ subject: { userId, roles, attributes: attrs }, ... })
  |     if result changed: patch effectivePermissions
  |-- 4. INSERT auditLog { action: "attribute_set", ... }
```

---

## 10. Migration Strategy

### 10.1 For `Authz` Users (Standard/Non-Indexed)

Current `Authz` users have data in:
- `roleAssignments` (populated)
- `userAttributes` (populated)
- `permissionOverrides` (populated)
- `effectivePermissions` / `effectiveRoles` / `effectiveRelationships` (EMPTY)

**Migration steps:**

1. **Schema migration**: Deploy v2 schema (adds new columns, new audit actions). No existing data needs to change -- new columns are optional.

2. **Backfill effective tables**: Run a one-time `recomputeAllUsers()` mutation that:
   - For each user in `roleAssignments`:
     - Resolves all role permissions via `flattenRolePermissions`
     - Evaluates static policies
     - Populates `effectiveRoles` and `effectivePermissions`
   - For each relationship in `relationships`:
     - Populates `effectiveRelationships` with transitive closure

3. **Swap client class**:
   ```typescript
   // Before (v1)
   import { Authz } from "@djpanda/convex-authz";
   const authz = new Authz(components.authz, { permissions, roles, tenantId: "app" });

   // After (v2) -- same import, same class name, same constructor
   import { Authz } from "@djpanda/convex-authz";
   const authz = new Authz(components.authz, {
     permissions, roles, tenantId: "app",
     policies,               // optional, same as before
     traversalRules,          // optional, new
     relationPermissions,     // optional, new
   });
   ```

4. **API compatibility**: All existing `Authz` methods remain with the same signatures. The `can()` method now reads from `effectivePermissions` instead of scanning `roleAssignments` + `permissionOverrides` at query time.

### 10.2 For `IndexedAuthz` Users

Current `IndexedAuthz` users have data in:
- `effectiveRoles` (populated)
- `effectivePermissions` (populated)
- `effectiveRelationships` (populated)
- `roleAssignments` (EMPTY -- IndexedAuthz writes directly to effective tables)

**Migration steps:**

1. **Backfill source-of-truth tables**: Run a migration that:
   - For each row in `effectiveRoles`: insert a corresponding `roleAssignment` row
   - For each row in `effectiveRelationships` where `isDirect=true`: insert a `relationships` row
   - For each row in `effectivePermissions` where `directGrant=true`: insert a `permissionOverrides` row

2. **Swap client class**:
   ```typescript
   // Before (v1)
   import { IndexedAuthz } from "@djpanda/convex-authz";
   const authz = new IndexedAuthz(components.authz, { permissions, roles, tenantId: "app" });

   // After (v2)
   import { Authz } from "@djpanda/convex-authz";
   const authz = new Authz(components.authz, { permissions, roles, tenantId: "app" });
   ```

3. **API changes**:
   - `hasRelation(subjectType, subjectId, relation, objectType, objectId)` changes to `hasRelation({ type, id }, relation, { type, id })`.
   - `addRelation` / `removeRelation` similarly use objects instead of positional strings.
   - Everything else is compatible.

### 10.3 Deprecation Timeline

```
v1.x (current)  -- Authz + IndexedAuthz both work
v2.0             -- Unified Authz class; IndexedAuthz re-exported as deprecated alias
v2.1             -- IndexedAuthz alias removed; migration guide published
```

### 10.4 Backward Compatibility Shim

```typescript
// v2 re-exports for backward compat
/** @deprecated Use Authz instead. IndexedAuthz is now unified into Authz. */
export const IndexedAuthz = Authz;
```

---

## 11. Component API Surface (Server-Side)

The component exposes these Convex functions, consolidated from the current `queries.ts`, `indexed.ts`, `rebac.ts`, and `mutations.ts`:

```
component/
  unified.ts        -- all query + mutation handlers (replaces queries.ts + indexed.ts)
    checkPermission        (query)  -- O(1) with optional deferred policy eval
    checkPermissions       (query)  -- batch canAny
    hasRole                (query)  -- O(1)
    hasRelation            (query)  -- O(1)
    getUserPermissions     (query)
    getUserRoles           (query)
    getUserAttributes      (query)
    getUserAttribute       (query)
    getUsersWithRole       (query)
    getAuditLog            (query)

    assignRoleWithCompute       (mutation)  -- write role + recompute
    revokeRoleWithCompute       (mutation)
    assignRolesWithCompute      (mutation)  -- batch
    revokeRolesWithCompute      (mutation)  -- batch
    grantPermissionDirect       (mutation)
    denyPermissionDirect        (mutation)
    setAttributeWithRecompute   (mutation)  -- write attr + re-eval policies
    removeAttributeWithRecompute (mutation)
    addRelationWithCompute      (mutation)  -- write relation + transitive closure
    removeRelationWithCompute   (mutation)
    offboardUser                (mutation)
    deprovisionUser             (mutation)
    cleanupExpired              (mutation)
    recomputeUser               (mutation)  -- full recomputation for one user

  rebac.ts          -- kept for BFS traversal diagnostic
    checkRelationWithTraversal  (query)
    listAccessibleObjects       (query)
    listSubjectsWithAccess      (query)

  schema.ts         -- v2 schema (Section 3.2)
  helpers.ts        -- unchanged
  validators.ts     -- unchanged
```

---

## 12. Open Questions and Future Work

1. **Policy hot-reloading**: If a developer changes a policy condition in code and redeploys, all `policyResult = "allow"` entries computed under the old policy are stale. Solution: `recomputeAll()` as a post-deploy hook, or a version field on effectivePermissions that is compared to a policy version hash.

2. **Relation-to-permission mapping**: The `relationPermissions` config (e.g., "document:editor" -> ["documents:update"]) means that `addRelation` must also write to `effectivePermissions`. This crosses the RBAC/ReBAC boundary and needs careful design to avoid circular dependencies.

3. **Convex transaction limits**: A single `assignRole` that grants 50 permissions means 50+ writes in one mutation. Convex mutations have write limits. May need to batch into multiple mutations for large role definitions, or use an action that orchestrates multiple mutations.

4. **Consistency during recomputation**: When `setAttribute` triggers policy re-evaluation for many permissions, there is a window where some effectivePermissions are updated and others are not. Since Convex mutations are atomic, this is not an issue -- the entire re-evaluation happens in one transaction. But for very large re-evaluations, we may hit Convex limits.

5. **Wildcard permission materialization**: If a role grants `"documents:*"`, should we materialize one row with `permission = "documents:*"` and do pattern matching at read time, or expand to all known document actions? Current design: materialize the pattern as-is and do pattern matching at read time (current behavior preserved).
