# Unified Authz v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify `Authz` and `IndexedAuthz` into a single `Authz` class that provides O(1) reads, ABAC policy support (static + deferred), ReBAC for all users, and fixes critical production bugs.

**Architecture:** All writes go to source-of-truth tables AND materialized effective tables (pre-computed). All reads hit effective tables first (O(1)), with ABAC policies classified as "static" (evaluated at write time) or "deferred" (evaluated at read time). ReBAC transitive closure is pre-computed at write time into `effectiveRelationships`. The two current classes merge into one `Authz` class.

**Tech Stack:** Convex (serverless DB), TypeScript, vitest, convex-test

**Reference Documents:**
- Architecture: `ARCHITECTURE-V2.md` (in repo root)
- Current schema: `src/component/schema.ts` (177 lines, 8 tables)
- Current client: `src/client/index.ts` (1425 lines, Authz + IndexedAuthz)

**Critical Convex Constraints:**
- Query/mutation timeout: ~1 second
- db.query calls per transaction: 4,096
- Documents scanned per query: 16,384
- Documents written per mutation: 8,192
- Compound indexes require equality on all leading fields before range filters
- After creating/modifying component files, run `npm run build:codegen` to regenerate `_generated/api.ts` and `_generated/component.ts`

**Index Naming Convention:** Use the CURRENT schema index names (`by_tenant_user_and_role`, `by_tenant_user_and_key`, `by_tenant_user_and_permission` — with "and"). Do NOT use the ARCHITECTURE-V2.md shorthand names. All code in `unified.ts` must reference the actual deployed index names.

---

## Phase 0: Critical Bug Fixes (Pre-v2, ship immediately)

These are production-breaking issues in the current codebase that must be fixed before any v2 work.

### Task 0.1: Fix cleanup full-table-scan patterns

**Files:**
- Modify: `src/component/mutations.ts:1053-1282` (cleanupExpired, runScheduledCleanup, runAuditRetentionCleanup)
- Modify: `src/component/indexed.ts:958-1015` (indexed cleanupExpired)
- Test: `src/component/mutations.test.ts`

**Problem:** `runAuditRetentionCleanup` does `ctx.db.query("auditLog").collect()` — full table scan. At 50K+ rows this exceeds Convex's 16,384 document scan limit. Same issue in `runScheduledCleanup` (scans 4 tables) and `cleanupExpired` (scans 3 tables).

- [ ] **Step 1: Write failing test for batched cleanup**

```typescript
// In mutations.test.ts
test("runAuditRetentionCleanup handles large datasets via batched deletion", async () => {
  const t = convexTest(schema, import.meta.glob("./**/*.ts"));
  // Insert 100 old audit entries
  for (let i = 0; i < 100; i++) {
    await t.mutation(api.mutations.logPermissionCheck, {
      tenantId: TENANT,
      userId: "user1",
      permission: "docs:read",
      result: true,
      enableAudit: true,
    });
  }
  // Run cleanup with 0-day retention (delete all)
  const result = await t.mutation(api.mutations.runAuditRetentionCleanup, {
    retentionDays: 0,
  });
  expect(result).toBeGreaterThan(0);
});
```

- [ ] **Step 2: Run test to verify current behavior**

Run: `npx vitest run src/component/mutations.test.ts -t "runAuditRetentionCleanup" -v`

- [ ] **Step 3: Rewrite cleanup mutations to use batched deletion**

Replace full table scans with batched queries. **Convex constraint:** compound indexes require equality on all leading fields before range filters. The `by_tenant_timestamp` index is `["tenantId", "timestamp"]` — you CANNOT skip `tenantId` and range-filter on `timestamp` alone.

**When `tenantId` is provided** — use indexed query:
```typescript
const oldEntries = await ctx.db
  .query("auditLog")
  .withIndex("by_tenant_timestamp", (q) =>
    q.eq("tenantId", args.tenantId).lt("timestamp", cutoff)
  )
  .take(BATCH_SIZE);
```

**When `tenantId` is omitted** (global cleanup) — use `.order("asc").take(BATCH_SIZE)` on the full table (scans oldest-first, bounded by BATCH_SIZE):
```typescript
const oldEntries = await ctx.db
  .query("auditLog")
  .order("asc")
  .take(BATCH_SIZE);
// Then filter in-memory: only delete entries where timestamp < cutoff
```

Use `BATCH_SIZE = 1000` to stay well within the 16,384 scan limit. Apply same pattern to `cleanupExpired` and `runScheduledCleanup`.

Also update `MAX_BULK_ROLES` in **both** `src/client/validation.ts` AND `src/component/indexed.ts` (line 66) — they are separate constants.

- [ ] **Step 4: Run tests to verify fix**

Run: `npx vitest run src/component/mutations.test.ts -v`
Expected: All cleanup tests pass.

- [ ] **Step 5: Fix indexed.cleanupExpired — uses args, optional tenantId**

In `src/component/indexed.ts`, fix the handler signature from `handler: async (ctx) =>` to `handler: async (ctx, args) =>`, change `tenantId: v.string()` to `tenantId: v.optional(v.string())`, and add tenant filtering with batched deletion.

- [ ] **Step 6: Run indexed tests**

Run: `npx vitest run src/component/indexed.test.ts -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/component/mutations.ts src/component/indexed.ts src/component/mutations.test.ts
git commit -m "fix: replace full-table-scan cleanup with batched index-based deletion

Prevents Convex 16,384 document scan limit from being hit at scale.
Cleanup mutations now use take(BATCH_SIZE) with index queries."
```

### Task 0.2: Add branching limit to ReBAC traversal

**Files:**
- Modify: `src/component/rebac.ts:242-410` (checkRelationWithTraversal)
- Test: `src/component/rebac.test.ts`

**Problem:** BFS traversal with branching factor 10 at depth 5 does 22,222 db.query calls, exceeding Convex's 4,096 limit.

- [ ] **Step 1: Write failing test for branching limit**

```typescript
test("checkRelationWithTraversal respects maxBranching limit", async () => {
  const t = convexTest(schema, import.meta.glob("./**/*.ts"));
  // Create a wide graph: user1 -> 20 teams, each team -> 1 org
  for (let i = 0; i < 20; i++) {
    await t.mutation(api.rebac.addRelation, {
      tenantId: TENANT,
      subjectType: "user", subjectId: "user1",
      relation: "member", objectType: "team", objectId: `team${i}`,
    });
  }
  const result = await t.query(api.rebac.checkRelationWithTraversal, {
    tenantId: TENANT,
    subjectType: "user", subjectId: "user1",
    relation: "member", objectType: "team", objectId: "team0",
    maxDepth: 3, maxBranching: 10,
  });
  expect(result.allowed).toBe(true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/component/rebac.test.ts -t "maxBranching" -v`
Expected: FAIL (maxBranching arg not recognized)

- [ ] **Step 3: Add maxBranching parameter to checkRelationWithTraversal**

In `rebac.ts`, add `maxBranching: v.optional(v.number())` to args (default 50). In the BFS loop, after collecting child nodes, limit to `args.maxBranching` results using `.take(maxBranching)` instead of `.collect()`.

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/component/rebac.test.ts -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/component/rebac.ts src/component/rebac.test.ts
git commit -m "fix: add maxBranching limit to ReBAC traversal

Prevents exceeding Convex 4,096 db.query call limit on wide graphs.
Default maxBranching=50."
```

### Task 0.3: Cap bulk operations to prevent transaction limit overflows

**Files:**
- Modify: `src/component/indexed.ts:368-481` (assignRolesWithCompute)
- Modify: `src/client/validation.ts` (MAX_BULK_ROLES)
- Test: `src/component/indexed.test.ts`

**Problem:** 100 roles × 50 permissions = 5,000 db.query calls, exceeding 4,096 limit.

- [ ] **Step 1: Reduce MAX_BULK_ROLES from 100 to 20**

In `src/client/validation.ts`, change:
```typescript
export const MAX_BULK_ROLES = 20;
```

- [ ] **Step 2: Add a comment explaining the limit**

```typescript
/**
 * Max roles per bulk operation. Kept at 20 to stay within Convex's
 * 4,096 db.query call limit (20 roles × ~100 permission lookups each = 2,000).
 */
export const MAX_BULK_ROLES = 20;
```

- [ ] **Step 3: Run all tests to verify nothing breaks**

Run: `npx vitest run -v`
Expected: PASS (existing tests use fewer than 20 roles)

- [ ] **Step 4: Commit**

```bash
git add src/client/validation.ts
git commit -m "fix: cap MAX_BULK_ROLES at 20 to prevent Convex transaction limit overflow"
```

---

## Phase 1: Schema Evolution

### Task 1.1: Add v2 fields to existing tables

**Files:**
- Modify: `src/component/schema.ts`
- Test: `src/component/authz.test.ts` (verify schema loads)

**Problem:** effectivePermissions needs `policyResult`/`policyName` for ABAC classification. relationships needs `caveat`/`caveatContext` for conditional edges. effectiveRelationships needs `depth`.

- [ ] **Step 1: Add new fields to schema**

In `src/component/schema.ts`, add to `relationships` table:
```typescript
caveat: v.optional(v.string()),
caveatContext: v.optional(v.any()),
```

Add to `effectivePermissions` table:
```typescript
policyResult: v.optional(v.union(
  v.literal("allow"),
  v.literal("deny"),
  v.literal("deferred"),
)),
policyName: v.optional(v.string()),
```

Add to `effectiveRelationships` table:
```typescript
depth: v.optional(v.number()),
```

Add to `auditLog` action union:
```typescript
v.literal("relation_added"),
v.literal("relation_removed"),
v.literal("policy_evaluated"),
```

- [ ] **Step 2: Run all tests to verify backward compatibility**

Run: `npx vitest run -v`
Expected: PASS (new fields are all optional, existing tests unaffected)

- [ ] **Step 3: Commit**

```bash
git add src/component/schema.ts
git commit -m "feat: add v2 schema fields for ABAC policies and caveats

- effectivePermissions: policyResult, policyName
- relationships: caveat, caveatContext
- effectiveRelationships: depth
- auditLog: relation_added, relation_removed, policy_evaluated actions"
```

---

## Phase 2: Unified Permission Resolution Engine

### Task 2.1: Create unified.ts with tiered checkPermission query

**Files:**
- Create: `src/component/unified.ts`
- Test: `src/component/unified.test.ts`

This is the core of v2 — a single `checkPermission` query that uses the tiered resolution algorithm.

- [ ] **Step 1: Write failing test for tiered O(1) permission check**

```typescript
// src/component/unified.test.ts
import { convexTest } from "convex-test";
import schema from "./schema.js";
import { api } from "./_generated/api.js";
import { describe, test, expect } from "vitest";

const TENANT = "test-tenant";

describe("unified checkPermission", () => {
  test("returns allowed=true from effectivePermissions cache (Tier 1)", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));

    // Pre-populate effectivePermissions directly
    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "alice",
        permission: "documents:read",
        scopeKey: "global",
        effect: "allow",
        sources: ["editor"],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe("cached");
  });

  test("returns allowed=false when no permission exists", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(result.allowed).toBe(false);
  });

  test("deny override takes precedence over cached allow (Layer 0)", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));

    await t.run(async (ctx) => {
      // Cached allow
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT, userId: "alice",
        permission: "documents:read", scopeKey: "global",
        effect: "allow", sources: ["editor"],
        createdAt: Date.now(), updatedAt: Date.now(),
      });
      // Deny override
      await ctx.db.insert("permissionOverrides", {
        tenantId: TENANT, userId: "alice",
        permission: "documents:read", effect: "deny",
      });
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe("override");
  });

  test("deferred policy result triggers policy evaluation info", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));

    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT, userId: "alice",
        permission: "billing:export", scopeKey: "global",
        effect: "allow", sources: ["admin"],
        policyResult: "deferred", policyName: "billing:export",
        createdAt: Date.now(), updatedAt: Date.now(),
      });
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "billing:export",
    });

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe("deferred");
    expect(result.policyName).toBe("billing:export");
  });

  test("expired effectivePermission returns false", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));

    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT, userId: "alice",
        permission: "documents:read", scopeKey: "global",
        effect: "allow", sources: ["editor"],
        expiresAt: Date.now() - 1000, // expired
        createdAt: Date.now(), updatedAt: Date.now(),
      });
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });

    expect(result.allowed).toBe(false);
  });
});
```

- [ ] **Step 2: Regenerate Convex component types**

Run: `npm run build:codegen`

This regenerates `_generated/api.ts` and `_generated/component.ts` to include the new `unified` module. Without this step, `api.unified.*` does not exist and tests will fail with module resolution errors, not useful test failures. **Run this after creating any new `.ts` file in `src/component/`.**

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run src/component/unified.test.ts -v`
Expected: FAIL (function not implemented)

- [ ] **Step 4: Implement unified checkPermission query**

Create `src/component/unified.ts`.

**Design note:** No live override check ("Layer 0"). Permission overrides are materialized into `effectivePermissions` at write time (via `grantPermissionUnified`/`denyPermissionUnified` with `directGrant=true`/`directDeny=true`). This preserves the O(1) guarantee — every `can()` call does exactly 1 indexed lookup (exact match) or 1 range query (wildcard fallback). Trust the dual-write invariant.

```typescript
import { v } from "convex/values";
import { query, mutation } from "./_generated/server.js";
import { scopeValidator } from "./validators.js";
import { isExpired, matchesPermissionPattern } from "./helpers.js";

export const checkPermission = query({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    scope: scopeValidator,
  },
  returns: v.object({
    allowed: v.boolean(),
    reason: v.string(),
    tier: v.string(),
    policyName: v.optional(v.string()),
  }),
  handler: async (ctx, args) => {
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    // Tier 1: O(1) exact lookup in effectivePermissions
    // Overrides are already materialized here with directGrant/directDeny flags
    const cached = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user_permission_scope", (q) =>
        q.eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("permission", args.permission)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (cached && !isExpired(cached.expiresAt)) {
      if (cached.effect === "deny") {
        return { allowed: false, reason: "Denied", tier: "cached" };
      }
      if (cached.effect === "allow") {
        if (!cached.policyResult || cached.policyResult === "allow") {
          return {
            allowed: true,
            reason: `Granted by: ${cached.sources.join(", ")}`,
            tier: "cached",
          };
        }
        if (cached.policyResult === "deferred") {
          return {
            allowed: true,
            reason: `Granted (policy deferred): ${cached.sources.join(", ")}`,
            tier: "deferred",
            policyName: cached.policyName ?? undefined,
          };
        }
        if (cached.policyResult === "deny") {
          return { allowed: false, reason: "Denied by static policy", tier: "cached" };
        }
      }
    }

    // Wildcard fallback: check patterns in effectivePermissions
    const allPerms = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user_scope", (q) =>
        q.eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("scopeKey", scopeKey)
      )
      .collect();

    // Deny patterns first (deny wins)
    for (const p of allPerms) {
      if (isExpired(p.expiresAt)) continue;
      if (p.effect === "deny" && matchesPermissionPattern(args.permission, p.permission)) {
        return { allowed: false, reason: `Denied by pattern: ${p.permission}`, tier: "cached" };
      }
    }
    // Allow patterns
    for (const p of allPerms) {
      if (isExpired(p.expiresAt)) continue;
      if (p.effect === "allow" && matchesPermissionPattern(args.permission, p.permission)) {
        if (!p.policyResult || p.policyResult === "allow") {
          return { allowed: true, reason: `Granted by pattern: ${p.permission}`, tier: "cached" };
        }
        if (p.policyResult === "deferred") {
          return {
            allowed: true,
            reason: `Granted by pattern (policy deferred)`,
            tier: "deferred",
            policyName: p.policyName ?? undefined,
          };
        }
      }
    }

    return { allowed: false, reason: "No permission granted", tier: "none" };
  },
});
```

- [ ] **Step 5: Run tests**

Run: `npx vitest run src/component/unified.test.ts -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/component/unified.ts src/component/unified.test.ts
git commit -m "feat: add unified tiered checkPermission query

Tier 1: O(1) effectivePermissions cache lookup
Deferred: signals client to evaluate ABAC policy
Wildcard: pattern fallback for docs:* style permissions"
```

### Task 2.2: Add unified write mutations (assignRoleWithCompute that writes to BOTH source + effective tables)

**Files:**
- Modify: `src/component/unified.ts` (add mutations)
- Test: `src/component/unified.test.ts`

The current `IndexedAuthz.assignRole` writes only to effective tables. The current `Authz.assignRole` writes only to source tables. The unified mutation writes to both.

- [ ] **Step 1: Write failing test for unified assignRole**

```typescript
test("assignRoleUnified writes to both roleAssignments and effectivePermissions", async () => {
  const t = convexTest(schema, import.meta.glob("./**/*.ts"));

  const assignmentId = await t.mutation(api.unified.assignRoleUnified, {
    tenantId: TENANT,
    userId: "alice",
    role: "editor",
    rolePermissions: ["documents:read", "documents:update"],
  });

  expect(assignmentId).toBeTruthy();

  // Verify source table has the assignment
  const roles = await t.run(async (ctx) => {
    return ctx.db
      .query("roleAssignments")
      .withIndex("by_tenant_user", (q) => q.eq("tenantId", TENANT).eq("userId", "alice"))
      .collect();
  });
  expect(roles).toHaveLength(1);
  expect(roles[0].role).toBe("editor");

  // Verify effective tables are populated
  const effective = await t.run(async (ctx) => {
    return ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user", (q) => q.eq("tenantId", TENANT).eq("userId", "alice"))
      .collect();
  });
  expect(effective).toHaveLength(2);
  expect(effective.map((e) => e.permission).sort()).toEqual(["documents:read", "documents:update"]);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/component/unified.test.ts -t "assignRoleUnified" -v`
Expected: FAIL

- [ ] **Step 3: Implement assignRoleUnified mutation**

Add to `src/component/unified.ts`:

```typescript
export const assignRoleUnified = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    role: v.string(),
    rolePermissions: v.array(v.string()),
    scope: scopeValidator,
    expiresAt: v.optional(v.number()),
    assignedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
    // v2: policy classifications from client
    policyClassifications: v.optional(v.record(v.string(), v.union(
      v.null(),
      v.literal("allow"),
      v.literal("deny"),
      v.literal("deferred"),
    ))),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";
    const now = Date.now();

    // 1. Check duplicate in source table
    const existing = await ctx.db
      .query("roleAssignments")
      .withIndex("by_tenant_user_and_role", (q) =>
        q.eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("role", args.role)
      )
      .collect();

    for (const e of existing) {
      if (matchesScope(e.scope, args.scope) && !isExpired(e.expiresAt)) {
        return e._id as string;
      }
    }

    // 2. Write to source table
    const assignmentId = await ctx.db.insert("roleAssignments", {
      tenantId: args.tenantId,
      userId: args.userId,
      role: args.role,
      scope: args.scope,
      expiresAt: args.expiresAt,
      assignedBy: args.assignedBy,
    });

    // 3. Upsert effectiveRoles
    const existingEffRole = await ctx.db
      .query("effectiveRoles")
      .withIndex("by_tenant_user_role_scope", (q) =>
        q.eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("role", args.role)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (existingEffRole) {
      await ctx.db.patch(existingEffRole._id, {
        expiresAt: args.expiresAt,
        updatedAt: now,
      });
    } else {
      await ctx.db.insert("effectiveRoles", {
        tenantId: args.tenantId,
        userId: args.userId,
        role: args.role,
        scopeKey,
        scope: args.scope,
        expiresAt: args.expiresAt,
        assignedBy: args.assignedBy,
        createdAt: now,
        updatedAt: now,
      });
    }

    // 4. Upsert effectivePermissions for each permission
    for (const permission of args.rolePermissions) {
      const policyResult = args.policyClassifications?.[permission] ?? null;

      // Skip permissions where static policy evaluated to deny
      if (policyResult === "deny") continue;

      const existingPerm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q.eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("permission", permission)
            .eq("scopeKey", scopeKey)
        )
        .unique();

      if (existingPerm) {
        const sources = existingPerm.sources.includes(args.role)
          ? existingPerm.sources
          : [...existingPerm.sources, args.role];
        await ctx.db.patch(existingPerm._id, { sources, updatedAt: now });
      } else {
        await ctx.db.insert("effectivePermissions", {
          tenantId: args.tenantId,
          userId: args.userId,
          permission,
          scopeKey,
          scope: args.scope,
          effect: "allow",
          sources: [args.role],
          policyResult: policyResult === "allow" ? "allow" : policyResult === "deferred" ? "deferred" : undefined,
          policyName: policyResult === "deferred" ? permission : undefined,
          createdAt: now,
          updatedAt: now,
        });
      }
    }

    // 5. Audit
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: now,
        action: "role_assigned",
        userId: args.userId,
        actorId: args.assignedBy,
        details: {
          role: args.role,
          scope: args.scope,
        },
      });
    }

    return assignmentId as string;
  },
});
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/component/unified.test.ts -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/component/unified.ts src/component/unified.test.ts
git commit -m "feat: add unified assignRoleUnified mutation

Writes to both source (roleAssignments) and effective
(effectiveRoles, effectivePermissions) tables in one transaction.
Supports static/deferred policy classification from client."
```

### Task 2.3: Add revokeRoleUnified, grantPermissionUnified, denyPermissionUnified

**Files:**
- Modify: `src/component/unified.ts`
- Test: `src/component/unified.test.ts`

Follow the same dual-write pattern. On revoke, remove role from `sources` array; if `sources` becomes empty and no `directGrant`, delete the effectivePermissions row.

- [ ] **Step 1: Write failing tests for revoke**

Test that revoking a role removes it from source AND effective tables. Test that revoking one of two roles that grant the same permission only removes the role from `sources`, not the permission.

- [ ] **Step 2: Implement revokeRoleUnified**
- [ ] **Step 3: Write failing tests for grantPermissionUnified and denyPermissionUnified**

Test that direct grants write to both permissionOverrides AND effectivePermissions with `directGrant=true`. Test that deny writes with `directDeny=true` and `effect="deny"`.

- [ ] **Step 4: Implement grantPermissionUnified and denyPermissionUnified**
- [ ] **Step 5: Run all tests**

Run: `npx vitest run src/component/unified.test.ts -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/component/unified.ts src/component/unified.test.ts
git commit -m "feat: add revokeRoleUnified, grantPermissionUnified, denyPermissionUnified"
```

### Task 2.4: Add setAttributeWithRecompute mutation

**Files:**
- Modify: `src/component/unified.ts`
- Test: `src/component/unified.test.ts`

When an attribute changes, re-evaluate all static policies for that user. This is the key innovation: attributes trigger policy re-evaluation at write time.

- [ ] **Step 1: Write failing test**

Test that changing an attribute from "engineering" to "sales" flips a static policy result on the user's effectivePermissions.

- [ ] **Step 2: Implement setAttributeWithRecompute**

The mutation accepts `staticPolicyNames: string[]` (which permissions have static policies) and `rolePermissionsMap` from the client. It writes the attribute, then for each effectivePermission row where `policyName` is in `staticPolicyNames`, it re-evaluates by calling an internal helper.

Note: The actual policy function lives in client code (JS), not in the component. The component mutation receives the policy evaluation results from the client layer. The client calls the mutation with pre-evaluated results.

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git add src/component/unified.ts src/component/unified.test.ts
git commit -m "feat: add setAttributeWithRecompute for static policy re-evaluation"
```

### Task 2.5: Add addRelationUnified and removeRelationUnified mutations

**Files:**
- Modify: `src/component/unified.ts`
- Test: `src/component/unified.test.ts`

Write-time transitive closure: when a relationship is added, pre-compute inherited relationships into `effectiveRelationships` using BFS with cycle detection and max depth. The existing `rebac.addRelation` only writes to `relationships` (source table). The unified mutation writes to both `relationships` AND `effectiveRelationships`.

- [ ] **Step 1: Write failing test for addRelationUnified**

Test that adding a relation writes to both `relationships` and `effectiveRelationships` (with `isDirect=true`).

- [ ] **Step 2: Implement addRelationUnified**

Port the transitive closure logic from `indexed.addRelationWithCompute` but also write to the source `relationships` table. Include `caveat`/`caveatContext` support.

- [ ] **Step 3: Write failing test for removeRelationUnified**

Test that removing a relation cascade-deletes inherited `effectiveRelationships` entries.

- [ ] **Step 4: Implement removeRelationUnified**
- [ ] **Step 5: Run tests and commit**

```bash
git add src/component/unified.ts src/component/unified.test.ts
git commit -m "feat: add addRelationUnified/removeRelationUnified with write-time transitive closure"
```

### Task 2.6: Add recomputeUser mutation

**Files:**
- Modify: `src/component/unified.ts`
- Test: `src/component/unified.test.ts`

Full recomputation of all effective tables for a user. Called after deploy when role definitions change, or to fix inconsistencies.

**Design:** The role→permission mapping lives in client code (`defineRoles`), not in the DB. The `recomputeUser` mutation must accept `rolePermissionsMap: v.record(v.string(), v.array(v.string()))` as an argument — the client wrapper `Authz.recomputeUser()` builds this via `buildRolePermissionsMap()` before calling the mutation. This follows the same pattern already established in `indexed.ts` (`assignRoleWithCompute` takes `rolePermissions`).

- [ ] **Step 1: Write failing test**

```typescript
test("recomputeUser rebuilds effectivePermissions from roleAssignments", async () => {
  const t = convexTest(schema, import.meta.glob("./**/*.ts"));

  // Insert a role assignment directly (simulating existing data)
  await t.run(async (ctx) => {
    await ctx.db.insert("roleAssignments", {
      tenantId: TENANT, userId: "alice", role: "editor",
    });
  });

  // Recompute — should create effectiveRoles + effectivePermissions
  await t.mutation(api.unified.recomputeUser, {
    tenantId: TENANT,
    userId: "alice",
    rolePermissionsMap: { editor: ["documents:read", "documents:update"] },
  });

  // Verify effective tables populated
  const perms = await t.run(async (ctx) => {
    return ctx.db.query("effectivePermissions")
      .withIndex("by_tenant_user", (q) => q.eq("tenantId", TENANT).eq("userId", "alice"))
      .collect();
  });
  expect(perms).toHaveLength(2);
});
```

- [ ] **Step 2: Implement recomputeUser**

The mutation:
1. Reads all `roleAssignments` for user
2. Deletes all `effectiveRoles` and non-directGrant `effectivePermissions` for user
3. For each active role assignment, resolves permissions via `rolePermissionsMap` arg
4. Inserts fresh `effectiveRoles` and `effectivePermissions` rows

```typescript
export const recomputeUser = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    rolePermissionsMap: v.record(v.string(), v.array(v.string())),
    policyClassifications: v.optional(v.record(v.string(), v.union(
      v.null(), v.literal("allow"), v.literal("deny"), v.literal("deferred"),
    ))),
  },
  returns: v.null(),
  handler: async (ctx, args) => { /* implementation */ },
});
```

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git add src/component/unified.ts src/component/unified.test.ts
git commit -m "feat: add recomputeUser for post-deploy effective table rebuild

Accepts rolePermissionsMap from client (built via buildRolePermissionsMap).
Deletes stale effective entries and recomputes from source tables."
```

---

## Phase 3: Unified Client Class

### Task 3.1: Merge IndexedAuthz methods into Authz

**Files:**
- Modify: `src/client/index.ts`
- Test: `src/client/index.test.ts`

- [ ] **Step 1: Add ReBAC methods to Authz class**

Add `hasRelation`, `addRelation`, `removeRelation`, `listAccessibleObjects`, `listSubjectsWithAccess` to the `Authz` class. Use structured `{ type, id }` objects for subject/object params.

```typescript
async hasRelation(
  ctx: QueryCtx | ActionCtx,
  subject: { type: string; id: string },
  relation: string,
  object: { type: string; id: string },
): Promise<boolean> {
  validateTenantId(this.options.tenantId);
  return ctx.runQuery(this.component.indexed.hasRelationFast, {
    tenantId: this.options.tenantId,
    subjectType: subject.type,
    subjectId: subject.id,
    relation,
    objectType: object.type,
    objectId: object.id,
  });
}
```

- [ ] **Step 2: Write tests for ReBAC on Authz**
- [ ] **Step 3: Switch `can()` to use unified.checkPermission**

Change the `Authz.can()` method to call `this.component.unified.checkPermission` instead of `this.component.queries.checkPermission`. Add ABAC policy evaluation as a second layer when result.tier === "deferred".

- [ ] **Step 4: Add private `_checkPermission()` and `canWithContext()`**

**Design:** `can()` returns `boolean` but `canWithContext()` needs the `tier` and `policyName` metadata. Add a private `_checkPermission()` that returns the full result object. Both `can()` and `canWithContext()` use it internally.

```typescript
/** Internal: returns full result with tier metadata */
private async _checkPermission(
  ctx: QueryCtx | ActionCtx,
  userId: string,
  permission: string,
  scope?: Scope,
): Promise<{ allowed: boolean; tier: string; policyName?: string }> {
  return ctx.runQuery(this.component.unified.checkPermission, {
    tenantId: this.options.tenantId,
    userId, permission, scope,
  });
}

async can(ctx, userId, permission, scope?): Promise<boolean> {
  const result = await this._checkPermission(ctx, userId, permission, scope);
  if (!result.allowed) return false;
  // For deferred policies, evaluate with empty context
  if (result.tier === "deferred" && this.options.policies) {
    return this._evaluateDeferredPolicy(ctx, userId, result.policyName, scope);
  }
  return true;
}

async canWithContext(
  ctx: QueryCtx | ActionCtx,
  userId: string,
  permission: string,
  scope?: Scope,
  requestContext?: Record<string, unknown>,
): Promise<boolean> {
  const result = await this._checkPermission(ctx, userId, permission, scope);
  if (!result.allowed) return false;
  if (result.tier === "deferred" && this.options.policies) {
    return this._evaluateDeferredPolicy(ctx, userId, result.policyName, scope, requestContext);
  }
  return true;
}
```

- [ ] **Step 5: Switch write methods to use unified mutations**

Change `assignRole` to call `unified.assignRoleUnified`, passing `rolePermissions` from `flattenRolePermissions()` and `policyClassifications` from evaluating static policies.

- [ ] **Step 6: Run all client tests**

Run: `npx vitest run src/client/index.test.ts -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/client/index.ts src/client/index.test.ts
git commit -m "feat: merge IndexedAuthz capabilities into Authz class

- ReBAC methods (hasRelation, addRelation, removeRelation) now on Authz
- can() uses unified tiered checkPermission (O(1) by default)
- canWithContext() for deferred ABAC policies
- Write methods use unified dual-write mutations"
```

### Task 3.2: Deprecate IndexedAuthz

**Files:**
- Modify: `src/client/index.ts`
- Test: `src/client/index.test.ts`

- [ ] **Step 1: Replace IndexedAuthz class with deprecated alias**

```typescript
/**
 * @deprecated Use `Authz` instead. `IndexedAuthz` is now unified into `Authz`.
 * Will be removed in v2.1.
 */
export const IndexedAuthz = Authz;
```

- [ ] **Step 2: Update IndexedAuthz tests to use Authz**

Change all `new IndexedAuthz(...)` to `new Authz(...)` in test files. Verify they pass.

- [ ] **Step 3: Run all tests**

Run: `npx vitest run -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/client/index.ts src/client/index.test.ts
git commit -m "deprecate: IndexedAuthz re-exported as alias for Authz

IndexedAuthz is now a deprecated alias. All functionality is in Authz.
Will be removed in v2.1."
```

### Task 3.3: Add new constructor options and definition helpers

**Files:**
- Modify: `src/client/index.ts`
- Test: `src/client/index.test.ts`

- [ ] **Step 1: Add policy type classification to definePolicies**

```typescript
export type PolicyDefinition = Record<string, {
  type?: "static" | "deferred";  // default: "static"
  condition: (ctx: PolicyContext) => boolean | Promise<boolean>;
  message?: string;
}>;
```

- [ ] **Step 2: Add new constructor options**

```typescript
constructor(component: ComponentApi, options: {
  permissions: P;
  roles: R;
  policies?: Policy;
  tenantId: string;
  defaultActorId?: string;
  // v2:
  traversalRules?: TraversalRules;
  relationPermissions?: RelationPermissionMap;
  caveats?: Record<string, CaveatFunction>;
})
```

- [ ] **Step 3: Add definition helpers**

```typescript
export function defineTraversalRules(rules: TraversalRules): TraversalRules { return rules; }
export function defineRelationPermissions(map: RelationPermissionMap): RelationPermissionMap { return map; }
export function defineCaveats(caveats: Record<string, CaveatFunction>): Record<string, CaveatFunction> { return caveats; }
```

- [ ] **Step 4: Write tests for new helpers**
- [ ] **Step 5: Run all tests**
- [ ] **Step 6: Commit**

```bash
git add src/client/index.ts src/client/index.test.ts
git commit -m "feat: add v2 constructor options and definition helpers

- definePolicies now supports type: 'static' | 'deferred'
- defineTraversalRules, defineRelationPermissions, defineCaveats helpers
- New constructor options: traversalRules, relationPermissions, caveats"
```

---

## Phase 4: Integration Tests

### Task 4.1: End-to-end tests for the unified path

**Files:**
- Create: `src/component/unified-e2e.test.ts`

- [ ] **Step 1: Write full lifecycle test**

Test: create Authz with permissions/roles/policies → assignRole → can() returns true via O(1) → revokeRole → can() returns false → verify source + effective tables are consistent.

- [ ] **Step 2: Write ABAC static policy test**

Test: define static policy (department == "engineering") → assignRole → can() returns true → setAttribute(department, "sales") → can() returns false (policy re-evaluated at write time).

- [ ] **Step 3: Write ABAC deferred policy test**

Test: define deferred policy (business hours) → assignRole → can() returns result with tier="deferred" → canWithContext() evaluates policy.

- [ ] **Step 4: Write ReBAC + RBAC unified test**

Test: same Authz instance can do assignRole + addRelation + can + hasRelation.

- [ ] **Step 5: Run all tests**

Run: `npx vitest run -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/component/unified-e2e.test.ts
git commit -m "test: add end-to-end tests for unified Authz v2 path"
```

### Task 4.2: Deprecate old component functions

**Files:**
- Modify: `src/component/queries.ts`
- Modify: `src/component/indexed.ts`
- Modify: `src/component/rebac.ts`

**Problem:** After Phase 3, both `queries.checkPermission` AND `unified.checkPermission` exist as deployed component functions. Old functions write only to source tables (mutations.ts) or only to effective tables (indexed.ts), bypassing the dual-write invariant. They must be marked internal or removed.

- [ ] **Step 1: Change old queries/indexed/rebac exports to internalQuery/internalMutation**

Replace `query` with `internalQuery` and `mutation` with `internalMutation` for all functions in `queries.ts`, `indexed.ts`, and `rebac.ts` that are superseded by `unified.ts`. This removes them from the public component API while keeping them callable internally (e.g., for backward compat shims or tests).

Keep `rebac.checkRelationWithTraversal` as a public query (diagnostic/fallback tool).

- [ ] **Step 2: Run all tests to verify nothing breaks**

Run: `npx vitest run -v`

Note: Some existing tests may reference `api.queries.*` or `api.indexed.*` — update them to use `internal.queries.*` or `api.unified.*` as appropriate.

- [ ] **Step 3: Run `npm run build:codegen` to regenerate types**
- [ ] **Step 4: Commit**

```bash
git add src/component/queries.ts src/component/indexed.ts src/component/rebac.ts
git commit -m "refactor: mark old component functions as internal

Superseded by unified.ts. Prevents bypass of dual-write invariant."
```

---

## Phase 5: Documentation and Release

### Task 5.1: Update README, CHANGELOG, examples

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `example/convex/app.ts`
- Modify: `example/convex/example.ts`

- [ ] **Step 1: Add "Unified Authz v2" section to README**

Document: single class, O(1) reads, static vs deferred ABAC, ReBAC available to all, canWithContext, recomputeUser, migration from IndexedAuthz.

- [ ] **Step 2: Add CHANGELOG entry**

```markdown
## v2.0.0

### BREAKING CHANGES

- **`IndexedAuthz` deprecated**: Use `Authz` instead. All IndexedAuthz
  functionality is now built into the unified `Authz` class.
  `IndexedAuthz` is re-exported as a deprecated alias.

- **`Authz.can()` now reads from effectivePermissions**: Permission checks
  are always O(1). Existing `Authz` users must run `recomputeUser()` or
  `recomputeAllUsers()` to backfill effective tables after upgrading.

- **ReBAC methods use structured objects**: `hasRelation`, `addRelation`,
  `removeRelation` now take `{ type, id }` objects instead of positional
  string arguments.

### New features

- `canWithContext()` for deferred ABAC policies with request context
- `recomputeUser()` for post-deploy effective table rebuild
- Static vs deferred policy classification in `definePolicies`
- `defineTraversalRules`, `defineRelationPermissions`, `defineCaveats`
- Caveats on relationship edges (`caveat`/`caveatContext`)
- Batched cleanup mutations (prevent Convex scan limit overflow)
- `maxBranching` parameter on ReBAC traversal
```

- [ ] **Step 3: Update example files**

Replace `IndexedAuthz` with `Authz` in examples. Add `tenantId` if missing.

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md example/
git commit -m "docs: update README, CHANGELOG, and examples for v2.0"
```

### Task 5.2: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update architecture section**

Replace the "Two Client Classes" section with "Unified Authz Class" description. Add the tiered resolution algorithm. Update the key file map to include `unified.ts`.

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for v2 unified architecture"
```

---

## Implementation Order Summary

```
Phase 0 (bug fixes):   0.1, 0.2, 0.3             (independent, can parallelize)
Phase 1 (schema):      1.1                        (backward compatible, no code changes needed)
Phase 2 (engine):      2.1 → 2.2 → 2.3 → 2.4 → 2.5 → 2.6
Phase 3 (client):      3.1 → 3.2 → 3.3           (depends on Phase 2)
Phase 4 (tests):       4.1 → 4.2                  (depends on Phase 3)
Phase 5 (docs):        5.1 → 5.2                  (depends on Phase 4)
```

Phase 0 should be shipped as a patch release (v0.1.8) immediately.
Phases 1-5 ship together as v2.0.0.

**Codegen reminder:** Run `npm run build:codegen` after creating new `.ts` files in `src/component/` (Phase 2) and after changing exports from `query`→`internalQuery` (Phase 4, Task 4.2).
