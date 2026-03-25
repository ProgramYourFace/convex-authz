/**
 * Exhaustive end-to-end tests for the unified Authz v2 component — Batch 2
 *
 * Categories 6-10:
 *   6. Policy interactions
 *   7. Direct grant/deny vs role-based
 *   8. Wildcards
 *   9. ReBAC
 *  10. Cross-tenant isolation
 */

import { convexTest } from "convex-test";
import schema from "../schema.js";
import { api } from "../_generated/api.js";
import { describe, test, expect } from "vitest";

const modules = import.meta.glob("../**/*.ts");
const TENANT = "test-tenant";

// ============================================================================
// CATEGORY 6: Policy interactions
// ============================================================================

describe("Category 6: Policy interactions", () => {
  test("6.4 setAttribute allow -> restores previously denied permission", async () => {
    const t = convexTest(schema, modules);

    // Assign role with deferred policy
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
      policyClassifications: { "docs:read": "deferred" },
    });

    // Should be deferred (allowed)
    const r1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(r1.allowed).toBe(true);
    expect(r1.tier).toBe("deferred");

    // Policy re-evaluation: deny
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "status",
      value: "suspended",
      policyReEvaluations: { "docs:read": "deny" },
    });

    // Now denied
    const r2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(r2.allowed).toBe(false);

    // Policy re-evaluation: allow -> restores
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "status",
      value: "active",
      policyReEvaluations: { "docs:read": "allow" },
    });

    // Should be allowed again
    const r3 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(r3.allowed).toBe(true);
  });

  test("6.5 setAttribute with no policyReEvaluations -> only attribute changes", async () => {
    const t = convexTest(schema, modules);

    // Assign role with NO policy classification
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Should be allowed
    const r1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(r1.allowed).toBe(true);

    // setAttributeWithRecompute with no policyReEvaluations
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "department",
      value: "engineering",
    });

    // Permission should still be allowed
    const r2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(r2.allowed).toBe(true);
  });

  test("6.6 setAttribute on permission without policyResult -> applies deny", async () => {
    const t = convexTest(schema, modules);

    // Assign role with NO policy classification -> policyResult is undefined
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // setAttributeWithRecompute with policyReEvaluations targeting docs:read
    // Even though docs:read has policyResult === undefined, the broader filter
    // now matches by permission name so the deny is applied correctly.
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "status",
      value: "suspended",
      policyReEvaluations: { "docs:read": "deny" },
    });

    // Permission should now be denied (filter matches rows without policyResult)
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);
  });

  test("6.7 directGrant overrides policy deny", async () => {
    const t = convexTest(schema, modules);

    // Direct grant first
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Assign role with policy deny on docs:read (skips materialization)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
      policyClassifications: { "docs:read": "deny" },
    });

    // Direct grant was first, so docs:read should still be allowed
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(true);
  });

  test("6.8 recompute with policyClassifications deny -> skips denied", async () => {
    const t = convexTest(schema, modules);

    // Assign role with two permissions
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // Delete effective tables to force recompute
    await t.run(async (ctx) => {
      const perms = await ctx.db.query("effectivePermissions").collect();
      for (const p of perms) await ctx.db.delete(p._id);
      const roles = await ctx.db.query("effectiveRoles").collect();
      for (const r of roles) await ctx.db.delete(r._id);
    });

    // Recompute with policy deny on docs:read
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { editor: ["docs:read", "docs:write"] },
      policyClassifications: { "docs:read": "deny" },
    });

    // docs:read should be denied (skipped by recompute)
    const readResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(readResult.allowed).toBe(false);

    // docs:write should still be allowed
    const writeResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(writeResult.allowed).toBe(true);
  });

  test("6.9 recompute preserves directGrant even with policy deny", async () => {
    const t = convexTest(schema, modules);

    // Assign role with docs:read
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Grant docs:read directly (directGrant = true)
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Recompute with policy deny on docs:read
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { editor: ["docs:read"] },
      policyClassifications: { "docs:read": "deny" },
    });

    // Direct grant should be preserved -> allowed
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(true);
  });

  test("6.10 recompute with deferred policy -> policyResult=deferred in DB", async () => {
    const t = convexTest(schema, modules);

    // Assign role
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Delete effective tables
    await t.run(async (ctx) => {
      const perms = await ctx.db.query("effectivePermissions").collect();
      for (const p of perms) await ctx.db.delete(p._id);
      const roles = await ctx.db.query("effectiveRoles").collect();
      for (const r of roles) await ctx.db.delete(r._id);
    });

    // Recompute with deferred policy
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { editor: ["docs:read"] },
      policyClassifications: { "docs:read": "deferred" },
    });

    // checkPermission should return tier=deferred
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(true);
    expect(result.tier).toBe("deferred");
  });
});

// ============================================================================
// CATEGORY 7: Direct grant/deny vs role-based
// ============================================================================

describe("Category 7: Direct grant/deny vs role-based", () => {
  test("7.1 direct grant clears policyResult", async () => {
    const t = convexTest(schema, modules);

    // grantPermissionUnified sets directGrant=true, policyResult=undefined
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Verify in DB: policyResult should be undefined
    const row = await t.run(async (ctx) => {
      return ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q: any) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "docs:read")
            .eq("scopeKey", "global"),
        )
        .unique();
    });

    expect(row).not.toBeNull();
    expect(row!.directGrant).toBe(true);
    expect(row!.policyResult).toBeUndefined();
  });

  test("7.3 revoke role preserves direct grant", async () => {
    const t = convexTest(schema, modules);

    // Assign role with docs:read
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Grant docs:read directly
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Revoke the role
    await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Direct grant should keep it allowed
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(true);
  });

  test("7.5 direct grant then deny -> deny wins", async () => {
    const t = convexTest(schema, modules);

    // Grant
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Deny
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Should be denied
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);

    // Verify DB: directDeny=true, directGrant=undefined
    const row = await t.run(async (ctx) => {
      return ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q: any) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "docs:read")
            .eq("scopeKey", "global"),
        )
        .unique();
    });
    expect(row).not.toBeNull();
    expect(row!.directDeny).toBe(true);
    expect(row!.directGrant).toBeUndefined();
  });

  test("7.7 role + deny -> grant clears deny -> allowed", async () => {
    const t = convexTest(schema, modules);

    // Assign role
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Deny
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Verify denied
    const denied = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(denied.allowed).toBe(false);

    // Grant -> clears deny
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Should be allowed
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(true);
  });

  test("7.8 grant + role + revoke role -> grant survives; then deny -> denied", async () => {
    const t = convexTest(schema, modules);

    // Direct grant
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Assign role with same permission
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Revoke role
    await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Direct grant should survive
    const r1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(r1.allowed).toBe(true);

    // Now deny -> should be denied
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    const r2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(r2.allowed).toBe(false);
  });

  test("7.9 recomputeUser preserves direct deny", async () => {
    const t = convexTest(schema, modules);

    // Assign role
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Deny permission directly
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Recompute
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { editor: ["docs:read"] },
    });

    // Direct deny should be preserved
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);
  });
});

// ============================================================================
// CATEGORY 8: Wildcards
// ============================================================================

describe("Category 8: Wildcards", () => {
  test("8.3 full wildcard '*' grants any permission", async () => {
    const t = convexTest(schema, modules);

    // Assign role with wildcard permission
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "superadmin",
      rolePermissions: ["*"],
    });

    // Check any arbitrary permission
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "anything:anything",
    });
    expect(result.allowed).toBe(true);
  });

  test("8.4 full wildcard deny '*' blocks everything", async () => {
    const t = convexTest(schema, modules);

    // Assign role with docs:read
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Deny with wildcard
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "*",
    });

    // docs:read should be denied due to wildcard deny
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);
  });

  test("8.5 wildcard deny 'docs:*' + exact allow 'docs:read' -> denied", async () => {
    const t = convexTest(schema, modules);

    // Assign role with docs:read (exact)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["docs:read"],
    });

    // Deny with wildcard docs:*
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:*",
    });

    // docs:read should be denied (wildcard deny overrides exact allow)
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);
  });

  test("8.6 wildcard allow 'docs:*' + exact deny 'docs:delete' -> read allowed, delete denied", async () => {
    const t = convexTest(schema, modules);

    // Assign role with docs:* wildcard
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:*"],
    });

    // Deny docs:delete exactly
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
    });

    // docs:read -> allowed (wildcard covers it, exact deny is only for docs:delete)
    const readResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(readResult.allowed).toBe(true);

    // docs:delete -> denied (exact deny)
    const deleteResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
    });
    expect(deleteResult.allowed).toBe(false);
  });

  test("8.7 '*:read' grants docs:read and settings:read but not docs:write", async () => {
    const t = convexTest(schema, modules);

    // Assign role with *:read wildcard
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "reader",
      rolePermissions: ["*:read"],
    });

    // docs:read -> allowed
    const docsRead = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(docsRead.allowed).toBe(true);

    // settings:read -> allowed
    const settingsRead = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "settings:read",
    });
    expect(settingsRead.allowed).toBe(true);

    // docs:write -> denied
    const docsWrite = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(docsWrite.allowed).toBe(false);
  });

  test("8.8 '*:delete' deny blocks docs:delete and settings:delete but not docs:read", async () => {
    const t = convexTest(schema, modules);

    // Assign role with specific permissions
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:delete", "settings:delete"],
    });

    // Deny *:delete
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "*:delete",
    });

    // docs:read -> allowed
    const docsRead = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(docsRead.allowed).toBe(true);

    // docs:delete -> denied
    const docsDelete = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
    });
    expect(docsDelete.allowed).toBe(false);

    // settings:delete -> denied
    const settingsDelete = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "settings:delete",
    });
    expect(settingsDelete.allowed).toBe(false);
  });

  test("8.9 wildcard allow + wildcard deny same pattern -> denied", async () => {
    const t = convexTest(schema, modules);

    // Assign role with docs:* wildcard (allow)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:*"],
    });

    // Deny with same wildcard pattern docs:*
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:*",
    });

    // docs:read -> denied (deny wins)
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);
  });

  test("8.10 wildcard allow scope p1, wildcard deny scope p2 -> isolated", async () => {
    const t = convexTest(schema, modules);

    // Assign role with docs:* in scope p1
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:*"],
      scope: { type: "project", id: "p1" },
    });

    // Deny docs:* in scope p2
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:*",
      scope: { type: "project", id: "p2" },
    });

    // p1 docs:read -> allowed
    const p1Result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p1" },
    });
    expect(p1Result.allowed).toBe(true);

    // p2 docs:read -> denied
    const p2Result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p2" },
    });
    expect(p2Result.allowed).toBe(false);
  });

  test("8.11 wildcard with deferred policy -> tier=deferred", async () => {
    const t = convexTest(schema, modules);

    // Assign with docs:* and deferred policy on docs:*
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:*"],
      policyClassifications: { "docs:*": "deferred" },
    });

    // checkPermission for docs:read -> should match wildcard, tier=deferred
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(true);
    expect(result.tier).toBe("deferred");
  });
});

// ============================================================================
// CATEGORY 9: ReBAC
// ============================================================================

describe("Category 9: ReBAC", () => {
  test("9.3 idempotent add -> same ID, one row", async () => {
    const t = convexTest(schema, modules);

    // Add relation
    const id1 = await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Add same relation again
    const id2 = await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Same ID returned
    expect(id1).toBe(id2);

    // DB should have exactly 1 row in relationships
    const rows = await t.run(async (ctx) => {
      return ctx.db
        .query("relationships")
        .withIndex("by_tenant_subject_relation_object", (q: any) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectType", "user")
            .eq("subjectId", "alice")
            .eq("relation", "member")
            .eq("objectType", "team")
            .eq("objectId", "team1"),
        )
        .collect();
    });
    expect(rows.length).toBe(1);
  });

  test("9.4 add + remove + add -> exists again, new ID", async () => {
    const t = convexTest(schema, modules);

    // Add
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Remove
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Verify removed
    const mid = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(mid).toBe(false);

    // Add again
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Should exist again
    const result = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(result).toBe(true);
  });

  test("9.5 add + offboard(removeRelationships=true) -> gone", async () => {
    const t = convexTest(schema, modules);

    // Add relation
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Verify exists
    const before = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(before).toBe(true);

    // Offboard with removeRelationships
    await t.mutation(api.mutations.offboardUser, {
      tenantId: TENANT,
      userId: "alice",
      removeRelationships: true,
    });

    // Should be gone
    const after = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(after).toBe(false);
  });

  test("9.6 add + deprovision -> gone", async () => {
    const t = convexTest(schema, modules);

    // Add relation
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Deprovision
    await t.mutation(api.mutations.deprovisionUser, {
      tenantId: TENANT,
      userId: "alice",
    });

    // Should be gone from hasRelationFast
    const result = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(result).toBe(false);

    // Also verify source relationships table is empty
    const relationships = await t.run(async (ctx) => {
      return ctx.db
        .query("relationships")
        .withIndex("by_tenant_subject", (q: any) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectType", "user")
            .eq("subjectId", "alice"),
        )
        .collect();
    });
    expect(relationships.length).toBe(0);
  });

  test("9.7 multiple relations, remove one -> others preserved", async () => {
    const t = convexTest(schema, modules);

    // Add (alice, member, team1)
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Add (alice, admin, team1)
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "admin",
      objectType: "team",
      objectId: "team1",
    });

    // Add (alice, member, team2)
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team2",
    });

    // Remove (alice, member, team1)
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // (alice, admin, team1) should still exist
    const adminTeam1 = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "admin",
      objectType: "team",
      objectId: "team1",
    });
    expect(adminTeam1).toBe(true);

    // (alice, member, team2) should still exist
    const memberTeam2 = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team2",
    });
    expect(memberTeam2).toBe(true);

    // (alice, member, team1) should be gone
    const memberTeam1 = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(memberTeam1).toBe(false);
  });

  test("9.8 idempotent add repairs missing effectiveRelationships", async () => {
    const t = convexTest(schema, modules);

    // Add relation
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Verify exists
    const before = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(before).toBe(true);

    // Delete effectiveRelationships row directly (simulate corruption)
    await t.run(async (ctx) => {
      const rows = await ctx.db
        .query("effectiveRelationships")
        .withIndex("by_tenant_subject_relation_object", (q: any) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectKey", "user:alice")
            .eq("relation", "member")
            .eq("objectKey", "team:team1"),
        )
        .collect();
      for (const row of rows) {
        await ctx.db.delete(row._id);
      }
    });

    // hasRelationFast should now return false (effective table empty)
    const missing = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(missing).toBe(false);

    // Add same relation again -> should repair effectiveRelationships
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Should be repaired
    const repaired = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(repaired).toBe(true);
  });

  test("9.9 removeRelation cleans up inherited rows", async () => {
    const t = convexTest(schema, modules);

    // Add a direct relation
    const _relId = await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Get the relationships table ID (source of truth)
    // removeRelationUnified uses relationships._id for inheritedFrom lookups
    const sourceRelRow = await t.run(async (ctx) => {
      return ctx.db
        .query("relationships")
        .withIndex("by_tenant_subject_relation_object", (q: any) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectType", "user")
            .eq("subjectId", "alice")
            .eq("relation", "member")
            .eq("objectType", "team")
            .eq("objectId", "team1"),
        )
        .unique();
    });

    const sourceRow = await t.run(async (ctx) => {
      return ctx.db
        .query("effectiveRelationships")
        .withIndex("by_tenant_subject_relation_object", (q: any) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectKey", "user:alice")
            .eq("relation", "member")
            .eq("objectKey", "team:team1"),
        )
        .unique();
    });
    expect(sourceRow).not.toBeNull();
    expect(sourceRelRow).not.toBeNull();

    // Manually insert an inherited effectiveRelationship that points to the
    // source effectiveRelationships row ID (this is what removeRelationUnified looks up)
    await t.run(async (ctx) => {
      await ctx.db.insert("effectiveRelationships", {
        tenantId: TENANT,
        subjectKey: "user:alice",
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectKey: "org:org1",
        objectType: "org",
        objectId: "org1",
        paths: [
          {
            isDirect: false,
            baseEffectiveId: sourceRow!._id as any,
            directRelationId: sourceRelRow!._id as any,
            depth: 1,
            path: [],
          },
        ],
        createdAt: Date.now(),
      });
    });

    // Verify inherited row exists
    const inheritedBefore = await t.run(async (ctx) => {
      const allRows = await ctx.db
        .query("effectiveRelationships")
        .withIndex("by_tenant_subject_relation_object", (q: any) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectKey", "user:alice")
            .eq("relation", "viewer")
            .eq("objectKey", "org:org1"),
        )
        .collect();
      return allRows;
    });
    expect(inheritedBefore.length).toBe(1);

    // Remove the original relation -> should clean up both direct and inherited
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Direct should be gone
    const directAfter = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(directAfter).toBe(false);

    // Inherited should also be gone
    const inheritedAfter = await t.run(async (ctx) => {
      const remaining = await ctx.db
        .query("effectiveRelationships")
        .withIndex("by_tenant_subject_relation_object", (q: any) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectKey", "user:alice")
            .eq("relation", "viewer")
            .eq("objectKey", "org:org1"),
        )
        .collect();
      // Only return rows that actually have paths in them
      return remaining.filter((r) => r.paths && r.paths.length > 0);
    });
    expect(inheritedAfter.length).toBe(0);
  });
});

// ============================================================================
// CATEGORY 10: Cross-tenant isolation
// ============================================================================

describe("Category 10: Cross-tenant isolation", () => {
  test("10.7 deny in tenant A doesn't affect tenant B", async () => {
    const t = convexTest(schema, modules);

    // Assign same role in both tenants
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-b",
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Deny in tenant A
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:read",
    });

    // A should be denied
    const resultA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:read",
    });
    expect(resultA.allowed).toBe(false);

    // B should still be allowed
    const resultB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "docs:read",
    });
    expect(resultB.allowed).toBe(true);
  });

  test("10.8 offboard in A doesn't affect B", async () => {
    const t = convexTest(schema, modules);

    // Assign in both
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-b",
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Offboard in A
    await t.mutation(api.mutations.offboardUser, {
      tenantId: "tenant-a",
      userId: "alice",
    });

    // A roles gone
    const rolesA = await t.query(api.indexed.getUserRolesFast, {
      tenantId: "tenant-a",
      userId: "alice",
    });
    expect(rolesA.length).toBe(0);

    // B roles intact
    const rolesB = await t.query(api.indexed.getUserRolesFast, {
      tenantId: "tenant-b",
      userId: "alice",
    });
    expect(rolesB.length).toBeGreaterThan(0);
    expect(rolesB[0].role).toBe("editor");
  });

  test("10.9 deprovision in A doesn't affect B", async () => {
    const t = convexTest(schema, modules);

    // Full setup both tenants
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: "tenant-a",
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-b",
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: "tenant-b",
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Deprovision A
    await t.mutation(api.mutations.deprovisionUser, {
      tenantId: "tenant-a",
      userId: "alice",
    });

    // A wiped
    const permA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:read",
    });
    expect(permA.allowed).toBe(false);

    const relA = await t.query(api.indexed.hasRelationFast, {
      tenantId: "tenant-a",
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(relA).toBe(false);

    // B intact
    const permB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "docs:read",
    });
    expect(permB.allowed).toBe(true);

    const relB = await t.query(api.indexed.hasRelationFast, {
      tenantId: "tenant-b",
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(relB).toBe(true);
  });

  test("10.10 wildcard deny in A doesn't affect B", async () => {
    const t = convexTest(schema, modules);

    // Assign in both
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-b",
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // Wildcard deny in A
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:*",
    });

    // A denied
    const readA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:read",
    });
    expect(readA.allowed).toBe(false);

    // B allowed
    const readB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "docs:read",
    });
    expect(readB.allowed).toBe(true);
  });

  test("10.11 same userId different tenants -> separate effective tables", async () => {
    const t = convexTest(schema, modules);

    // A: editor (docs:read, docs:write)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // B: admin (users:manage, settings:manage)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-b",
      userId: "alice",
      role: "admin",
      rolePermissions: ["users:manage", "settings:manage"],
    });

    // A: editor perms allowed
    const docsReadA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:read",
    });
    expect(docsReadA.allowed).toBe(true);

    // A: admin perms denied
    const usersManageA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "users:manage",
    });
    expect(usersManageA.allowed).toBe(false);

    // B: editor perms denied
    const docsReadB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "docs:read",
    });
    expect(docsReadB.allowed).toBe(false);

    // B: admin perms allowed
    const usersManageB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "users:manage",
    });
    expect(usersManageB.allowed).toBe(true);
  });
});
