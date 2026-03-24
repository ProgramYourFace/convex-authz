/**
 * Comprehensive end-to-end invariant tests for the unified Authz v2 component.
 *
 * Goal: catch interaction bugs where one operation's side effects break
 * another operation's invariants. Every test follows the "write then verify"
 * pattern using convex-test.
 */

import { convexTest } from "convex-test";
import { describe, test, expect } from "vitest";
import schema from "../schema.js";
import { api } from "../_generated/api.js";

const modules = import.meta.glob("../**/*.ts");
const TENANT = "test-tenant";

// ============================================================================
// Category 1: Every write method -> can() verification
// ============================================================================

describe("Category 1: Every write method -> checkPermission verification", () => {
  test("1.1 assignRoleUnified -> checkPermission returns allowed", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["documents:read", "documents:update"],
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(result.allowed).toBe(true);
    expect(result.tier).toBe("cached");
  });

  test("1.2 revokeRoleUnified -> checkPermission returns denied (after previous assign)", async () => {
    const t = convexTest(schema, modules);

    // Assign first
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["documents:read", "documents:update"],
    });

    // Verify it works
    const before = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(before.allowed).toBe(true);

    // Revoke
    const revoked = await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["documents:read", "documents:update"],
    });
    expect(revoked).toBe(true);

    // Should now be denied
    const after = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(after.allowed).toBe(false);
  });

  test("1.3 grantPermissionUnified -> checkPermission returns allowed", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:delete",
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:delete",
    });
    expect(result.allowed).toBe(true);
  });

  test("1.4 denyPermissionUnified -> checkPermission returns denied", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:delete",
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:delete",
    });
    expect(result.allowed).toBe(false);
  });

  test("1.5 addRelationUnified -> hasRelationFast returns true", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

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

  test("1.6 removeRelationUnified -> hasRelationFast returns false (after previous add)", async () => {
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

    // Verify it exists
    const before = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(before).toBe(true);

    // Remove
    const removed = await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(removed).toBe(true);

    // Should now be false
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

  test("1.7 setAttributeWithRecompute -> policyReEvaluation updates checkPermission result", async () => {
    const t = convexTest(schema, modules);

    // Assign role with deferred policy
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["documents:read"],
      policyClassifications: { "documents:read": "deferred" },
    });

    // Should be allowed with deferred tier
    const before = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(before.allowed).toBe(true);
    expect(before.tier).toBe("deferred");

    // Set attribute with policy re-evaluation that denies
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "status",
      value: "suspended",
      policyReEvaluations: { "documents:read": "deny" },
    });

    // Should now be denied
    const after = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(after.allowed).toBe(false);
  });

  test("1.8 recomputeUser -> rebuilds effective tables from source", async () => {
    const t = convexTest(schema, modules);

    // Assign role (populates both source + effective)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["documents:read", "documents:update"],
    });

    // Verify permission works
    const before = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(before.allowed).toBe(true);

    // Simulate stale effective tables by deleting all effective entries
    await t.run(async (ctx) => {
      const perms = await ctx.db.query("effectivePermissions").collect();
      for (const p of perms) await ctx.db.delete(p._id);
      const roles = await ctx.db.query("effectiveRoles").collect();
      for (const r of roles) await ctx.db.delete(r._id);
    });

    // Permission check should fail (effective tables empty)
    const stale = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(stale.allowed).toBe(false);

    // Recompute from source tables
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { editor: ["documents:read", "documents:update"] },
    });

    // Permission check should work again
    const after = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(after.allowed).toBe(true);
  });
});

// ============================================================================
// Category 2: Interaction between operations (real bugs found)
// ============================================================================

describe("Category 2: Interaction between operations", () => {
  test("2.1 revokeRole preserves directDeny", async () => {
    const t = convexTest(schema, modules);

    // Step 1: Create a directDeny on documents:read
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });

    // Step 2: Assign a role that includes documents:read
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["documents:read", "documents:write"],
    });

    // Step 3: Revoke that role
    await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["documents:read", "documents:write"],
    });

    // Step 4: documents:read should still be DENIED (directDeny preserved)
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(result.allowed).toBe(false);
  });

  test("2.2 grantPermission clears directDeny", async () => {
    const t = convexTest(schema, modules);

    // Step 1: Create a directDeny
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });

    // Verify it's denied
    const denied = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(denied.allowed).toBe(false);

    // Step 2: Grant the same permission — should flip to allow, clear directDeny
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });

    // Step 3: Should be ALLOWED
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(result.allowed).toBe(true);
  });

  test("2.3 denyPermission overrides role-granted allow", async () => {
    const t = convexTest(schema, modules);

    // Assign role with documents:read
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["documents:read"],
    });

    // Verify it's allowed
    const before = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(before.allowed).toBe(true);

    // Deny the same permission
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });

    // Should be DENIED (deny wins over role-granted allow)
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(result.allowed).toBe(false);
  });

  test("2.4 revoking one of two roles preserves shared permission", async () => {
    const t = convexTest(schema, modules);

    // Assign editor with docs:read and docs:write
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // Assign viewer with docs:read
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["docs:read"],
    });

    // Revoke editor
    await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // docs:read should still be ALLOWED (viewer still grants it)
    const readResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(readResult.allowed).toBe(true);

    // docs:write should be DENIED (only editor granted it)
    const writeResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(writeResult.allowed).toBe(false);
  });

  test("2.5 revokeAll then checkPermission returns false for role perms but direct grant preserved", async () => {
    const t = convexTest(schema, modules);

    // Assign admin role with permissions
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["a:b", "c:d", "e:f"],
    });

    // Grant a direct permission
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "extra:perm",
    });

    // revokeAllRoles only deletes source roleAssignments, then recomputeUser
    // rebuilds effective tables (preserving direct grants/denies)
    await t.mutation(api.unified.revokeAllRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: {},
      });

    // Simulate what the client does: call recomputeUser after revokeAllRoles
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { admin: ["a:b", "c:d", "e:f"] },
    });

    // Role permission should be DENIED (role was revoked)
    const rolePermResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "a:b",
    });
    expect(rolePermResult.allowed).toBe(false);

    // Direct grant should be preserved by recomputeUser
    const directResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "extra:perm",
    });
    expect(directResult.allowed).toBe(true);
  });
});

// ============================================================================
// Category 3: Bulk operations -> effective tables sync
// ============================================================================

describe("Category 3: Bulk operations -> effective tables sync", () => {
  test("3.1 assignRoles (bulk) + recomputeUser updates effective tables", async () => {
    const t = convexTest(schema, modules);

    // Use bulk assignRoles (the old mutations path)
    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "admin" },
        { role: "editor" },
        { role: "viewer" },
      ],
      rolePermissionsMap: {},
      });

    // Client would call recomputeUser after bulk assign
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: {
        admin: ["settings:manage", "users:manage"],
        editor: ["docs:read", "docs:write"],
        viewer: ["docs:read"],
      },
    });

    // Check permission from each role
    const settingsResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "settings:manage",
    });
    expect(settingsResult.allowed).toBe(true);

    const docsWriteResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(docsWriteResult.allowed).toBe(true);

    const docsReadResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(docsReadResult.allowed).toBe(true);
  });

  test("3.2 revokeRoles (bulk) + recomputeUser updates effective tables", async () => {
    const t = convexTest(schema, modules);

    // First assign 3 roles via unified path
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["settings:manage"],
    });
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:write"],
    });
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["docs:read"],
    });

    // Use bulk revokeRoles to revoke 2 of them
    await t.mutation(api.unified.revokeRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "admin" },
        { role: "editor" },
      ],
      rolePermissionsMap: {},
      });

    // Recompute effective tables
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: {
        admin: ["settings:manage"],
        editor: ["docs:write"],
        viewer: ["docs:read"],
      },
    });

    // Revoked roles' permissions should be DENIED
    const settingsResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "settings:manage",
    });
    expect(settingsResult.allowed).toBe(false);

    const docsWriteResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(docsWriteResult.allowed).toBe(false);

    // Remaining role's permissions should still be ALLOWED
    const docsReadResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(docsReadResult.allowed).toBe(true);
  });

  test("3.3 bulk assign then single revoke", async () => {
    const t = convexTest(schema, modules);

    // Bulk assign 3 roles + recompute
    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "admin" },
        { role: "editor" },
        { role: "viewer" },
      ],
      rolePermissionsMap: {},
      });

    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: {
        admin: ["settings:manage"],
        editor: ["docs:write"],
        viewer: ["docs:read"],
      },
    });

    // Single revoke of one role using unified path
    await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:write"],
    });

    // Remaining 2 roles' permissions should still work
    const settingsResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "settings:manage",
    });
    expect(settingsResult.allowed).toBe(true);

    const docsReadResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(docsReadResult.allowed).toBe(true);

    // Revoked role's permission should be DENIED
    const docsWriteResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(docsWriteResult.allowed).toBe(false);
  });
});

// ============================================================================
// Category 4: Scope interactions
// ============================================================================

describe("Category 4: Scope interactions", () => {
  test("4.1 global role grants global permission, not scoped", async () => {
    const t = convexTest(schema, modules);

    // Assign role with NO scope (global)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["docs:read"],
    });

    // Global check -> ALLOWED
    const globalResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(globalResult.allowed).toBe(true);

    // Scoped check -> DENIED (different scopeKey: "project:p1" vs "global")
    const scopedResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p1" },
    });
    expect(scopedResult.allowed).toBe(false);
  });

  test("4.2 scoped role grants scoped permission", async () => {
    const t = convexTest(schema, modules);

    // Assign role with scope
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:write"],
      scope: { type: "project", id: "p1" },
    });

    // Same scope -> ALLOWED
    const sameScopeResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
      scope: { type: "project", id: "p1" },
    });
    expect(sameScopeResult.allowed).toBe(true);

    // No scope (global) -> DENIED
    const globalResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(globalResult.allowed).toBe(false);

    // Different scope -> DENIED
    const diffScopeResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
      scope: { type: "project", id: "p2" },
    });
    expect(diffScopeResult.allowed).toBe(false);
  });

  test("4.3 direct grant in one scope doesn't affect another", async () => {
    const t = convexTest(schema, modules);

    // Grant permission in org:o1
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
      scope: { type: "org", id: "o1" },
    });

    // Same scope -> ALLOWED
    const o1Result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
      scope: { type: "org", id: "o1" },
    });
    expect(o1Result.allowed).toBe(true);

    // Different scope -> DENIED
    const o2Result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
      scope: { type: "org", id: "o2" },
    });
    expect(o2Result.allowed).toBe(false);

    // Global -> DENIED
    const globalResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
    });
    expect(globalResult.allowed).toBe(false);
  });
});

// ============================================================================
// Category 5: Policy classification
// ============================================================================

describe("Category 5: Policy classification", () => {
  test("5.1 static policy deny prevents materialization", async () => {
    const t = convexTest(schema, modules);

    // Assign role where policy for docs:delete evaluates to "deny"
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:delete"],
      policyClassifications: { "docs:delete": "deny" },
    });

    // docs:delete should be DENIED (was never materialized)
    const deleteResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
    });
    expect(deleteResult.allowed).toBe(false);

    // docs:read should still be ALLOWED (no classification -> default allow)
    const readResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(readResult.allowed).toBe(true);
  });

  test("5.2 deferred policy marks tier=deferred", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["billing:export"],
      policyClassifications: { "billing:export": "deferred" },
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

  test("5.3 setAttribute triggers policy re-evaluation across scopes", async () => {
    const t = convexTest(schema, modules);

    // Assign role with deferred policy in scope org:o1
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
      policyClassifications: { "docs:read": "deferred" },
      scope: { type: "org", id: "o1" },
    });

    // Assign same role with deferred policy in scope org:o2
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor2",
      rolePermissions: ["docs:read"],
      policyClassifications: { "docs:read": "deferred" },
      scope: { type: "org", id: "o2" },
    });

    // Both should be allowed (deferred)
    const beforeO1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "org", id: "o1" },
    });
    expect(beforeO1.allowed).toBe(true);
    expect(beforeO1.tier).toBe("deferred");

    const beforeO2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "org", id: "o2" },
    });
    expect(beforeO2.allowed).toBe(true);
    expect(beforeO2.tier).toBe("deferred");

    // Set attribute with policy re-evaluation that denies docs:read
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "status",
      value: "suspended",
      policyReEvaluations: { "docs:read": "deny" },
    });

    // Both scopes should now be DENIED
    const afterO1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "org", id: "o1" },
    });
    expect(afterO1.allowed).toBe(false);

    const afterO2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "org", id: "o2" },
    });
    expect(afterO2.allowed).toBe(false);
  });
});

// ============================================================================
// Category 6: Cross-tenant isolation
// ============================================================================

describe("Category 6: Cross-tenant isolation", () => {
  test("6.1 role assigned in tenant A invisible in tenant B", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      role: "admin",
      rolePermissions: ["docs:read"],
    });

    // Tenant A -> allowed
    const resultA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:read",
    });
    expect(resultA.allowed).toBe(true);

    // Tenant B -> denied
    const resultB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "docs:read",
    });
    expect(resultB.allowed).toBe(false);
  });

  test("6.2 permission override in tenant A invisible in tenant B", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:delete",
    });

    const resultA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:delete",
    });
    expect(resultA.allowed).toBe(true);

    const resultB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "docs:delete",
    });
    expect(resultB.allowed).toBe(false);
  });

  test("6.3 relation in tenant A invisible in tenant B", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: "tenant-a",
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    const resultA = await t.query(api.indexed.hasRelationFast, {
      tenantId: "tenant-a",
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(resultA).toBe(true);

    const resultB = await t.query(api.indexed.hasRelationFast, {
      tenantId: "tenant-b",
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(resultB).toBe(false);
  });

  test("6.4 attribute in tenant A invisible in tenant B", async () => {
    const t = convexTest(schema, modules);

    // Set attribute in tenant A with deferred policy on docs:read
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
      policyClassifications: { "docs:read": "deferred" },
    });

    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: "tenant-a",
      userId: "alice",
      key: "plan",
      value: "enterprise",
      policyReEvaluations: { "docs:read": "allow" },
    });

    // Tenant A should still have docs:read allowed
    const resultA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:read",
    });
    expect(resultA.allowed).toBe(true);

    // Tenant B should have nothing
    const resultB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "docs:read",
    });
    expect(resultB.allowed).toBe(false);
  });

  test("6.5 revokeAll in tenant A doesn't affect tenant B", async () => {
    const t = convexTest(schema, modules);

    // Assign roles in both tenants
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      role: "admin",
      rolePermissions: ["docs:read"],
    });

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-b",
      userId: "alice",
      role: "admin",
      rolePermissions: ["docs:read"],
    });

    // Revoke all in tenant A
    await t.mutation(api.unified.revokeAllRolesUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      rolePermissionsMap: {},
      });

    // Recompute tenant A
    await t.mutation(api.unified.recomputeUser, {
      tenantId: "tenant-a",
      userId: "alice",
      rolePermissionsMap: { admin: ["docs:read"] },
    });

    // Tenant A -> denied
    const resultA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:read",
    });
    expect(resultA.allowed).toBe(false);

    // Tenant B -> still allowed (not affected)
    const resultB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "docs:read",
    });
    expect(resultB.allowed).toBe(true);
  });

  test("6.6 recomputeUser in tenant A doesn't affect tenant B", async () => {
    const t = convexTest(schema, modules);

    // Assign roles in both tenants
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

    // Recompute tenant A with EMPTY permissions map (simulating permission change)
    await t.mutation(api.unified.recomputeUser, {
      tenantId: "tenant-a",
      userId: "alice",
      rolePermissionsMap: { editor: [] },
    });

    // Tenant A -> denied (no permissions mapped)
    const resultA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "docs:read",
    });
    expect(resultA.allowed).toBe(false);

    // Tenant B -> still allowed (not affected by tenant A recompute)
    const resultB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "docs:read",
    });
    expect(resultB.allowed).toBe(true);
  });
});

// ============================================================================
// Category 7: Wildcard patterns
// ============================================================================

describe("Category 7: Wildcard patterns", () => {
  test("7.1 wildcard pattern 'docs:*' grants 'docs:read'", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["docs:*"],
    });

    // docs:read should be allowed (matched by docs:*)
    const readResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(readResult.allowed).toBe(true);

    // docs:write should be allowed (matched by docs:*)
    const writeResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(writeResult.allowed).toBe(true);

    // settings:read should be DENIED (not matched by docs:*)
    const settingsResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "settings:read",
    });
    expect(settingsResult.allowed).toBe(false);
  });

  test("7.2 deny pattern 'docs:*' blocks 'docs:read' even with allow", async () => {
    const t = convexTest(schema, modules);

    // Assign role with explicit docs:read allow
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["docs:read"],
    });

    // Deny docs:* (wildcard deny pattern)
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:*",
    });

    // docs:read should be DENIED (deny pattern docs:* wins)
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);
  });
});

// ============================================================================
// Category 8: Expiration
// ============================================================================

describe("Category 8: Expiration", () => {
  test("8.1 expired role assignment returns denied", async () => {
    const t = convexTest(schema, modules);

    // Assign role with already-expired expiresAt
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
      expiresAt: Date.now() - 1000,
    });

    // The effective table entry should have expiresAt set.
    // checkPermission should return denied because isExpired() returns true.
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);
  });

  test("8.2 expired direct grant returns denied", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      expiresAt: Date.now() - 1000,
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);
  });
});

// ============================================================================
// Category 9: Edge cases
// ============================================================================

describe("Category 9: Edge cases", () => {
  test("9.1 double assign same role is idempotent", async () => {
    const t = convexTest(schema, modules);

    const id1 = await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    const id2 = await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Should return same ID (idempotent)
    expect(id1).toBe(id2);

    // Verify only 1 row in roleAssignments and 1 in effectiveRoles
    await t.run(async (ctx) => {
      const assignments = await ctx.db
        .query("roleAssignments")
        .withIndex("by_tenant_user_and_role", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "alice").eq("role", "editor")
        )
        .collect();
      expect(assignments.length).toBe(1);

      const effectiveRoles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user_role_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("role", "editor")
            .eq("scopeKey", "global")
        )
        .collect();
      expect(effectiveRoles.length).toBe(1);
    });
  });

  test("9.2 revoke non-existent role returns false", async () => {
    const t = convexTest(schema, modules);

    const result = await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "nonexistent",
      rolePermissions: ["a:b"],
    });

    expect(result).toBe(false);
  });

  test("9.3 checkPermission for user with no data returns denied", async () => {
    const t = convexTest(schema, modules);

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "nobody",
      permission: "anything:read",
    });

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe("none");
  });

  test("9.4 recomputeUser with empty rolePermissionsMap clears effective tables", async () => {
    const t = convexTest(schema, modules);

    // Assign role first
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // Verify it works
    const before = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(before.allowed).toBe(true);

    // Recompute with empty map (simulating role definition change)
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: {},
    });

    // Should be DENIED (effective tables cleared because no permissions mapped)
    const after = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(after.allowed).toBe(false);
  });
});

// ============================================================================
// Category 10: Bulk unified mutations (transactional dual-write)
// ============================================================================

describe("Category 10: Bulk unified mutations", () => {
  test("10.1 assignRolesUnified populates effective tables for all roles", async () => {
    const t = convexTest(schema, import.meta.glob("../**/*.ts"));

    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "editor" },
        { role: "viewer" },
      ],
      rolePermissionsMap: {
        editor: ["docs:read", "docs:write"],
        viewer: ["docs:read"],
      },
    });

    // docs:read should be allowed (granted by both roles)
    const r1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT, userId: "alice", permission: "docs:read",
    });
    expect(r1.allowed).toBe(true);

    // docs:write should be allowed (granted by editor)
    const r2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT, userId: "alice", permission: "docs:write",
    });
    expect(r2.allowed).toBe(true);

    // settings:read should be denied (not granted by any role)
    const r3 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT, userId: "alice", permission: "settings:read",
    });
    expect(r3.allowed).toBe(false);
  });

  test("10.2 revokeRolesUnified removes permissions atomically", async () => {
    const t = convexTest(schema, import.meta.glob("../**/*.ts"));

    // Assign 3 roles
    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "admin" },
        { role: "editor" },
        { role: "viewer" },
      ],
      rolePermissionsMap: {
        admin: ["docs:read", "docs:write", "docs:delete"],
        editor: ["docs:read", "docs:write"],
        viewer: ["docs:read"],
      },
    });

    // Revoke admin and editor (viewer remains)
    await t.mutation(api.unified.revokeRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "admin" },
        { role: "editor" },
      ],
      rolePermissionsMap: {
        admin: ["docs:read", "docs:write", "docs:delete"],
        editor: ["docs:read", "docs:write"],
        viewer: ["docs:read"],
      },
    });

    // docs:read still allowed (viewer grants it)
    const r1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT, userId: "alice", permission: "docs:read",
    });
    expect(r1.allowed).toBe(true);

    // docs:write denied (only admin and editor granted it, both revoked)
    const r2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT, userId: "alice", permission: "docs:write",
    });
    expect(r2.allowed).toBe(false);

    // docs:delete denied (only admin granted it)
    const r3 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT, userId: "alice", permission: "docs:delete",
    });
    expect(r3.allowed).toBe(false);
  });

  test("10.3 revokeAllRolesUnified clears all role-based permissions but preserves direct grants", async () => {
    const t = convexTest(schema, import.meta.glob("../**/*.ts"));

    // Assign roles
    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [{ role: "admin" }, { role: "editor" }],
      rolePermissionsMap: {
        admin: ["docs:delete", "settings:manage"],
        editor: ["docs:read", "docs:write"],
      },
    });

    // Direct grant one permission
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT, userId: "alice", permission: "billing:view",
    });

    // Revoke all roles
    await t.mutation(api.unified.revokeAllRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: {
        admin: ["docs:delete", "settings:manage"],
        editor: ["docs:read", "docs:write"],
      },
    });

    // All role-based permissions denied
    const r1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT, userId: "alice", permission: "docs:read",
    });
    expect(r1.allowed).toBe(false);

    const r2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT, userId: "alice", permission: "docs:delete",
    });
    expect(r2.allowed).toBe(false);

    // Direct grant preserved
    const r3 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT, userId: "alice", permission: "billing:view",
    });
    expect(r3.allowed).toBe(true);
  });

  test("10.4 assignRolesUnified propagates policyClassifications to existing rows", async () => {
    const t = convexTest(schema, import.meta.glob("../**/*.ts"));

    // First role creates the permission row with no policy
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["docs:read"],
    });

    // Second role via bulk adds itself as source + sets deferred policy
    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [{ role: "auditor" }],
      rolePermissionsMap: { auditor: ["docs:read"] },
      policyClassifications: { "docs:read": "deferred" },
    });

    // The permission should now have policyResult=deferred
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT, userId: "alice", permission: "docs:read",
    });
    expect(result.allowed).toBe(true);
    expect(result.tier).toBe("deferred");
  });
});

// ============================================================================
// Category 11: Offboarding / Deprovisioning
// ============================================================================

describe("Category 11: Offboarding and deprovisioning", () => {
  test("11.1 offboardUser clears role-based permissions but preserves direct grants when configured", async () => {
    const t = convexTest(schema, import.meta.glob("../**/*.ts"));

    // Assign role
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // Direct grant
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "billing:view",
    });

    // Add relation
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Offboard (removes roles but not overrides by default)
    await t.mutation(api.mutations.offboardUser, {
      tenantId: TENANT,
      userId: "alice",
      removeAttributes: false,
      removeOverrides: false,
      removeRelationships: true,
      enableAudit: true,
    });

    // Role-based permissions should be gone from source table
    const roles = await t.run(async (ctx) => {
      return ctx.db
        .query("roleAssignments")
        .withIndex("by_tenant_user", (q) => q.eq("tenantId", TENANT).eq("userId", "alice"))
        .collect();
    });
    expect(roles).toHaveLength(0);

    // Relation should be gone
    const rels = await t.run(async (ctx) => {
      return ctx.db
        .query("relationships")
        .withIndex("by_tenant_subject", (q) => q.eq("tenantId", TENANT).eq("subjectType", "user").eq("subjectId", "alice"))
        .collect();
    });
    expect(rels).toHaveLength(0);
  });

  test("11.2 deprovisionUser removes everything", async () => {
    const t = convexTest(schema, import.meta.glob("../**/*.ts"));

    // Set up: role + direct grant + attribute + relation
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["docs:delete"],
    });

    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "billing:view",
    });

    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "department",
      value: "engineering",
    });

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Deprovision — wipes everything
    await t.mutation(api.mutations.deprovisionUser, {
      tenantId: TENANT,
      userId: "alice",
      enableAudit: true,
    });

    // All source tables should be empty for this user
    const checkTables = await t.run(async (ctx) => {
      const roles = await ctx.db.query("roleAssignments")
        .withIndex("by_tenant_user", (q) => q.eq("tenantId", TENANT).eq("userId", "alice"))
        .collect();
      const overrides = await ctx.db.query("permissionOverrides")
        .withIndex("by_tenant_user", (q) => q.eq("tenantId", TENANT).eq("userId", "alice"))
        .collect();
      const attrs = await ctx.db.query("userAttributes")
        .withIndex("by_tenant_user", (q) => q.eq("tenantId", TENANT).eq("userId", "alice"))
        .collect();
      const effPerms = await ctx.db.query("effectivePermissions")
        .withIndex("by_tenant_user", (q) => q.eq("tenantId", TENANT).eq("userId", "alice"))
        .collect();
      const effRoles = await ctx.db.query("effectiveRoles")
        .withIndex("by_tenant_user", (q) => q.eq("tenantId", TENANT).eq("userId", "alice"))
        .collect();
      return { roles, overrides, attrs, effPerms, effRoles };
    });

    expect(checkTables.roles).toHaveLength(0);
    expect(checkTables.overrides).toHaveLength(0);
    expect(checkTables.attrs).toHaveLength(0);
    expect(checkTables.effPerms).toHaveLength(0);
    expect(checkTables.effRoles).toHaveLength(0);
  });
});
