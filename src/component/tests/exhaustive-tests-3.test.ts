/**
 * Exhaustive end-to-end tests – Batch 3 (Categories 11-14)
 *
 * Covers: Offboarding/Deprovisioning, Bulk operations, Recompute scenarios,
 * and Edge cases for the unified Authz v2 component.
 */

import { convexTest } from "convex-test";
import schema from "../schema.js";
import { api } from "../_generated/api.js";
import { describe, test, expect } from "vitest";

const modules = import.meta.glob("../**/*.ts");
const TENANT = "test-tenant";

// ============================================================================
// CATEGORY 11: Offboarding / Deprovisioning
// ============================================================================

describe("Category 11: Offboarding / Deprovisioning", () => {
  test("11.3 offboard scoped -> only removes roles in that scope", async () => {
    const t = convexTest(schema, modules);

    // Assign editor in scope p1
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
      scope: { type: "project", id: "p1" },
    });

    // Assign admin globally
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["admin:manage"],
    });

    // Offboard only in scope p1
    const result = await t.mutation(api.mutations.offboardUser, {
      tenantId: TENANT,
      userId: "alice",
      scope: { type: "project", id: "p1" },
    });

    expect(result.rolesRevoked).toBe(1);

    // Global admin role should still be present
    const roles = await t.query(api.queries.getUserRoles, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(roles.length).toBe(1);
    expect(roles[0].role).toBe("admin");

    // Global admin permission should still work
    const check = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "admin:manage",
    });
    expect(check.allowed).toBe(true);

    // Scoped permission should be denied
    const checkScoped = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p1" },
    });
    expect(checkScoped.allowed).toBe(false);
  });

  test("11.4 offboard removeAttributes=true -> attributes removed", async () => {
    const t = convexTest(schema, modules);

    // Set attribute
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "department",
      value: "engineering",
    });

    // Verify attribute exists
    const attrsBefore = await t.query(api.queries.getUserAttributes, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(attrsBefore.length).toBe(1);

    // Offboard with removeAttributes=true
    await t.mutation(api.mutations.offboardUser, {
      tenantId: TENANT,
      userId: "alice",
      removeAttributes: true,
    });

    // DB: userAttributes should be empty
    const attrsAfter = await t.run(async (ctx) => {
      return await ctx.db
        .query("userAttributes")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "alice")
        )
        .collect();
    });
    expect(attrsAfter.length).toBe(0);
  });

  test("11.5 offboard removeAttributes=false -> attributes preserved", async () => {
    const t = convexTest(schema, modules);

    // Set attribute
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "department",
      value: "engineering",
    });

    // Offboard with removeAttributes=false
    await t.mutation(api.mutations.offboardUser, {
      tenantId: TENANT,
      userId: "alice",
      removeAttributes: false,
    });

    // DB: userAttributes should still have the row
    const attrsAfter = await t.run(async (ctx) => {
      return await ctx.db
        .query("userAttributes")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "alice")
        )
        .collect();
    });
    expect(attrsAfter.length).toBe(1);
    expect(attrsAfter[0].key).toBe("department");
    expect(attrsAfter[0].value).toBe("engineering");
  });

  test("11.6 offboard removes effectiveRoles and effectivePermissions", async () => {
    const t = convexTest(schema, modules);

    // Assign role
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // Verify effective data exists
    const rolesBefore = await t.query(api.indexed.getUserRolesFast, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(rolesBefore.length).toBe(1);

    const permsBefore = await t.query(api.indexed.getUserPermissionsFast, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(permsBefore.length).toBe(2);

    // Offboard
    await t.mutation(api.mutations.offboardUser, {
      tenantId: TENANT,
      userId: "alice",
    });

    // effectiveRoles should be empty
    const rolesAfter = await t.query(api.indexed.getUserRolesFast, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(rolesAfter.length).toBe(0);

    // effectivePermissions should be empty
    const permsAfter = await t.query(api.indexed.getUserPermissionsFast, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(permsAfter.length).toBe(0);
  });

  test("11.7 offboard returns correct counts", async () => {
    const t = convexTest(schema, modules);

    // Assign 2 roles
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["docs:view"],
    });

    // Grant 1 permission override
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "special:access",
    });

    // Set 1 attribute
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "level",
      value: "senior",
    });

    // Add 1 relation
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Offboard with all removal options enabled (no scope = full deprovision)
    const result = await t.mutation(api.mutations.offboardUser, {
      tenantId: TENANT,
      userId: "alice",
      removeAttributes: true,
      removeOverrides: true,
      removeRelationships: true,
    });

    expect(result.rolesRevoked).toBe(2);
    expect(result.attributesRemoved).toBe(1);
    expect(result.overridesRemoved).toBe(1);
    expect(result.relationshipsRemoved).toBe(1);
    // effectiveRoles: 2 (one per role)
    expect(result.effectiveRolesRemoved).toBe(2);
    // effectivePermissions: docs:read, docs:view, special:access
    expect(result.effectivePermissionsRemoved).toBe(3);
    // effectiveRelationships: 1
    expect(result.effectiveRelationshipsRemoved).toBe(1);
  });

  test("11.8 deprovision then reassign -> clean state", async () => {
    const t = convexTest(schema, modules);

    // Full setup
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["admin:manage", "admin:delete"],
    });
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "tier",
      value: "premium",
    });

    // Deprovision
    await t.mutation(api.mutations.deprovisionUser, {
      tenantId: TENANT,
      userId: "alice",
    });

    // Verify clean
    const checkOld = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "admin:manage",
    });
    expect(checkOld.allowed).toBe(false);

    // Reassign new role only
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["docs:read"],
    });

    // Only new role permission is allowed
    const checkNew = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(checkNew.allowed).toBe(true);

    // Old admin permission still denied
    const checkOld2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "admin:manage",
    });
    expect(checkOld2.allowed).toBe(false);
  });

  test("11.9 offboard + recompute -> empty", async () => {
    const t = convexTest(schema, modules);

    // Assign 2 roles
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["docs:view"],
    });

    // Offboard (removes roles from source + effective tables)
    await t.mutation(api.mutations.offboardUser, {
      tenantId: TENANT,
      userId: "alice",
    });

    // Recompute with empty map (no roles in source = nothing to rebuild)
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: {},
    });

    // No effective rows
    const roles = await t.query(api.indexed.getUserRolesFast, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(roles.length).toBe(0);

    const perms = await t.query(api.indexed.getUserPermissionsFast, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(perms.length).toBe(0);
  });

  test("11.10 deprovision user with zero data -> zero counts, no error", async () => {
    const t = convexTest(schema, modules);

    const result = await t.mutation(api.mutations.deprovisionUser, {
      tenantId: TENANT,
      userId: "ghost",
    });

    expect(result.rolesRevoked).toBe(0);
    expect(result.overridesRemoved).toBe(0);
    expect(result.attributesRemoved).toBe(0);
    expect(result.relationshipsRemoved).toBe(0);
    expect(result.effectiveRolesRemoved).toBe(0);
    expect(result.effectivePermissionsRemoved).toBe(0);
    expect(result.effectiveRelationshipsRemoved).toBe(0);
  });
});

// ============================================================================
// CATEGORY 12: Bulk operations
// ============================================================================

describe("Category 12: Bulk operations", () => {
  test("12.5 assignRolesUnified with 0 roles -> {assigned:0}", async () => {
    const t = convexTest(schema, modules);

    const result = await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [],
      rolePermissionsMap: {},
    });

    expect(result.assigned).toBe(0);
    expect(result.assignmentIds).toEqual([]);
  });

  test("12.6 revokeRolesUnified with 0 roles -> {revoked:0}", async () => {
    const t = convexTest(schema, modules);

    const result = await t.mutation(api.unified.revokeRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [],
      rolePermissionsMap: {},
      });

    expect(result.revoked).toBe(0);
  });

  test("12.7 assignRolesUnified with >20 roles -> throws", async () => {
    const t = convexTest(schema, modules);

    const tooManyRoles = Array.from({ length: 21 }, (_, i) => ({
      role: `role-${i}`,
    }));

    await expect(
      t.mutation(api.unified.assignRolesUnified, {
        tenantId: TENANT,
        userId: "alice",
        roles: tooManyRoles,
        rolePermissionsMap: {},
      })
    ).rejects.toThrow(/must not exceed 20/);
  });

  test("12.8 revokeRolesUnified with >20 roles -> throws", async () => {
    const t = convexTest(schema, modules);

    const tooManyRoles = Array.from({ length: 21 }, (_, i) => ({
      role: `role-${i}`,
    }));

    await expect(
      t.mutation(api.unified.revokeRolesUnified, {
        tenantId: TENANT,
        userId: "alice",
        roles: tooManyRoles,
        rolePermissionsMap: {},
      })
    ).rejects.toThrow(/must not exceed 20/);
  });

  test("12.9 assignRolesUnified duplicate role in batch -> one entry", async () => {
    const t = convexTest(schema, modules);

    // Assign via bulk with the same role appearing twice (same scope)
    // The second occurrence should be detected as a duplicate and skipped
    // because the first one was just inserted in the same transaction.
    const result = await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "editor" },
        { role: "editor" },
      ],
      rolePermissionsMap: { editor: ["docs:read"] },
    });

    // First one gets inserted, second is detected as duplicate and skipped
    expect(result.assigned).toBe(1);

    // Only one roleAssignment entry
    const roles = await t.query(api.queries.getUserRoles, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(roles.length).toBe(1);
    expect(roles[0].role).toBe("editor");
  });

  test("12.10 bulk assign + revokeAll + bulk assign -> clean state", async () => {
    const t = convexTest(schema, modules);

    // Bulk assign
    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "editor" },
        { role: "viewer" },
      ],
      rolePermissionsMap: {
        editor: ["docs:write"],
        viewer: ["docs:read"],
      },
    });

    // Verify both permissions work
    const check1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(check1.allowed).toBe(true);

    // Revoke all via bulk
    await t.mutation(api.unified.revokeRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "editor" },
        { role: "viewer" },
      ],
      rolePermissionsMap: {
        editor: ["docs:write"],
        viewer: ["docs:read"],
      },
    });

    // Verify both permissions are denied
    const checkAfterRevoke = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(checkAfterRevoke.allowed).toBe(false);

    // Bulk assign again (new set)
    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "admin" },
      ],
      rolePermissionsMap: {
        admin: ["admin:manage"],
      },
    });

    // Only admin permission allowed
    const checkAdmin = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "admin:manage",
    });
    expect(checkAdmin.allowed).toBe(true);

    // Old permissions still denied
    const checkOld = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(checkOld.allowed).toBe(false);
  });

  test("12.11 assignRolesUnified with scoped roles -> each scope independent", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "editor", scope: { type: "project", id: "p1" } },
        { role: "editor", scope: { type: "project", id: "p2" } },
      ],
      rolePermissionsMap: {
        editor: ["docs:read", "docs:write"],
      },
    });

    // p1 scope: allowed
    const checkP1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p1" },
    });
    expect(checkP1.allowed).toBe(true);

    // p2 scope: allowed
    const checkP2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p2" },
    });
    expect(checkP2.allowed).toBe(true);

    // p3 scope: denied (not assigned)
    const checkP3 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p3" },
    });
    expect(checkP3.allowed).toBe(false);

    // global: denied (only scoped)
    const checkGlobal = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(checkGlobal.allowed).toBe(false);
  });

  test("12.12 revokeRolesUnified with scoped roles -> only revokes correct scope", async () => {
    const t = convexTest(schema, modules);

    // Assign in both scopes
    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "editor", scope: { type: "project", id: "p1" } },
        { role: "editor", scope: { type: "project", id: "p2" } },
      ],
      rolePermissionsMap: {
        editor: ["docs:read"],
      },
    });

    // Revoke only from p1
    const result = await t.mutation(api.unified.revokeRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "editor", scope: { type: "project", id: "p1" } },
      ],
      rolePermissionsMap: {
        editor: ["docs:read"],
      },
    });
    expect(result.revoked).toBe(1);

    // p1: denied
    const checkP1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p1" },
    });
    expect(checkP1.allowed).toBe(false);

    // p2: still allowed
    const checkP2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p2" },
    });
    expect(checkP2.allowed).toBe(true);
  });

  test("12.13 assignRolesUnified mixed expiry -> merged uses max/undefined", async () => {
    const t = convexTest(schema, modules);

    const future1 = Date.now() + 60_000;
    const future2 = Date.now() + 120_000;

    // Assign two roles that share a permission, with different expiries
    await t.mutation(api.unified.assignRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      roles: [
        { role: "editor", expiresAt: future1 },
        { role: "admin", expiresAt: future2 },
      ],
      rolePermissionsMap: {
        editor: ["docs:read"],
        admin: ["docs:read", "admin:manage"],
      },
    });

    // The "docs:read" permission should have merged expiry = max(future1, future2) = future2
    const perms = await t.run(async (ctx) => {
      return await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "docs:read")
            .eq("scopeKey", "global")
        )
        .unique();
    });

    expect(perms).not.toBeNull();
    expect(perms!.expiresAt).toBe(future2);
    expect(perms!.sources).toContain("editor");
    expect(perms!.sources).toContain("admin");

    // Now assign a third role with NO expiry for the same permission
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "superadmin",
      rolePermissions: ["docs:read"],
      // no expiresAt => undefined => effectively "never expires"
    });

    // Merged expiresAt should now be undefined (never expires wins)
    const permsAfter = await t.run(async (ctx) => {
      return await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "docs:read")
            .eq("scopeKey", "global")
        )
        .unique();
    });

    expect(permsAfter).not.toBeNull();
    expect(permsAfter!.expiresAt).toBeUndefined();
  });
});

// ============================================================================
// CATEGORY 13: Recompute scenarios
// ============================================================================

describe("Category 13: Recompute scenarios", () => {
  test("13.4 recompute preserves direct denies", async () => {
    const t = convexTest(schema, modules);

    // Assign role with "docs:read"
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Deny the same permission directly
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Verify denied
    const before = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(before.allowed).toBe(false);

    // Recompute
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { editor: ["docs:read"] },
    });

    // Still denied (directDeny preserved)
    const after = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(after.allowed).toBe(false);

    // Verify DB has directDeny=true
    const row = await t.run(async (ctx) => {
      return await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "docs:read")
            .eq("scopeKey", "global")
        )
        .unique();
    });
    expect(row).not.toBeNull();
    expect(row!.directDeny).toBe(true);
  });

  test("13.5 recompute with new permission in map -> appears", async () => {
    const t = convexTest(schema, modules);

    // Assign editor with only docs:read
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Verify docs:write is denied
    const before = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(before.allowed).toBe(false);

    // Recompute with expanded permissions
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { editor: ["docs:read", "docs:write"] },
    });

    // docs:write should now be allowed
    const after = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(after.allowed).toBe(true);
  });

  test("13.6 recompute with removed permission -> disappears", async () => {
    const t = convexTest(schema, modules);

    // Assign editor with docs:read and docs:write
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // Verify docs:write is allowed
    const before = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(before.allowed).toBe(true);

    // Recompute with reduced permissions
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { editor: ["docs:read"] },
    });

    // docs:write should now be denied
    const after = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(after.allowed).toBe(false);

    // docs:read should still be allowed
    const stillAllowed = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(stillAllowed.allowed).toBe(true);
  });

  test("13.8 recompute with multiple roles -> all rebuilt", async () => {
    const t = convexTest(schema, modules);

    // Assign editor and viewer
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["docs:view"],
    });

    // Manually delete effective tables to simulate corruption
    await t.run(async (ctx) => {
      const effRoles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "alice")
        )
        .collect();
      for (const r of effRoles) await ctx.db.delete(r._id);

      const effPerms = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "alice")
        )
        .collect();
      for (const p of effPerms) await ctx.db.delete(p._id);
    });

    // Verify permissions are gone
    const check = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(check.allowed).toBe(false);

    // Recompute with both roles
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: {
        editor: ["docs:read", "docs:write"],
        viewer: ["docs:view"],
      },
    });

    // All permissions from both roles should be present
    const checkRead = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(checkRead.allowed).toBe(true);

    const checkWrite = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:write",
    });
    expect(checkWrite.allowed).toBe(true);

    const checkView = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:view",
    });
    expect(checkView.allowed).toBe(true);

    // Effective roles rebuilt
    const roles = await t.query(api.indexed.getUserRolesFast, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(roles.length).toBe(2);
  });

  test("13.9 recompute clears stale policyResult from direct rows", async () => {
    const t = convexTest(schema, modules);

    // Assign role
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Grant the same permission directly (which clears policyResult)
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Manually set a stale policyResult on the direct row via DB
    await t.run(async (ctx) => {
      const row = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "docs:read")
            .eq("scopeKey", "global")
        )
        .unique();
      if (row) {
        await ctx.db.patch(row._id, {
          policyResult: "deny" as const,
          policyName: "stale-policy",
        });
      }
    });

    // Recompute should clear the stale policyResult from the direct grant row
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { editor: ["docs:read"] },
    });

    // The direct grant row should have policyResult cleared
    const row = await t.run(async (ctx) => {
      return await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "docs:read")
            .eq("scopeKey", "global")
        )
        .unique();
    });
    expect(row).not.toBeNull();
    expect(row!.directGrant).toBe(true);
    expect(row!.policyResult).toBeUndefined();
    expect(row!.policyName).toBeUndefined();
  });

  test("13.10 recompute handles role in multiple scopes", async () => {
    const t = convexTest(schema, modules);

    // Directly insert two roleAssignments for the same role in different scopes.
    // We use t.run() because assignRoleUnified's duplicate check uses matchesScope
    // which treats global as matching any scope — a known design choice.
    await t.run(async (ctx) => {
      // Global editor assignment
      await ctx.db.insert("roleAssignments", {
        tenantId: TENANT,
        userId: "alice",
        role: "editor",
        scope: undefined,
      });
      // Scoped editor assignment in p1
      await ctx.db.insert("roleAssignments", {
        tenantId: TENANT,
        userId: "alice",
        role: "editor",
        scope: { type: "project", id: "p1" },
      });
    });

    // Recompute should rebuild both scopes from source roleAssignments
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { editor: ["docs:read"] },
    });

    // Global scope: allowed
    const checkGlobal = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(checkGlobal.allowed).toBe(true);

    // p1 scope: allowed
    const checkP1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p1" },
    });
    expect(checkP1.allowed).toBe(true);

    // p2 scope: denied (not assigned)
    const checkP2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p2" },
    });
    expect(checkP2.allowed).toBe(false);
  });

  test("13.11 recompute after revokeAll + directGrant -> only grant remains", async () => {
    const t = convexTest(schema, modules);

    // Assign 3 roles
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["docs:view"],
    });
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["admin:manage"],
    });

    // Grant one permission directly
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "special:access",
    });

    // Revoke all roles from source table
    await t.mutation(api.unified.revokeAllRolesUnified, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: {},
      });

    // Recompute (no roles in source, but directGrant should remain)
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: {
        editor: ["docs:read", "docs:write"],
        viewer: ["docs:view"],
        admin: ["admin:manage"],
      },
    });

    // Only directGrant permission should be allowed
    const checkSpecial = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "special:access",
    });
    expect(checkSpecial.allowed).toBe(true);

    // Role-based permissions should be denied
    const checkRead = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(checkRead.allowed).toBe(false);

    const checkAdmin = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "admin:manage",
    });
    expect(checkAdmin.allowed).toBe(false);
  });

  test("13.12 recompute with deferred policy propagates to directGrant row", async () => {
    const t = convexTest(schema, modules);

    // Grant permission directly
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "billing:export",
    });

    // Assign role with same permission
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["billing:export"],
    });

    // Recompute with policyClassifications: { "billing:export": "deferred" }
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "alice",
      rolePermissionsMap: { admin: ["billing:export"] },
      policyClassifications: { "billing:export": "deferred" },
    });

    // Check DB: row should have directGrant=true AND policyResult="deferred"
    const row = await t.run(async (ctx) => {
      return await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "billing:export")
            .eq("scopeKey", "global")
        )
        .unique();
    });
    expect(row).not.toBeNull();
    expect(row!.directGrant).toBe(true);
    expect(row!.policyResult).toBe("deferred");
    expect(row!.sources).toContain("admin");
  });
});

// ============================================================================
// CATEGORY 14: Edge cases
// ============================================================================

describe("Category 14: Edge cases", () => {
  test("14.4 double revoke -> second returns false", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // First revoke succeeds
    const first = await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });
    expect(first).toBe(true);

    // Second revoke returns false (nothing to revoke)
    const second = await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });
    expect(second).toBe(false);
  });

  test("14.5 removeRelation non-existent -> false", async () => {
    const t = convexTest(schema, modules);

    const result = await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team-nonexistent",
    });
    expect(result).toBe(false);
  });

  test("14.6 double removeRelation -> second false", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    const first = await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(first).toBe(true);

    const second = await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(second).toBe(false);
  });

  test("14.7 grant same permission twice -> idempotent, reason updated", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      reason: "original reason",
    });

    // Grant again with updated reason
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      reason: "updated reason",
    });

    // Should still be allowed
    const check = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(check.allowed).toBe(true);

    // Verify only one effective row, with updated reason
    const row = await t.run(async (ctx) => {
      return await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "docs:read")
            .eq("scopeKey", "global")
        )
        .unique();
    });
    expect(row).not.toBeNull();
    expect(row!.reason).toBe("updated reason");
    expect(row!.directGrant).toBe(true);
  });

  test("14.8 deny same permission twice -> idempotent, reason updated", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
      reason: "first deny",
    });

    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
      reason: "second deny",
    });

    // Should be denied
    const check = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:delete",
    });
    expect(check.allowed).toBe(false);

    // Verify only one effective row, with updated reason
    const row = await t.run(async (ctx) => {
      return await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "docs:delete")
            .eq("scopeKey", "global")
        )
        .unique();
    });
    expect(row).not.toBeNull();
    expect(row!.reason).toBe("second deny");
    expect(row!.directDeny).toBe(true);
  });

  test("14.9 assignRole with empty rolePermissions -> role assigned, no effectivePermissions", async () => {
    const t = convexTest(schema, modules);

    const id = await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "empty-role",
      rolePermissions: [],
    });
    expect(id).toBeTruthy();

    // Role is assigned
    const roles = await t.query(api.indexed.getUserRolesFast, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(roles.length).toBe(1);
    expect(roles[0].role).toBe("empty-role");

    // No effective permissions
    const perms = await t.query(api.indexed.getUserPermissionsFast, {
      tenantId: TENANT,
      userId: "alice",
    });
    expect(perms.length).toBe(0);
  });

  test("14.10 recompute non-existent user -> no error", async () => {
    const t = convexTest(schema, modules);

    // Should not throw
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "non-existent-user",
      rolePermissionsMap: { editor: ["docs:read"] },
    });

    // Verify nothing was created
    const roles = await t.query(api.indexed.getUserRolesFast, {
      tenantId: TENANT,
      userId: "non-existent-user",
    });
    expect(roles.length).toBe(0);
  });

  test("14.11 setAttribute same key twice -> value updated not duplicated", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "theme",
      value: "dark",
    });

    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "alice",
      key: "theme",
      value: "light",
    });

    // Should have exactly one attribute row, not two
    const attrs = await t.run(async (ctx) => {
      return await ctx.db
        .query("userAttributes")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "alice")
        )
        .collect();
    });
    expect(attrs.length).toBe(1);
    expect(attrs[0].value).toBe("light");
  });

  test("14.12 removeAttribute non-existent key -> returns false", async () => {
    const t = convexTest(schema, modules);

    const result = await t.mutation(api.mutations.removeAttribute, {
      tenantId: TENANT,
      userId: "alice",
      key: "nonexistent",
    });
    expect(result).toBe(false);
  });

  test("14.13 addRelation with caveat -> stored in DB", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "editor",
      objectType: "document",
      objectId: "doc1",
      caveat: "requireMFA",
      caveatContext: { minLevel: 2 },
    });

    // Verify caveat is stored in source table
    const rel = await t.run(async (ctx) => {
      return await ctx.db
        .query("relationships")
        .withIndex("by_tenant_subject_relation_object", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectType", "user")
            .eq("subjectId", "alice")
            .eq("relation", "editor")
            .eq("objectType", "document")
            .eq("objectId", "doc1")
        )
        .unique();
    });
    expect(rel).not.toBeNull();
    expect(rel!.caveat).toBe("requireMFA");
    expect(rel!.caveatContext).toEqual({ minLevel: 2 });
  });

  test("14.14 checkPermission scoped on global-only data -> denied", async () => {
    const t = convexTest(schema, modules);

    // Assign role globally
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read"],
    });

    // Check with a specific scope: should be denied (data is global, not scoped)
    const check = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
      scope: { type: "project", id: "p1" },
    });
    expect(check.allowed).toBe(false);
  });

  test("14.15 assign with long permission string -> works", async () => {
    const t = convexTest(schema, modules);

    const longPermission = "a".repeat(500) + ":read";

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: [longPermission],
    });

    const check = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: longPermission,
    });
    expect(check.allowed).toBe(true);
  });

  test("14.16 multiple users same tenant -> no cross-user leakage", async () => {
    const t = convexTest(schema, modules);

    // Assign different roles to different users
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["admin:manage"],
    });

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "bob",
      role: "viewer",
      rolePermissions: ["docs:read"],
    });

    // Alice should NOT have bob's permission
    const aliceDocsRead = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(aliceDocsRead.allowed).toBe(false);

    // Bob should NOT have alice's permission
    const bobAdmin = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "bob",
      permission: "admin:manage",
    });
    expect(bobAdmin.allowed).toBe(false);

    // Each user has only their own permission
    const aliceAdmin = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "admin:manage",
    });
    expect(aliceAdmin.allowed).toBe(true);

    const bobRead = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "bob",
      permission: "docs:read",
    });
    expect(bobRead.allowed).toBe(true);
  });

  test("14.17 assign + deny + revoke role -> deny preserved", async () => {
    const t = convexTest(schema, modules);

    // Assign role with docs:read
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // Deny docs:read directly
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });

    // Revoke the role
    await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["docs:read", "docs:write"],
    });

    // docs:read should still be denied (directDeny preserved even after role revoked)
    const check = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(check.allowed).toBe(false);

    // Verify DB: directDeny row still present
    const row = await t.run(async (ctx) => {
      return await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "docs:read")
            .eq("scopeKey", "global")
        )
        .unique();
    });
    expect(row).not.toBeNull();
    expect(row!.directDeny).toBe(true);
    expect(row!.effect).toBe("deny");
  });

  test("14.18 grantPermission clears policyResult and policyName", async () => {
    const t = convexTest(schema, modules);

    // Assign role with deferred policy
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "admin",
      rolePermissions: ["billing:export"],
      policyClassifications: { "billing:export": "deferred" },
    });

    // Verify deferred tier
    const before = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "billing:export",
    });
    expect(before.tier).toBe("deferred");

    // Grant the same permission directly (should clear policy)
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "billing:export",
    });

    // Now should be cached (not deferred)
    const after = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "billing:export",
    });
    expect(after.allowed).toBe(true);
    expect(after.tier).toBe("cached");

    // Verify DB: policyResult and policyName cleared
    const row = await t.run(async (ctx) => {
      return await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "alice")
            .eq("permission", "billing:export")
            .eq("scopeKey", "global")
        )
        .unique();
    });
    expect(row).not.toBeNull();
    expect(row!.directGrant).toBe(true);
    expect(row!.policyResult).toBeUndefined();
    expect(row!.policyName).toBeUndefined();
  });

  test("14.19 checkPermission exact allow with policyResult=deny -> denied", async () => {
    const t = convexTest(schema, modules);

    // Insert an effective permission with allow effect but policyResult=deny
    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "alice",
        permission: "docs:read",
        scopeKey: "global",
        effect: "allow",
        sources: ["editor"],
        policyResult: "deny",
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);
  });

  test("14.20 checkPermission wildcard allow with policyResult=deny -> denied", async () => {
    const t = convexTest(schema, modules);

    // Insert a wildcard pattern with allow effect but policyResult=deny
    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "alice",
        permission: "docs:*",
        scopeKey: "global",
        effect: "allow",
        sources: ["editor"],
        policyResult: "deny",
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
    });

    // Check a permission that would match the wildcard
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "docs:read",
    });
    expect(result.allowed).toBe(false);
  });
});
