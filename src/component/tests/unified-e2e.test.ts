/**
 * End-to-end integration tests for the unified Authz flow.
 *
 * These tests exercise actual Convex function calls via convex-test,
 * covering the full lifecycle of permissions, roles, overrides, ReBAC,
 * and cross-tenant isolation.
 */

import { convexTest } from "convex-test";
import { describe, test, expect } from "vitest";
import schema from "../schema.js";
import { api } from "../_generated/api.js";

const modules = import.meta.glob("../**/*.ts");
const TENANT = "test-tenant";

describe("Unified Authz end-to-end integration", () => {
  test("full lifecycle: assign role, check permission, revoke, check again", async () => {
    const t = convexTest(schema, modules);

    // Assign role with permissions
    const assignmentId = await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["documents:read", "documents:update"],
    });
    expect(assignmentId).toBeTruthy();

    // Check permission — should be allowed (Tier 1 cached)
    const result1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(result1.allowed).toBe(true);
    expect(result1.tier).toBe("cached");

    // Revoke role
    const revoked = await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "editor",
      rolePermissions: ["documents:read", "documents:update"],
    });
    expect(revoked).toBe(true);

    // Check again — should be denied
    const result2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(result2.allowed).toBe(false);
  });

  test("deny override blocks previously granted permission", async () => {
    const t = convexTest(schema, modules);

    // Grant permission directly
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:delete",
    });

    // Check — should be allowed
    const result1 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:delete",
    });
    expect(result1.allowed).toBe(true);

    // Deny the same permission
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:delete",
    });

    // Check — should be denied
    const result2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:delete",
    });
    expect(result2.allowed).toBe(false);
  });

  test("deferred policy returns tier=deferred with policyName", async () => {
    const t = convexTest(schema, modules);

    // Assign role with a deferred policy classification
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

  test("RBAC and ReBAC work together in same tenant", async () => {
    const t = convexTest(schema, modules);

    // RBAC: assign role
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["documents:read"],
    });

    // ReBAC: add relation
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });

    // Check RBAC permission
    const rbacResult = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(rbacResult.allowed).toBe(true);

    // Check ReBAC relation
    const rebacResult = await t.query(api.indexed.hasRelationFast, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "member",
      objectType: "team",
      objectId: "team1",
    });
    expect(rebacResult).toBe(true);
  });

  test("recomputeUser rebuilds effective tables from source", async () => {
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

  test("permissions are isolated per tenant", async () => {
    const t = convexTest(schema, modules);

    // Assign role in tenant A
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: "tenant-a",
      userId: "alice",
      role: "admin",
      rolePermissions: ["documents:delete"],
    });

    // Check in tenant A — allowed
    const resultA = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-a",
      userId: "alice",
      permission: "documents:delete",
    });
    expect(resultA.allowed).toBe(true);

    // Check in tenant B — denied (different tenant)
    const resultB = await t.query(api.unified.checkPermission, {
      tenantId: "tenant-b",
      userId: "alice",
      permission: "documents:delete",
    });
    expect(resultB.allowed).toBe(false);
  });
});
