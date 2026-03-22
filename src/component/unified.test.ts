/**
 * Tests for the unified tiered checkPermission query.
 */

import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "./schema.js";
import { api } from "./_generated/api.js";

const modules = import.meta.glob("./**/*.ts");
const TENANT = "test-tenant";

describe("unified checkPermission", () => {
  it("returns allowed=true from effectivePermissions cache (Tier 1)", async () => {
    const t = convexTest(schema, modules);

    // Pre-populate effectivePermissions directly
    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "user_1",
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
      userId: "user_1",
      permission: "documents:read",
    });

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe("cached");
    expect(result.reason).toBe("Allowed");
  });

  it("returns allowed=false when no permission exists", async () => {
    const t = convexTest(schema, modules);

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "documents:read",
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("No permission granted");
    expect(result.tier).toBe("none");
  });

  it("expired effectivePermission returns false", async () => {
    const t = convexTest(schema, modules);

    const pastTime = Date.now() - 10_000;

    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "user_1",
        permission: "documents:read",
        scopeKey: "global",
        effect: "allow",
        sources: ["editor"],
        expiresAt: pastTime,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "documents:read",
    });

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe("none");
  });

  it("deferred policy result returns tier=deferred with policyName", async () => {
    const t = convexTest(schema, modules);

    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "user_1",
        permission: "billing:manage",
        scopeKey: "global",
        effect: "allow",
        sources: ["admin"],
        policyResult: "deferred",
        policyName: "requireMFA",
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "billing:manage",
    });

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe("deferred");
    expect(result.policyName).toBe("requireMFA");
  });

  it("deny effect returns allowed=false", async () => {
    const t = convexTest(schema, modules);

    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "user_1",
        permission: "documents:delete",
        scopeKey: "global",
        effect: "deny",
        sources: [],
        reason: "Restricted action",
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "documents:delete",
    });

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe("cached");
    expect(result.reason).toBe("Restricted action");
  });

  it("wildcard pattern match works (documents:* matches documents:read)", async () => {
    const t = convexTest(schema, modules);

    // Insert a wildcard permission — no exact "documents:read" row
    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "user_1",
        permission: "documents:*",
        scopeKey: "global",
        effect: "allow",
        sources: ["admin"],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "documents:read",
    });

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe("cached");
    expect(result.reason).toBe("Allowed by wildcard pattern");
  });

  it("deny pattern takes precedence over allow pattern", async () => {
    const t = convexTest(schema, modules);

    await t.run(async (ctx) => {
      // Broad allow
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "user_1",
        permission: "documents:*",
        scopeKey: "global",
        effect: "allow",
        sources: ["admin"],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });

      // Specific deny
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "user_1",
        permission: "documents:delete",
        scopeKey: "global",
        effect: "deny",
        sources: [],
        reason: "Restricted",
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "documents:delete",
    });

    // The exact deny (Tier 1) should win over the wildcard allow (Tier 2)
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("Restricted");
  });
});

describe("assignRoleUnified", () => {
  it("writes to both roleAssignments and effectivePermissions", async () => {
    const t = convexTest(schema, modules);

    const assignmentId = await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "editor",
      rolePermissions: ["documents:read", "documents:write"],
      scope: undefined,
    });

    expect(typeof assignmentId).toBe("string");

    // Verify source table has the row
    await t.run(async (ctx) => {
      const assignments = await ctx.db
        .query("roleAssignments")
        .withIndex("by_tenant_user_and_role", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "user_1").eq("role", "editor")
        )
        .collect();
      expect(assignments.length).toBe(1);
      expect(assignments[0].role).toBe("editor");
    });

    // Verify effectiveRoles table
    await t.run(async (ctx) => {
      const roles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user_role_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("role", "editor")
            .eq("scopeKey", "global")
        )
        .collect();
      expect(roles.length).toBe(1);
    });

    // Verify effectivePermissions table
    await t.run(async (ctx) => {
      const perms = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "user_1")
        )
        .collect();
      expect(perms.length).toBe(2);
      const permNames = perms.map((p) => p.permission).sort();
      expect(permNames).toEqual(["documents:read", "documents:write"]);
      expect(perms[0].sources).toContain("editor");
      expect(perms[0].effect).toBe("allow");
    });
  });

  it("returns existing ID for duplicate assignment", async () => {
    const t = convexTest(schema, modules);

    const id1 = await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "editor",
      rolePermissions: ["documents:read"],
      scope: undefined,
    });

    const id2 = await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "editor",
      rolePermissions: ["documents:read"],
      scope: undefined,
    });

    expect(id1).toBe(id2);

    // Verify only one row in roleAssignments
    await t.run(async (ctx) => {
      const assignments = await ctx.db
        .query("roleAssignments")
        .withIndex("by_tenant_user_and_role", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "user_1").eq("role", "editor")
        )
        .collect();
      expect(assignments.length).toBe(1);
    });
  });

  it("skips permissions where policy is deny", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "editor",
      rolePermissions: ["documents:read", "documents:delete"],
      scope: undefined,
      policyClassifications: {
        "documents:read": null,
        "documents:delete": "deny",
      },
    });

    await t.run(async (ctx) => {
      const perms = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "user_1")
        )
        .collect();
      const permNames = perms.map((p) => p.permission);
      expect(permNames).toContain("documents:read");
      expect(permNames).not.toContain("documents:delete");
    });
  });

  it("marks deferred policy in effectivePermissions", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "admin",
      rolePermissions: ["billing:manage"],
      scope: undefined,
      policyClassifications: {
        "billing:manage": "deferred",
      },
    });

    await t.run(async (ctx) => {
      const perm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "billing:manage")
            .eq("scopeKey", "global")
        )
        .unique();
      expect(perm).not.toBeNull();
      expect(perm!.policyResult).toBe("deferred");
      expect(perm!.policyName).toBe("billing:manage");
      expect(perm!.effect).toBe("allow");
      expect(perm!.sources).toEqual(["admin"]);
    });
  });
});
