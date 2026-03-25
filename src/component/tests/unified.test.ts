/**
 * Tests for the unified tiered checkPermission query.
 */

import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "../schema.js";
import { api } from "../_generated/api.js";

const modules = import.meta.glob("../**/*.ts");
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
    expect(result.reason).toBe("Allowed by pattern");
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
          q.eq("tenantId", TENANT).eq("userId", "user_1").eq("role", "editor"),
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
            .eq("scopeKey", "global"),
        )
        .collect();
      expect(roles.length).toBe(1);
    });

    // Verify effectivePermissions table
    await t.run(async (ctx) => {
      const perms = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "user_1"),
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
          q.eq("tenantId", TENANT).eq("userId", "user_1").eq("role", "editor"),
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
          q.eq("tenantId", TENANT).eq("userId", "user_1"),
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
            .eq("scopeKey", "global"),
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

describe("revokeRoleUnified", () => {
  it("removes from source and effective tables", async () => {
    const t = convexTest(schema, modules);

    // Assign a role first
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "editor",
      rolePermissions: ["documents:read", "documents:write"],
      scope: undefined,
    });

    // Revoke it
    const result = await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "editor",
      rolePermissions: ["documents:read", "documents:write"],
      scope: undefined,
    });

    expect(result).toBe(true);

    // Verify roleAssignments is empty
    await t.run(async (ctx) => {
      const assignments = await ctx.db
        .query("roleAssignments")
        .withIndex("by_tenant_user_and_role", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "user_1").eq("role", "editor"),
        )
        .collect();
      expect(assignments.length).toBe(0);
    });

    // Verify effectiveRoles is empty
    await t.run(async (ctx) => {
      const roles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user_role_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("role", "editor")
            .eq("scopeKey", "global"),
        )
        .collect();
      expect(roles.length).toBe(0);
    });

    // Verify effectivePermissions is empty
    await t.run(async (ctx) => {
      const perms = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "user_1"),
        )
        .collect();
      expect(perms.length).toBe(0);
    });
  });

  it("preserves permission when another role still grants it", async () => {
    const t = convexTest(schema, modules);

    // Assign two roles that share "documents:read"
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "editor",
      rolePermissions: ["documents:read", "documents:write"],
      scope: undefined,
    });

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "viewer",
      rolePermissions: ["documents:read"],
      scope: undefined,
    });

    // Revoke editor — documents:read should remain because viewer still grants it
    const result = await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "editor",
      rolePermissions: ["documents:read", "documents:write"],
      scope: undefined,
    });

    expect(result).toBe(true);

    await t.run(async (ctx) => {
      // documents:read should still exist with source "viewer"
      const readPerm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "documents:read")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(readPerm).not.toBeNull();
      expect(readPerm!.sources).toEqual(["viewer"]);

      // documents:write should be deleted (only editor granted it)
      const writePerm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "documents:write")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(writePerm).toBeNull();
    });
  });

  it("returns false if role not found", async () => {
    const t = convexTest(schema, modules);

    const result = await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: "user_1",
      role: "nonexistent",
      rolePermissions: ["documents:read"],
      scope: undefined,
    });

    expect(result).toBe(false);
  });
});

describe("grantPermissionUnified", () => {
  it("writes to both overrides and effective tables", async () => {
    const t = convexTest(schema, modules);

    const overrideId = await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "billing:manage",
      scope: undefined,
      reason: "Admin approval",
    });

    expect(typeof overrideId).toBe("string");

    // Verify permissionOverrides
    await t.run(async (ctx) => {
      const overrides = await ctx.db
        .query("permissionOverrides")
        .withIndex("by_tenant_user_and_permission", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "billing:manage"),
        )
        .collect();
      expect(overrides.length).toBe(1);
      expect(overrides[0].effect).toBe("allow");
      expect(overrides[0].reason).toBe("Admin approval");
    });

    // Verify effectivePermissions
    await t.run(async (ctx) => {
      const perm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "billing:manage")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(perm).not.toBeNull();
      expect(perm!.effect).toBe("allow");
      expect(perm!.directGrant).toBe(true);
      expect(perm!.sources).toEqual([]);
    });
  });
});

describe("setAttributeWithRecompute", () => {
  it("writes attribute to userAttributes", async () => {
    const t = convexTest(schema, modules);

    const attrId = await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "user_1",
      key: "department",
      value: "engineering",
    });

    expect(typeof attrId).toBe("string");

    await t.run(async (ctx) => {
      const attr = await ctx.db
        .query("userAttributes")
        .withIndex("by_tenant_user_and_key", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("key", "department"),
        )
        .unique();
      expect(attr).not.toBeNull();
      expect(attr!.value).toBe("engineering");
    });
  });

  it("updates existing attribute", async () => {
    const t = convexTest(schema, modules);

    // Set attribute first time
    const id1 = await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "user_1",
      key: "department",
      value: "engineering",
    });

    // Set same attribute with new value
    const id2 = await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "user_1",
      key: "department",
      value: "sales",
    });

    // Same row should be updated (same ID)
    expect(id1).toBe(id2);

    await t.run(async (ctx) => {
      const attrs = await ctx.db
        .query("userAttributes")
        .withIndex("by_tenant_user_and_key", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("key", "department"),
        )
        .collect();
      // Only one row should exist
      expect(attrs.length).toBe(1);
      expect(attrs[0].value).toBe("sales");
    });
  });

  it("updates effectivePermissions based on policy re-evaluation", async () => {
    const t = convexTest(schema, modules);

    // First assign a role with a deferred policy
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

    // Verify it starts as deferred
    await t.run(async (ctx) => {
      const perm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "billing:manage")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(perm).not.toBeNull();
      expect(perm!.policyResult).toBe("deferred");
      expect(perm!.policyName).toBe("billing:manage");
    });

    // Now set an attribute and provide policy re-evaluation results
    // Simulate: attribute change causes policy to evaluate to "deny"
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "user_1",
      key: "mfa_enabled",
      value: false,
      policyReEvaluations: {
        "billing:manage": "deny",
      },
    });

    // Verify effectivePermissions was updated
    await t.run(async (ctx) => {
      const perm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "billing:manage")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(perm).not.toBeNull();
      expect(perm!.policyResult).toBe("deny");
    });

    // Set attribute again so policy now evaluates to "allow"
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: "user_1",
      key: "mfa_enabled",
      value: true,
      policyReEvaluations: {
        "billing:manage": "allow",
      },
    });

    // Verify effectivePermissions was restored to allow
    await t.run(async (ctx) => {
      const perm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "billing:manage")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(perm).not.toBeNull();
      expect(perm!.policyResult).toBe("allow");
      expect(perm!.effect).toBe("allow");
    });
  });
});

describe("addRelationUnified", () => {
  it("writes to both relationships and effectiveRelationships", async () => {
    const t = convexTest(schema, modules);

    const relationId = await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "member",
      objectType: "org",
      objectId: "org_1",
    });

    expect(typeof relationId).toBe("string");

    // Verify relationships (source of truth)
    await t.run(async (ctx) => {
      const rels = await ctx.db
        .query("relationships")
        .withIndex("by_tenant_subject_relation_object", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectType", "user")
            .eq("subjectId", "user_1")
            .eq("relation", "member")
            .eq("objectType", "org")
            .eq("objectId", "org_1"),
        )
        .collect();
      expect(rels.length).toBe(1);
      expect(rels[0].relation).toBe("member");
      expect(rels[0].createdAt).toBeGreaterThan(0);
    });

    // Verify effectiveRelationships (materialized)
    await t.run(async (ctx) => {
      const effRels = await ctx.db
        .query("effectiveRelationships")
        .withIndex("by_tenant_subject_relation_object", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectKey", "user:user_1")
            .eq("relation", "member")
            .eq("objectKey", "org:org_1"),
        )
        .collect();
      expect(effRels.length).toBe(1);
      expect(effRels[0].paths[0].isDirect).toBe(true);
      expect(effRels[0].paths[0].baseEffectiveId).toBeUndefined();
      expect(effRels[0].paths[0].depth).toBe(0);
      expect(effRels[0].subjectType).toBe("user");
      expect(effRels[0].subjectId).toBe("user_1");
      expect(effRels[0].objectType).toBe("org");
      expect(effRels[0].objectId).toBe("org_1");
    });
  });

  it("is idempotent — returns same ID for duplicate", async () => {
    const t = convexTest(schema, modules);

    const id1 = await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "member",
      objectType: "org",
      objectId: "org_1",
    });

    const id2 = await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "member",
      objectType: "org",
      objectId: "org_1",
    });

    expect(id1).toBe(id2);

    // Verify only one row in relationships
    await t.run(async (ctx) => {
      const rels = await ctx.db
        .query("relationships")
        .withIndex("by_tenant_subject_relation_object", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectType", "user")
            .eq("subjectId", "user_1")
            .eq("relation", "member")
            .eq("objectType", "org")
            .eq("objectId", "org_1"),
        )
        .collect();
      expect(rels.length).toBe(1);
    });
  });

  it("stores caveat and caveatContext", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "viewer",
      objectType: "document",
      objectId: "doc_1",
      caveat: "ipAllowlist",
      caveatContext: { allowedIPs: ["10.0.0.0/8"] },
    });

    await t.run(async (ctx) => {
      const rel = await ctx.db
        .query("relationships")
        .withIndex("by_tenant_subject_relation_object", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectType", "user")
            .eq("subjectId", "user_1")
            .eq("relation", "viewer")
            .eq("objectType", "document")
            .eq("objectId", "doc_1"),
        )
        .unique();
      expect(rel).not.toBeNull();
      expect(rel!.caveat).toBe("ipAllowlist");
      expect(rel!.caveatContext).toEqual({ allowedIPs: ["10.0.0.0/8"] });
    });
  });
});

describe("removeRelationUnified", () => {
  it("removes from both tables", async () => {
    const t = convexTest(schema, modules);

    // Add a relation first
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "member",
      objectType: "org",
      objectId: "org_1",
    });

    // Remove it
    const result = await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "member",
      objectType: "org",
      objectId: "org_1",
    });

    expect(result).toBe(true);

    // Verify relationships is empty
    await t.run(async (ctx) => {
      const rels = await ctx.db
        .query("relationships")
        .withIndex("by_tenant_subject_relation_object", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectType", "user")
            .eq("subjectId", "user_1")
            .eq("relation", "member")
            .eq("objectType", "org")
            .eq("objectId", "org_1"),
        )
        .collect();
      expect(rels.length).toBe(0);
    });

    // Verify effectiveRelationships is empty
    await t.run(async (ctx) => {
      const effRels = await ctx.db
        .query("effectiveRelationships")
        .withIndex("by_tenant_subject_relation_object", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("subjectKey", "user:user_1")
            .eq("relation", "member")
            .eq("objectKey", "org:org_1"),
        )
        .collect();
      expect(effRels.length).toBe(0);
    });
  });

  it("returns false if not found", async () => {
    const t = convexTest(schema, modules);

    const result = await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "member",
      objectType: "org",
      objectId: "nonexistent",
    });

    expect(result).toBe(false);
  });
});

describe("recomputeUser", () => {
  it("recomputeUser rebuilds effectivePermissions from roleAssignments", async () => {
    const t = convexTest(schema, modules);

    // Insert a roleAssignment directly (bypassing the unified mutation)
    await t.run(async (ctx) => {
      await ctx.db.insert("roleAssignments", {
        tenantId: TENANT,
        userId: "user_1",
        role: "editor",
        scope: undefined,
      });
    });

    // Call recomputeUser with the role->permissions map
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "user_1",
      rolePermissionsMap: {
        editor: ["documents:read", "documents:write"],
      },
    });

    // Verify effectivePermissions is populated
    await t.run(async (ctx) => {
      const perms = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "user_1"),
        )
        .collect();
      expect(perms.length).toBe(2);
      const permNames = perms.map((p) => p.permission).sort();
      expect(permNames).toEqual(["documents:read", "documents:write"]);
      expect(perms[0].sources).toContain("editor");
      expect(perms[0].effect).toBe("allow");
    });

    // Verify effectiveRoles is populated
    await t.run(async (ctx) => {
      const roles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", TENANT).eq("userId", "user_1"),
        )
        .collect();
      expect(roles.length).toBe(1);
      expect(roles[0].role).toBe("editor");
      expect(roles[0].scopeKey).toBe("global");
    });
  });

  it("recomputeUser preserves directGrant entries", async () => {
    const t = convexTest(schema, modules);

    // Create a direct grant via grantPermissionUnified
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "billing:manage",
      scope: undefined,
      reason: "Special admin access",
    });

    // Insert a roleAssignment
    await t.run(async (ctx) => {
      await ctx.db.insert("roleAssignments", {
        tenantId: TENANT,
        userId: "user_1",
        role: "viewer",
        scope: undefined,
      });
    });

    // Recompute — the direct grant should survive
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "user_1",
      rolePermissionsMap: {
        viewer: ["documents:read"],
      },
    });

    // Verify the direct grant is still there
    await t.run(async (ctx) => {
      const perm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "billing:manage")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(perm).not.toBeNull();
      expect(perm!.directGrant).toBe(true);
      expect(perm!.effect).toBe("allow");
      expect(perm!.reason).toBe("Special admin access");
    });

    // Verify role-derived permission was also written
    await t.run(async (ctx) => {
      const perm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "documents:read")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(perm).not.toBeNull();
      expect(perm!.sources).toContain("viewer");
    });
  });

  it("recomputeUser clears stale effective entries", async () => {
    const t = convexTest(schema, modules);

    // Manually insert a stale effectivePermission (not a direct grant)
    await t.run(async (ctx) => {
      await ctx.db.insert("effectivePermissions", {
        tenantId: TENANT,
        userId: "user_1",
        permission: "stale:permission",
        scopeKey: "global",
        effect: "allow",
        sources: ["old-role"],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
    });

    // Insert a roleAssignment for a different role
    await t.run(async (ctx) => {
      await ctx.db.insert("roleAssignments", {
        tenantId: TENANT,
        userId: "user_1",
        role: "viewer",
        scope: undefined,
      });
    });

    // Recompute — stale entry should be gone
    await t.mutation(api.unified.recomputeUser, {
      tenantId: TENANT,
      userId: "user_1",
      rolePermissionsMap: {
        viewer: ["documents:read"],
      },
    });

    // Stale permission should be gone
    await t.run(async (ctx) => {
      const stalePerm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "stale:permission")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(stalePerm).toBeNull();
    });

    // New permission should be present
    await t.run(async (ctx) => {
      const newPerm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "documents:read")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(newPerm).not.toBeNull();
      expect(newPerm!.sources).toContain("viewer");
    });
  });
});

describe("denyPermissionUnified", () => {
  it("overrides existing allow", async () => {
    const t = convexTest(schema, modules);

    // First grant the permission
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "billing:manage",
      scope: undefined,
    });

    // Verify it's allowed
    await t.run(async (ctx) => {
      const perm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "billing:manage")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(perm!.effect).toBe("allow");
      expect(perm!.directGrant).toBe(true);
    });

    // Now deny it
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "billing:manage",
      scope: undefined,
      reason: "Compliance violation",
    });

    // Verify override is now deny
    await t.run(async (ctx) => {
      const overrides = await ctx.db
        .query("permissionOverrides")
        .withIndex("by_tenant_user_and_permission", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "billing:manage"),
        )
        .collect();
      expect(overrides.length).toBe(1);
      expect(overrides[0].effect).toBe("deny");
    });

    // Verify effectivePermissions is now deny with directDeny
    await t.run(async (ctx) => {
      const perm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", TENANT)
            .eq("userId", "user_1")
            .eq("permission", "billing:manage")
            .eq("scopeKey", "global"),
        )
        .unique();
      expect(perm).not.toBeNull();
      expect(perm!.effect).toBe("deny");
      expect(perm!.directDeny).toBe(true);
      expect(perm!.reason).toBe("Compliance violation");
    });
  });
});

describe("ReBAC → permission bridge", () => {
  it("addRelationUnified with relationPermissions writes to effectivePermissions", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "viewer",
      objectType: "document",
      objectId: "doc1",
      relationPermissions: {
        "document:viewer": ["documents:read"],
        "document:editor": ["documents:read", "documents:update"],
      },
    });

    // alice should now have documents:read scoped to document:doc1
    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
      scope: { type: "document", id: "doc1" },
    });
    expect(result.allowed).toBe(true);

    // Not in a different scope
    const result2 = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
      scope: { type: "document", id: "doc2" },
    });
    expect(result2.allowed).toBe(false);
  });

  it("removeRelationUnified cleans up relation-derived permissions", async () => {
    const t = convexTest(schema, modules);

    const relPerms = {
      "document:viewer": ["documents:read"],
    };

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "viewer",
      objectType: "document",
      objectId: "doc1",
      relationPermissions: relPerms,
    });

    // Verify permission exists
    const before = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
      scope: { type: "document", id: "doc1" },
    });
    expect(before.allowed).toBe(true);

    // Remove relation
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "viewer",
      objectType: "document",
      objectId: "doc1",
      relationPermissions: relPerms,
    });

    // Permission should be gone
    const after = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
      scope: { type: "document", id: "doc1" },
    });
    expect(after.allowed).toBe(false);
  });

  it("relation + role both grant same permission — removing relation preserves role grant", async () => {
    const t = convexTest(schema, modules);

    // Assign role that grants documents:read globally
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: "alice",
      role: "viewer",
      rolePermissions: ["documents:read"],
    });

    // Add relation that also grants documents:read scoped to doc1
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "viewer",
      objectType: "document",
      objectId: "doc1",
      relationPermissions: { "document:viewer": ["documents:read"] },
    });

    // Remove the relation
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "alice",
      relation: "viewer",
      objectType: "document",
      objectId: "doc1",
      relationPermissions: { "document:viewer": ["documents:read"] },
    });

    // Global role-based permission should still work
    const global = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "alice",
      permission: "documents:read",
    });
    expect(global.allowed).toBe(true);
  });

  it("editor relation grants multiple permissions", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "bob",
      relation: "editor",
      objectType: "document",
      objectId: "doc1",
      relationPermissions: {
        "document:editor": [
          "documents:read",
          "documents:update",
          "documents:delete",
        ],
      },
    });

    // All three permissions should be granted
    for (const perm of [
      "documents:read",
      "documents:update",
      "documents:delete",
    ]) {
      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "bob",
        permission: perm,
        scope: { type: "document", id: "doc1" },
      });
      expect(result.allowed).toBe(true);
    }

    // Not granted globally
    const global = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: "bob",
      permission: "documents:read",
    });
    expect(global.allowed).toBe(false);
  });
});
