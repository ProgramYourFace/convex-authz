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
