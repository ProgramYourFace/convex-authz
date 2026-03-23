/**
 * Real backend benchmark: seeds large data and measures actual Convex latency.
 *
 * Run:
 *   npx convex run benchmark-real:seedLargeData
 *   npx convex run benchmark-real:benchmarkReads
 *   npx convex run benchmark-real:benchmarkWrites
 *   npx convex run benchmark-real:cleanup
 */
import { mutation, query, action } from "./_generated/server.js";
import { api, components } from "./_generated/api.js";
import { Authz, definePermissions, defineRoles } from "@djpanda/convex-authz";
import { v } from "convex/values";

const permissions = definePermissions({
  documents: { create: true, read: true, update: true, delete: true },
  settings: { view: true, manage: true },
  users: { invite: true, remove: true, manage: true },
  billing: { view: true, manage: true },
});

const roles = defineRoles(permissions, {
  admin: {
    documents: ["create", "read", "update", "delete"],
    settings: ["view", "manage"],
    users: ["invite", "remove", "manage"],
    billing: ["view", "manage"],
  },
  editor: {
    documents: ["create", "read", "update"],
    settings: ["view"],
  },
  viewer: {
    documents: ["read"],
    settings: ["view"],
  },
  billing_admin: {
    billing: ["view", "manage"],
    settings: ["view"],
  },
});

const authz = new Authz(components.authz, { permissions, roles, tenantId: "benchmark" });

const ROLE_NAMES = ["admin", "editor", "viewer", "billing_admin"] as const;

/**
 * Seed large dataset: creates N users with roles in batches.
 * Call multiple times — it's idempotent (skips existing users by email).
 */
export const seedBatch = mutation({
  args: {
    batchStart: v.number(),
    batchSize: v.number(),
    orgId: v.id("orgs"),
  },
  returns: v.object({ created: v.number(), skipped: v.number() }),
  handler: async (ctx, args) => {
    let created = 0;
    let skipped = 0;

    for (let i = args.batchStart; i < args.batchStart + args.batchSize; i++) {
      const email = `bench-user-${i}@benchmark.com`;
      const existing = await ctx.db
        .query("users")
        .withIndex("by_email", (q) => q.eq("email", email))
        .first();

      if (existing) {
        skipped++;
        continue;
      }

      const userId = await ctx.db.insert("users", {
        name: `Bench User ${i}`,
        email,
      });

      await ctx.db.insert("org_members", {
        orgId: args.orgId,
        userId,
      });

      const role = ROLE_NAMES[i % ROLE_NAMES.length];
      await authz.assignRole(
        ctx,
        String(userId),
        role as keyof typeof roles,
        { type: "org", id: String(args.orgId) },
      );

      created++;
    }

    return { created, skipped };
  },
});

/**
 * Orchestrator: seeds large data in batches via scheduled mutations.
 */
export const seedLargeData = action({
  args: {
    totalUsers: v.optional(v.number()),
    batchSize: v.optional(v.number()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const total = args.totalUsers ?? 200;
    const batchSize = args.batchSize ?? 20;

    // Create or get benchmark org
    let orgId = await ctx.runQuery(api.benchmarkReal.getBenchOrg);
    if (!orgId) {
      orgId = await ctx.runMutation(api.benchmarkReal.createBenchOrg);
    }

    console.log(`Seeding ${total} users in batches of ${batchSize}...`);

    for (let start = 0; start < total; start += batchSize) {
      const result = await ctx.runMutation(api.benchmarkReal.seedBatch, {
        batchStart: start,
        batchSize: Math.min(batchSize, total - start),
        orgId,
      });
      console.log(`Batch ${start}-${start + batchSize}: created=${result.created}, skipped=${result.skipped}`);
    }

    return `Seeded ${total} users in benchmark org`;
  },
});

export const getBenchOrg = query({
  args: {},
  returns: v.union(v.id("orgs"), v.null()),
  handler: async (ctx) => {
    const org = await ctx.db
      .query("orgs")
      .withIndex("by_slug", (q) => q.eq("slug", "benchmark"))
      .first();
    return org?._id ?? null;
  },
});

export const createBenchOrg = mutation({
  args: {},
  returns: v.id("orgs"),
  handler: async (ctx) => {
    return await ctx.db.insert("orgs", {
      name: "Benchmark Corp",
      slug: "benchmark",
      plan: "enterprise",
    });
  },
});

/**
 * Benchmark reads: measures actual Convex query latency.
 * Runs N permission checks and reports timing.
 */
export const benchmarkReads = action({
  args: {
    iterations: v.optional(v.number()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const iterations = args.iterations ?? 50;

    // Find a benchmark user
    const orgId = await ctx.runQuery(api.benchmarkReal.getBenchOrg);
    if (!orgId) return "No benchmark org found. Run seedLargeData first.";

    const userId = await ctx.runQuery(api.benchmarkReal.findBenchUser, {
      index: 25,
    });
    if (!userId) return "No benchmark users found. Run seedLargeData first.";

    console.log(`Running ${iterations} iterations against user ${userId}...`);

    // Benchmark 1: Single permission check (allowed)
    const allowedTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const start = Date.now();
      await ctx.runQuery(api.benchmarkReal.checkPermissionDirect, {
        userId,
        permission: "documents:read",
        orgId,
      });
      allowedTimes.push(Date.now() - start);
    }

    // Benchmark 2: Single permission check (denied)
    const deniedTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const start = Date.now();
      await ctx.runQuery(api.benchmarkReal.checkPermissionDirect, {
        userId,
        permission: "billing:manage",
        orgId,
      });
      deniedTimes.push(Date.now() - start);
    }

    // Benchmark 3: Check all 11 permissions
    const allPermsTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const start = Date.now();
      await ctx.runQuery(api.benchmarkReal.checkAllPermsDirect, {
        userId,
        orgId,
      });
      allPermsTimes.push(Date.now() - start);
    }

    // Benchmark 4: Wrong scope (cross-tenant denied)
    const wrongScopeTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const start = Date.now();
      await ctx.runQuery(api.benchmarkReal.checkPermissionDirect, {
        userId,
        permission: "documents:read",
        // no orgId = global scope = should be denied for org-scoped role
      });
      wrongScopeTimes.push(Date.now() - start);
    }

    const median = (arr: number[]) => {
      const sorted = [...arr].sort((a, b) => a - b);
      return sorted[Math.floor(sorted.length / 2)];
    };
    const p95 = (arr: number[]) => {
      const sorted = [...arr].sort((a, b) => a - b);
      return sorted[Math.ceil(0.95 * sorted.length) - 1];
    };
    const avg = (arr: number[]) => arr.reduce((a, b) => a + b, 0) / arr.length;

    const report = [
      `\n========== REAL CONVEX BENCHMARK (${iterations} iterations) ==========`,
      ``,
      `checkPermission (ALLOWED):`,
      `  median: ${median(allowedTimes)}ms  p95: ${p95(allowedTimes)}ms  avg: ${avg(allowedTimes).toFixed(1)}ms`,
      ``,
      `checkPermission (DENIED):`,
      `  median: ${median(deniedTimes)}ms  p95: ${p95(deniedTimes)}ms  avg: ${avg(deniedTimes).toFixed(1)}ms`,
      ``,
      `checkAllPermissions (11 perms):`,
      `  median: ${median(allPermsTimes)}ms  p95: ${p95(allPermsTimes)}ms  avg: ${avg(allPermsTimes).toFixed(1)}ms`,
      ``,
      `checkPermission (wrong scope):`,
      `  median: ${median(wrongScopeTimes)}ms  p95: ${p95(wrongScopeTimes)}ms  avg: ${avg(wrongScopeTimes).toFixed(1)}ms`,
      ``,
      `==========================================================`,
    ].join("\n");

    console.log(report);
    return report;
  },
});

/**
 * Benchmark writes: measures actual mutation latency.
 */
export const benchmarkWrites = action({
  args: {
    iterations: v.optional(v.number()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const iterations = args.iterations ?? 10;

    const orgId = await ctx.runQuery(api.benchmarkReal.getBenchOrg);
    if (!orgId) return "No benchmark org found. Run seedLargeData first.";

    // Create temp users for write benchmarks
    const assignTimes: number[] = [];
    const revokeTimes: number[] = [];
    const grantTimes: number[] = [];
    const denyTimes: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const userId = await ctx.runMutation(api.benchmarkReal.createTempUser, {
        index: 10000 + i,
        orgId,
      });

      // Benchmark assignRole
      const start1 = Date.now();
      await ctx.runMutation(api.benchmarkReal.assignRoleDirect, {
        userId,
        role: "editor",
        orgId,
      });
      assignTimes.push(Date.now() - start1);

      // Benchmark grantPermission
      const start2 = Date.now();
      await ctx.runMutation(api.benchmarkReal.grantPermissionDirect, {
        userId,
        permission: "documents:delete",
        orgId,
      });
      grantTimes.push(Date.now() - start2);

      // Benchmark denyPermission
      const start3 = Date.now();
      await ctx.runMutation(api.benchmarkReal.denyPermissionDirect, {
        userId,
        permission: "documents:delete",
        orgId,
      });
      denyTimes.push(Date.now() - start3);

      // Benchmark revokeRole
      const start4 = Date.now();
      await ctx.runMutation(api.benchmarkReal.revokeRoleDirect, {
        userId,
        role: "editor",
        orgId,
      });
      revokeTimes.push(Date.now() - start4);
    }

    const median = (arr: number[]) => {
      const sorted = [...arr].sort((a, b) => a - b);
      return sorted[Math.floor(sorted.length / 2)];
    };
    const avg = (arr: number[]) => arr.reduce((a, b) => a + b, 0) / arr.length;

    const report = [
      `\n========== REAL CONVEX WRITE BENCHMARK (${iterations} iterations) ==========`,
      ``,
      `assignRole:       median: ${median(assignTimes)}ms  avg: ${avg(assignTimes).toFixed(1)}ms`,
      `revokeRole:       median: ${median(revokeTimes)}ms  avg: ${avg(revokeTimes).toFixed(1)}ms`,
      `grantPermission:  median: ${median(grantTimes)}ms  avg: ${avg(grantTimes).toFixed(1)}ms`,
      `denyPermission:   median: ${median(denyTimes)}ms  avg: ${avg(denyTimes).toFixed(1)}ms`,
      ``,
      `================================================================`,
    ].join("\n");

    console.log(report);
    return report;
  },
});

// ── Internal helpers ──────────────────────────────────────────────

export const findBenchUser = query({
  args: { index: v.number() },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, args) => {
    const email = `bench-user-${args.index}@benchmark.com`;
    const user = await ctx.db
      .query("users")
      .withIndex("by_email", (q) => q.eq("email", email))
      .first();
    return user ? String(user._id) : null;
  },
});

export const checkPermissionDirect = query({
  args: {
    userId: v.string(),
    permission: v.string(),
    orgId: v.optional(v.id("orgs")),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const scope = args.orgId ? { type: "org", id: String(args.orgId) } : undefined;
    return await authz.can(ctx, args.userId, args.permission, scope);
  },
});

export const checkAllPermsDirect = query({
  args: {
    userId: v.string(),
    orgId: v.id("orgs"),
  },
  returns: v.record(v.string(), v.boolean()),
  handler: async (ctx, args) => {
    const scope = { type: "org", id: String(args.orgId) };
    const perms = [
      "documents:create", "documents:read", "documents:update", "documents:delete",
      "settings:view", "settings:manage",
      "users:invite", "users:remove", "users:manage",
      "billing:view", "billing:manage",
    ];
    const results: Record<string, boolean> = {};
    for (const p of perms) {
      results[p] = await authz.can(ctx, args.userId, p, scope);
    }
    return results;
  },
});

export const createTempUser = mutation({
  args: { index: v.number(), orgId: v.id("orgs") },
  returns: v.string(),
  handler: async (ctx, args) => {
    const userId = await ctx.db.insert("users", {
      name: `Temp User ${args.index}`,
      email: `temp-${args.index}-${Date.now()}@benchmark.com`,
    });
    await ctx.db.insert("org_members", { orgId: args.orgId, userId });
    return String(userId);
  },
});

export const assignRoleDirect = mutation({
  args: { userId: v.string(), role: v.string(), orgId: v.id("orgs") },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authz.assignRole(
      ctx, args.userId, args.role as keyof typeof roles,
      { type: "org", id: String(args.orgId) },
    );
  },
});

export const revokeRoleDirect = mutation({
  args: { userId: v.string(), role: v.string(), orgId: v.id("orgs") },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authz.revokeRole(
      ctx, args.userId, args.role as keyof typeof roles,
      { type: "org", id: String(args.orgId) },
    );
  },
});

export const grantPermissionDirect = mutation({
  args: { userId: v.string(), permission: v.string(), orgId: v.id("orgs") },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authz.grantPermission(
      ctx, args.userId, args.permission,
      { type: "org", id: String(args.orgId) },
    );
  },
});

export const denyPermissionDirect = mutation({
  args: { userId: v.string(), permission: v.string(), orgId: v.id("orgs") },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authz.denyPermission(
      ctx, args.userId, args.permission,
      { type: "org", id: String(args.orgId) },
    );
  },
});

/**
 * Cleanup: remove benchmark data
 */
export const cleanup = mutation({
  args: {},
  returns: v.number(),
  handler: async (ctx) => {
    let deleted = 0;
    // Batched cleanup — delete up to 100 benchmark users per call
    const users = await ctx.db
      .query("users")
      .withIndex("by_email")
      .take(200);
    for (const user of users) {
      if (user.email.includes("@benchmark.com")) {
        const memberships = await ctx.db
          .query("org_members")
          .withIndex("by_user", (q) => q.eq("userId", user._id))
          .take(50);
        for (const m of memberships) await ctx.db.delete(m._id);
        await ctx.db.delete(user._id);
        deleted++;
        if (deleted >= 100) break; // batch limit
      }
    }
    return deleted;
  },
});

export const cleanupOrg = mutation({
  args: {},
  returns: v.boolean(),
  handler: async (ctx) => {
    const org = await ctx.db
      .query("orgs")
      .withIndex("by_slug", (q) => q.eq("slug", "benchmark"))
      .first();
    if (org) {
      await ctx.db.delete(org._id);
      return true;
    }
    return false;
  },
});

export const cleanupAll = action({
  args: {},
  returns: v.number(),
  handler: async (ctx) => {
    let totalDeleted = 0;
    // Keep calling cleanup until no more benchmark users
    while (true) {
      const deleted = await ctx.runMutation(api.benchmarkReal.cleanup, {});
      totalDeleted += deleted;
      if (deleted === 0) break;
      console.log(`Deleted ${deleted} users (total: ${totalDeleted})`);
    }
    await ctx.runMutation(api.benchmarkReal.cleanupOrg, {});
    console.log(`Cleanup complete: ${totalDeleted} users removed`);
    return totalDeleted;
  },
});
