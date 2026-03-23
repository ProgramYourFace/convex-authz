/**
 * Integration benchmark: tests the Authz component through the full app stack.
 *
 * Unlike component-level benchmarks (which test unified.ts directly),
 * these exercise the real path: app mutation/query → Authz client → component functions.
 *
 * Run: npx vitest run example/convex/benchmark.test.ts
 */
import { convexTest } from "convex-test";
import { describe, test, expect } from "vitest";
import schema from "./schema.js";
import { api } from "./_generated/api.js";
import authzTest from "@djpanda/convex-authz/test";

const ITERATIONS = 30;

function median(arr: number[]): number {
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function percentile(arr: number[], p: number): number {
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

function formatStats(label: string, times: number[]): string {
  return [
    `\n=== ${label} (${times.length} iterations) ===`,
    `  median: ${median(times).toFixed(2)}ms`,
    `  p95:    ${percentile(times, 95).toFixed(2)}ms`,
    `  min:    ${Math.min(...times).toFixed(2)}ms`,
    `  max:    ${Math.max(...times).toFixed(2)}ms`,
    `  avg:    ${(times.reduce((a, b) => a + b, 0) / times.length).toFixed(2)}ms`,
  ].join("\n");
}

describe("Integration Benchmarks (app → Authz client → component)", () => {
  /**
   * Benchmark: Full lifecycle through app functions
   * assignRole (app mutation) → checkPermission (app query) → revokeRole → checkPermission
   */
  test("full lifecycle: assign → check → revoke → check", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));
    authzTest.register(t, "authz");

    // Create a user in the app
    const userId = await t.run(async (ctx) => {
      return await ctx.db.insert("users", {
        name: "Alice",
        email: "alice@test.com",
      });
    });

    // Benchmark: assign role through app mutation
    const assignTimes: number[] = [];
    const start1 = performance.now();
    await t.mutation(api.app.assignRole, {
      userId,
      role: "editor",
    });
    assignTimes.push(performance.now() - start1);

    // Benchmark: check permission through app query (N iterations)
    const checkTimes: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      const result = await t.query(api.app.checkPermission, {
        userId,
        permission: "documents:read",
      });
      checkTimes.push(performance.now() - start);
      expect(result).toBe(true);
    }

    // Benchmark: revoke role through app mutation
    const revokeTimes: number[] = [];
    const start2 = performance.now();
    await t.mutation(api.app.revokeRole, {
      userId,
      role: "editor",
    });
    revokeTimes.push(performance.now() - start2);

    // Benchmark: check permission after revoke (should be false)
    const checkAfterTimes: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      const result = await t.query(api.app.checkPermission, {
        userId,
        permission: "documents:read",
      });
      checkAfterTimes.push(performance.now() - start);
      expect(result).toBe(false);
    }

    console.log(formatStats("assignRole (app mutation)", assignTimes));
    console.log(formatStats("checkPermission ALLOWED (app query)", checkTimes));
    console.log(formatStats("revokeRole (app mutation)", revokeTimes));
    console.log(formatStats("checkPermission DENIED (app query)", checkAfterTimes));
  });

  /**
   * Benchmark: checkAllPermissions — checks 11 permissions for one user
   * This is the realistic "page load" scenario where the frontend needs
   * to know all permissions at once.
   */
  test("checkAllPermissions: 11 permission checks in one query", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));
    authzTest.register(t, "authz");

    const userId = await t.run(async (ctx) => {
      return await ctx.db.insert("users", {
        name: "Bob",
        email: "bob@test.com",
      });
    });

    // Assign admin role (grants all 11 permissions)
    await t.mutation(api.app.assignRole, { userId, role: "admin" });

    const times: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      const results = await t.query(api.app.checkAllPermissions, { userId });
      times.push(performance.now() - start);

      // All 11 should be true for admin
      expect(Object.values(results).every((v) => v === true)).toBe(true);
    }

    console.log(formatStats("checkAllPermissions (11 perms, admin)", times));
  });

  /**
   * Benchmark: Scoped permission checks — checks with org scope
   */
  test("scoped permission check: org-level role", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));
    authzTest.register(t, "authz");

    const userId = await t.run(async (ctx) => {
      return await ctx.db.insert("users", { name: "Carol", email: "carol@test.com" });
    });
    const orgId = await t.run(async (ctx) => {
      return await ctx.db.insert("orgs", { name: "Acme", slug: "acme", plan: "pro" });
    });

    // Assign editor role scoped to org
    await t.mutation(api.app.assignRole, { userId, role: "editor", orgId });

    const allowedTimes: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      const result = await t.query(api.app.checkPermission, {
        userId,
        permission: "documents:read",
        orgId,
      });
      allowedTimes.push(performance.now() - start);
      expect(result).toBe(true);
    }

    const deniedTimes: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      const result = await t.query(api.app.checkPermission, {
        userId,
        permission: "documents:read",
        // No orgId — global scope, should be denied
      });
      deniedTimes.push(performance.now() - start);
      expect(result).toBe(false);
    }

    console.log(formatStats("checkPermission ALLOWED (scoped to org)", allowedTimes));
    console.log(formatStats("checkPermission DENIED (wrong scope)", deniedTimes));
  });

  /**
   * Benchmark: Multi-user load — 50 users with roles, check permissions
   */
  test("multi-user: 50 users with roles, random permission checks", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));
    authzTest.register(t, "authz");

    // Create 50 users and assign roles
    const userIds: string[] = [];
    for (let i = 0; i < 50; i++) {
      const userId = await t.run(async (ctx) => {
        return await ctx.db.insert("users", {
          name: `User ${i}`,
          email: `user${i}@test.com`,
        });
      });
      userIds.push(userId as string);

      const role = i % 3 === 0 ? "admin" : i % 3 === 1 ? "editor" : "viewer";
      await t.mutation(api.app.assignRole, {
        userId: userId as any,
        role,
      });
    }

    // Benchmark: check permission for user in the middle
    const times: number[] = [];
    const midUser = userIds[25] as any;
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      await t.query(api.app.checkPermission, {
        userId: midUser,
        permission: "documents:read",
      });
      times.push(performance.now() - start);
    }

    console.log(formatStats("checkPermission (50 users in system)", times));
  });

  /**
   * Benchmark: Grant + deny override flow
   */
  test("grant and deny override flow", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));
    authzTest.register(t, "authz");

    const userId = await t.run(async (ctx) => {
      return await ctx.db.insert("users", { name: "Dave", email: "dave@test.com" });
    });

    // Assign viewer role
    await t.mutation(api.app.assignRole, { userId, role: "viewer" });

    // Grant extra permission
    const grantTimes: number[] = [];
    const start1 = performance.now();
    await t.mutation(api.app.grantPermission, {
      userId,
      permission: "documents:delete",
    });
    grantTimes.push(performance.now() - start1);

    // Check granted permission
    const checkGrantTimes: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      const result = await t.query(api.app.checkPermission, {
        userId,
        permission: "documents:delete",
      });
      checkGrantTimes.push(performance.now() - start);
      expect(result).toBe(true);
    }

    // Deny that permission
    const denyTimes: number[] = [];
    const start2 = performance.now();
    await t.mutation(api.app.denyPermission, {
      userId,
      permission: "documents:delete",
    });
    denyTimes.push(performance.now() - start2);

    // Check denied
    const checkDenyTimes: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      const result = await t.query(api.app.checkPermission, {
        userId,
        permission: "documents:delete",
      });
      checkDenyTimes.push(performance.now() - start);
      expect(result).toBe(false);
    }

    console.log(formatStats("grantPermission (app mutation)", grantTimes));
    console.log(formatStats("checkPermission after GRANT", checkGrantTimes));
    console.log(formatStats("denyPermission (app mutation)", denyTimes));
    console.log(formatStats("checkPermission after DENY", checkDenyTimes));
  });
});
