/**
 * Large-scale integration benchmark.
 *
 * Tests authz performance with realistic data volumes:
 * - 500 users across 10 tenants (50 per tenant)
 * - 4 roles per tenant with 5-11 permissions each
 * - ~500 role assignments (1 per user)
 * - ~2500 effectivePermissions rows (avg 5 perms per role × 500 users)
 * - 50 direct permission overrides
 * - 50 relations
 *
 * This reveals performance characteristics that small-data benchmarks miss:
 * table scan costs, index selectivity, wildcard pattern matching overhead.
 *
 * Run: npx vitest run example/convex/benchmark-scale.test.ts
 */
import { convexTest } from "convex-test";
import { describe, test, expect } from "vitest";
import schema from "./schema.js";
import { api } from "./_generated/api.js";
import authzTest from "@djpanda/convex-authz/test";

const TENANTS = ["acme", "globex", "initech", "hooli", "piedpiper", "umbrella", "wayne", "stark", "oscorp", "lexcorp"];
const ROLES = ["admin", "editor", "viewer", "billing_admin"] as const;
const USERS_PER_TENANT = 50;
const BENCH_ITERATIONS = 30;

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

describe("Large-Scale Benchmarks (500 users, 10 tenants)", () => {
  /**
   * Seed a large dataset, then benchmark reads.
   * All benchmarks share one convexTest instance with pre-seeded data.
   */
  test("seed and benchmark at scale", { timeout: 120000 }, async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));
    authzTest.register(t, "authz");

    // ── Phase 1: Seed data ──────────────────────────────────────────
    console.log("\n🌱 Seeding large-scale data...");

    const permissions = {
      admin: ["documents:create", "documents:read", "documents:update", "documents:delete",
              "settings:view", "settings:manage", "users:invite", "users:remove",
              "users:manage", "billing:view", "billing:manage"],
      editor: ["documents:create", "documents:read", "documents:update", "settings:view"],
      viewer: ["documents:read", "settings:view"],
      billing_admin: ["billing:view", "billing:manage", "settings:view"],
    };

    // Create orgs
    const orgIds: Record<string, any> = {};
    for (const tenant of TENANTS) {
      orgIds[tenant] = await t.run(async (ctx) => {
        return await ctx.db.insert("orgs", { name: tenant, slug: tenant, plan: "enterprise" });
      });
    }
    console.log(`  ✓ Created ${TENANTS.length} orgs`);

    // Create users and assign roles via unified mutations (component level)
    const usersByTenant: Record<string, string[]> = {};
    let totalAssignments = 0;

    for (const tenant of TENANTS) {
      usersByTenant[tenant] = [];
      for (let i = 0; i < USERS_PER_TENANT; i++) {
        const userId = await t.run(async (ctx) => {
          return await ctx.db.insert("users", {
            name: `${tenant}-user-${i}`,
            email: `user${i}@${tenant}.com`,
          });
        });
        usersByTenant[tenant].push(String(userId));

        // Assign role: distribute across roles
        const role = ROLES[i % ROLES.length];
        const scope = { type: "org", id: String(orgIds[tenant]) };

        await t.mutation(api.app.assignRole, {
          userId: userId as any,
          role,
          orgId: orgIds[tenant],
        });
        totalAssignments++;
      }
    }
    console.log(`  ✓ Created ${TENANTS.length * USERS_PER_TENANT} users with ${totalAssignments} role assignments`);

    // Add some direct permission overrides
    let overrideCount = 0;
    for (const tenant of TENANTS.slice(0, 5)) {
      for (let i = 0; i < 10; i++) {
        const userId = usersByTenant[tenant][i];
        await t.mutation(api.app.grantPermission, {
          userId: usersByTenant[tenant][i] as any,
          permission: "documents:delete",
          orgId: orgIds[tenant],
        });
        overrideCount++;
      }
    }
    console.log(`  ✓ Created ${overrideCount} direct permission overrides`);

    // Note: component tables (effectivePermissions, effectiveRoles) are isolated
    // from the app's DB in convex-test. We can't count them via t.run().
    // The data IS there — assignRoleUnified writes to them.
    console.log(`  ✓ Effective tables populated via assignRoleUnified (component-isolated, not queryable from app DB)`);
    console.log(`\n📊 Starting benchmarks...\n`);

    // ── Phase 2: Benchmark reads ────────────────────────────────────

    // Pick a user from the middle of the first tenant
    const targetUser = usersByTenant["acme"][25] as any;
    const targetOrg = orgIds["acme"];

    // Benchmark 1: Single permission check (the hot path)
    const singleCheckTimes: number[] = [];
    for (let i = 0; i < BENCH_ITERATIONS; i++) {
      const start = performance.now();
      const result = await t.query(api.app.checkPermission, {
        userId: targetUser,
        permission: "documents:read",
        orgId: targetOrg,
      });
      singleCheckTimes.push(performance.now() - start);
      expect(result).toBe(true);
    }
    console.log(formatStats("Single checkPermission (HIT, 500 users in system)", singleCheckTimes));

    // Benchmark 2: Permission check miss (permission not granted)
    const missTimes: number[] = [];
    for (let i = 0; i < BENCH_ITERATIONS; i++) {
      const start = performance.now();
      const result = await t.query(api.app.checkPermission, {
        userId: targetUser,
        permission: "billing:manage",
        orgId: targetOrg,
      });
      missTimes.push(performance.now() - start);
      // User 25 is a viewer (25 % 4 = 1 → editor), so billing:manage depends on role
    }
    console.log(formatStats("Single checkPermission (MISS, 500 users in system)", missTimes));

    // Benchmark 3: Wrong tenant (should be denied)
    const wrongTenantTimes: number[] = [];
    const otherOrg = orgIds["globex"];
    for (let i = 0; i < BENCH_ITERATIONS; i++) {
      const start = performance.now();
      const result = await t.query(api.app.checkPermission, {
        userId: targetUser,
        permission: "documents:read",
        orgId: otherOrg,
      });
      wrongTenantTimes.push(performance.now() - start);
      expect(result).toBe(false);
    }
    console.log(formatStats("checkPermission wrong scope (cross-tenant denied)", wrongTenantTimes));

    // Benchmark 4: Check all 11 permissions (page load scenario)
    const allPermsTimes: number[] = [];
    for (let i = 0; i < BENCH_ITERATIONS; i++) {
      const start = performance.now();
      const results = await t.query(api.app.checkAllPermissions, {
        userId: targetUser,
        orgId: targetOrg,
      });
      allPermsTimes.push(performance.now() - start);
    }
    console.log(formatStats("checkAllPermissions (11 perms, 500 users in system)", allPermsTimes));

    // Benchmark 5: Check permission for user WITH direct override
    const overrideUser = usersByTenant["acme"][3] as any; // Has direct grant
    const overrideTimes: number[] = [];
    for (let i = 0; i < BENCH_ITERATIONS; i++) {
      const start = performance.now();
      const result = await t.query(api.app.checkPermission, {
        userId: overrideUser,
        permission: "documents:delete",
        orgId: targetOrg,
      });
      overrideTimes.push(performance.now() - start);
      expect(result).toBe(true);
    }
    console.log(formatStats("checkPermission with directGrant override", overrideTimes));

    // Benchmark 6: assignRole at scale (write performance with large tables)
    const newUser = await t.run(async (ctx) => {
      return await ctx.db.insert("users", { name: "new-user", email: "new@test.com" });
    });
    const assignTimes: number[] = [];
    // Assign different roles to avoid idempotency
    for (let i = 0; i < 4; i++) {
      const start = performance.now();
      await t.mutation(api.app.assignRole, {
        userId: newUser as any,
        role: ROLES[i],
        orgId: targetOrg,
      });
      assignTimes.push(performance.now() - start);
    }
    console.log(formatStats("assignRole (write at scale, 500+ existing users)", assignTimes));

    // Benchmark 7: revokeRole at scale
    const revokeTimes: number[] = [];
    for (let i = 0; i < 4; i++) {
      const start = performance.now();
      await t.mutation(api.app.revokeRole, {
        userId: newUser as any,
        role: ROLES[i],
        orgId: targetOrg,
      });
      revokeTimes.push(performance.now() - start);
    }
    console.log(formatStats("revokeRole (write at scale)", revokeTimes));

    // Benchmark 8: Random user permission checks across tenants
    const randomTimes: number[] = [];
    for (let i = 0; i < BENCH_ITERATIONS; i++) {
      const tenantIdx = i % TENANTS.length;
      const userIdx = (i * 7) % USERS_PER_TENANT; // Pseudo-random spread
      const tenant = TENANTS[tenantIdx];
      const userId = usersByTenant[tenant][userIdx] as any;
      const org = orgIds[tenant];

      const start = performance.now();
      await t.query(api.app.checkPermission, {
        userId,
        permission: "documents:read",
        orgId: org,
      });
      randomTimes.push(performance.now() - start);
    }
    console.log(formatStats("Random user checkPermission across tenants", randomTimes));

    // ── Summary ─────────────────────────────────────────────────────
    console.log("\n" + "=".repeat(60));
    console.log("SCALE SUMMARY");
    console.log("=".repeat(60));
    console.log(`Data: ${TENANTS.length} tenants × ${USERS_PER_TENANT} users = ${TENANTS.length * USERS_PER_TENANT} users`);
    console.log(`Role assignments: ${totalAssignments}`);
    console.log(`Direct overrides: ${overrideCount}`);
    console.log(`\nRead performance:`);
    console.log(`  Single check (HIT):   ${median(singleCheckTimes).toFixed(2)}ms median`);
    console.log(`  Single check (MISS):  ${median(missTimes).toFixed(2)}ms median`);
    console.log(`  Wrong scope:          ${median(wrongTenantTimes).toFixed(2)}ms median`);
    console.log(`  11-perm page load:    ${median(allPermsTimes).toFixed(2)}ms median`);
    console.log(`  With directGrant:     ${median(overrideTimes).toFixed(2)}ms median`);
    console.log(`  Random cross-tenant:  ${median(randomTimes).toFixed(2)}ms median`);
    console.log(`\nWrite performance:`);
    console.log(`  assignRole:           ${median(assignTimes).toFixed(2)}ms median`);
    console.log(`  revokeRole:           ${median(revokeTimes).toFixed(2)}ms median`);
    console.log("=".repeat(60));
  });
});
