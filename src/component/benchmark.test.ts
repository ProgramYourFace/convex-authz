/**
 * Performance benchmark: measures relative performance of key operations.
 *
 * Run on both branches to compare:
 *   git stash && git checkout main && npx vitest run src/component/benchmark.test.ts
 *   git checkout dev && git stash pop && npx vitest run src/component/benchmark.test.ts
 *
 * Or use vitest bench mode:
 *   npx vitest bench src/component/benchmark.test.ts
 */
import { convexTest } from "convex-test";
import schema from "./schema.js";
import { api } from "./_generated/api.js";
import { describe, test, expect } from "vitest";

const TENANT = "bench-tenant";
const ITERATIONS = 50;

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

function formatStats(times: number[]): string {
  return [
    `  median: ${median(times).toFixed(2)}ms`,
    `  p95:    ${percentile(times, 95).toFixed(2)}ms`,
    `  p99:    ${percentile(times, 99).toFixed(2)}ms`,
    `  min:    ${Math.min(...times).toFixed(2)}ms`,
    `  max:    ${Math.max(...times).toFixed(2)}ms`,
    `  avg:    ${(times.reduce((a, b) => a + b, 0) / times.length).toFixed(2)}ms`,
  ].join("\n");
}

describe("Performance Benchmarks", () => {
  /**
   * Benchmark: Permission check (the hot path)
   *
   * Main branch (Authz): queries.checkPermission — scans roleAssignments + permissionOverrides
   * Dev branch (v2):     unified.checkPermission — O(1) effectivePermissions lookup
   */
  test("checkPermission latency", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));

    // Setup: assign roles with many permissions to make the scan path slower
    const roles = ["admin", "editor", "viewer", "moderator", "analyst"];
    const permissionsPerRole = 10;

    for (const role of roles) {
      const perms = Array.from(
        { length: permissionsPerRole },
        (_, i) => `resource${i}:action${i}`,
      );

      // Use the unified path (dev) or fall back to indexed path
      try {
        await t.mutation(api.unified.assignRoleUnified, {
          tenantId: TENANT,
          userId: "bench-user",
          role,
          rolePermissions: perms,
        });
      } catch {
        // Main branch: use mutations.assignRole (source only)
        await t.mutation(api.mutations.assignRole, {
          tenantId: TENANT,
          userId: "bench-user",
          role,
        });
      }
    }

    // Also add some permission overrides to make scan path heavier
    for (let i = 0; i < 5; i++) {
      try {
        await t.mutation(api.unified.grantPermissionUnified, {
          tenantId: TENANT,
          userId: "bench-user",
          permission: `override${i}:read`,
        });
      } catch {
        await t.mutation(api.mutations.grantPermission, {
          tenantId: TENANT,
          userId: "bench-user",
          permission: `override${i}:read`,
        });
      }
    }

    // Benchmark: check a permission that exists
    const times: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      try {
        // Dev branch: unified path
        await t.query(api.unified.checkPermission, {
          tenantId: TENANT,
          userId: "bench-user",
          permission: "resource0:action0",
        });
      } catch {
        // Main branch: queries path (with rolePermissions map)
        await t.query(api.queries.checkPermission, {
          tenantId: TENANT,
          userId: "bench-user",
          permission: "resource0:action0",
          rolePermissions: Object.fromEntries(
            roles.map((r) => [
              r,
              Array.from(
                { length: permissionsPerRole },
                (_, i) => `resource${i}:action${i}`,
              ),
            ]),
          ),
        });
      }
      times.push(performance.now() - start);
    }

    console.log(`\n=== checkPermission (${ITERATIONS} iterations) ===`);
    console.log(formatStats(times));

    // Benchmark: check a permission that does NOT exist (worst case for scan)
    const timesMiss: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      try {
        await t.query(api.unified.checkPermission, {
          tenantId: TENANT,
          userId: "bench-user",
          permission: "nonexistent:permission",
        });
      } catch {
        await t.query(api.queries.checkPermission, {
          tenantId: TENANT,
          userId: "bench-user",
          permission: "nonexistent:permission",
          rolePermissions: Object.fromEntries(
            roles.map((r) => [
              r,
              Array.from(
                { length: permissionsPerRole },
                (_, i) => `resource${i}:action${i}`,
              ),
            ]),
          ),
        });
      }
      timesMiss.push(performance.now() - start);
    }

    console.log(`\n=== checkPermission MISS (${ITERATIONS} iterations) ===`);
    console.log(formatStats(timesMiss));

    expect(times.length).toBe(ITERATIONS);
  });

  /**
   * Benchmark: Role assignment (write path)
   *
   * Main branch (Authz): mutations.assignRole — 1 write to roleAssignments
   * Dev branch (v2):     unified.assignRoleUnified — writes to roleAssignments + effectiveRoles + effectivePermissions
   */
  test("assignRole latency", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));

    const times: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      try {
        await t.mutation(api.unified.assignRoleUnified, {
          tenantId: TENANT,
          userId: `user-${i}`,
          role: "editor",
          rolePermissions: [
            "docs:read",
            "docs:write",
            "docs:delete",
            "settings:read",
            "settings:write",
          ],
        });
      } catch {
        await t.mutation(api.mutations.assignRole, {
          tenantId: TENANT,
          userId: `user-${i}`,
          role: "editor",
        });
      }
      times.push(performance.now() - start);
    }

    console.log(`\n=== assignRole (${ITERATIONS} iterations) ===`);
    console.log(formatStats(times));

    expect(times.length).toBe(ITERATIONS);
  });

  /**
   * Benchmark: hasRole check
   */
  test("hasRole latency", async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));

    // Setup
    try {
      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "bench-user",
        role: "admin",
        rolePermissions: ["all:manage"],
      });
    } catch {
      await t.mutation(api.mutations.assignRole, {
        tenantId: TENANT,
        userId: "bench-user",
        role: "admin",
      });
    }

    const times: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      try {
        await t.query(api.indexed.hasRoleFast, {
          tenantId: TENANT,
          userId: "bench-user",
          role: "admin",
        });
      } catch {
        await t.query(api.queries.hasRole, {
          tenantId: TENANT,
          userId: "bench-user",
          role: "admin",
        });
      }
      times.push(performance.now() - start);
    }

    console.log(`\n=== hasRole (${ITERATIONS} iterations) ===`);
    console.log(formatStats(times));

    expect(times.length).toBe(ITERATIONS);
  });

  /**
   * Benchmark: Permission check under load (many users, many roles)
   * Tests how performance scales with data volume
   */
  test("checkPermission with 100 users x 3 roles", { timeout: 60000 }, async () => {
    const t = convexTest(schema, import.meta.glob("./**/*.ts"));

    // Setup: 100 users with 3 roles each
    const perms = ["docs:read", "docs:write", "docs:delete", "settings:view"];
    for (let u = 0; u < 100; u++) {
      for (const role of ["viewer", "editor", "admin"]) {
        try {
          await t.mutation(api.unified.assignRoleUnified, {
            tenantId: TENANT,
            userId: `user-${u}`,
            role,
            rolePermissions: perms,
          });
        } catch {
          await t.mutation(api.mutations.assignRole, {
            tenantId: TENANT,
            userId: `user-${u}`,
            role,
          });
        }
      }
    }

    // Benchmark: check permission for user in the middle
    const times: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      try {
        await t.query(api.unified.checkPermission, {
          tenantId: TENANT,
          userId: "user-50",
          permission: "docs:read",
        });
      } catch {
        await t.query(api.queries.checkPermission, {
          tenantId: TENANT,
          userId: "user-50",
          permission: "docs:read",
          rolePermissions: {
            viewer: perms,
            editor: perms,
            admin: perms,
          },
        });
      }
      times.push(performance.now() - start);
    }

    console.log(
      `\n=== checkPermission (100 users x 3 roles, ${ITERATIONS} iterations) ===`,
    );
    console.log(formatStats(times));

    expect(times.length).toBe(ITERATIONS);
  });
});
