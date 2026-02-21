/**
 * Additional query tests to cover uncovered code paths
 */

import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "./schema.js";
import { api } from "./_generated/api.js";

const modules = import.meta.glob("./**/*.ts");

describe("queries - additional coverage", () => {
  describe("getUserRoles with scope", () => {
    it("should filter roles by scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "viewer",
      });

      const scopedRoles = await t.query(api.queries.getUserRoles, {
        userId: "user_123",
        scope: { type: "team", id: "team_1" },
      });

      // Should only return the scoped admin role (global viewer matches any scope via matchesScope)
      expect(scopedRoles.length).toBeGreaterThanOrEqual(1);
      expect(scopedRoles.some((r) => r.role === "admin")).toBe(true);
    });

    it("should filter out expired roles", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        expiresAt: pastTime,
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "viewer",
      });

      const roles = await t.query(api.queries.getUserRoles, {
        userId: "user_123",
      });

      expect(roles).toHaveLength(1);
      expect(roles[0].role).toBe("viewer");
    });
  });

  describe("getPermissionOverrides", () => {
    it("should get all overrides for a user", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
      });

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
      });

      expect(overrides).toHaveLength(2);
    });

    it("should filter by permission", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
      });

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(overrides).toHaveLength(1);
      expect(overrides[0].permission).toBe("documents:read");
      expect(overrides[0].effect).toBe("allow");
    });

    it("should filter out expired overrides", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        expiresAt: pastTime,
      });

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:write",
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
      });

      expect(overrides).toHaveLength(1);
      expect(overrides[0].permission).toBe("documents:write");
    });
  });

  describe("checkPermission - edge cases", () => {
    it("should handle expired overrides", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        expiresAt: pastTime,
      });

      const result = await t.query(api.queries.checkPermission, {
        userId: "user_123",
        permission: "documents:read",
        rolePermissions: {},
      });

      expect(result.allowed).toBe(false);
    });

    it("should handle expired role assignments", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        expiresAt: pastTime,
      });

      const result = await t.query(api.queries.checkPermission, {
        userId: "user_123",
        permission: "documents:read",
        rolePermissions: {
          admin: ["documents:read"],
        },
      });

      expect(result.allowed).toBe(false);
    });

    it("should handle scoped permission checks", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      const result = await t.query(api.queries.checkPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
        rolePermissions: {
          admin: ["documents:read"],
        },
      });

      expect(result.allowed).toBe(true);
    });

    it("should deny when role has no matching permissions", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "viewer",
      });

      const result = await t.query(api.queries.checkPermission, {
        userId: "user_123",
        permission: "documents:delete",
        rolePermissions: {
          viewer: ["documents:read"],
        },
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("No role or override grants this permission");
    });
  });

  describe("checkPermissions (canAny)", () => {
    it("should return allowed true when user has at least one permission", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "viewer",
      });

      const result = await t.query(api.queries.checkPermissions, {
        userId: "user_123",
        permissions: ["documents:delete", "documents:read", "documents:update"],
        rolePermissions: {
          viewer: ["documents:read"],
        },
      });

      expect(result.allowed).toBe(true);
      expect(result.matchedPermission).toBe("documents:read");
    });

    it("should return allowed false when user has none of the permissions", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "viewer",
      });

      const result = await t.query(api.queries.checkPermissions, {
        userId: "user_123",
        permissions: ["documents:delete", "documents:update"],
        rolePermissions: {
          viewer: ["documents:read"],
        },
      });

      expect(result.allowed).toBe(false);
      expect(result.matchedPermission).toBeUndefined();
    });

    it("should respect deny override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
      });
      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
      });

      const result = await t.query(api.queries.checkPermissions, {
        userId: "user_123",
        permissions: ["documents:delete", "documents:read"],
        rolePermissions: {
          admin: ["documents:read", "documents:delete"],
        },
      });

      expect(result.allowed).toBe(true);
      expect(result.matchedPermission).toBe("documents:read");
    });

    it("should return allowed false for empty permissions array", async () => {
      const t = convexTest(schema, modules);

      const result = await t.query(api.queries.checkPermissions, {
        userId: "user_123",
        permissions: [],
        rolePermissions: {},
      });

      expect(result.allowed).toBe(false);
    });

    it("should throw when permissions exceed limit", async () => {
      const t = convexTest(schema, modules);

      const permissions = Array.from(
        { length: 101 },
        (_, i) => `documents:action${i}`
      );

      await expect(
        t.query(api.queries.checkPermissions, {
          userId: "user_123",
          permissions,
          rolePermissions: {},
        })
      ).rejects.toThrow(/must not exceed 100/);
    });
  });

  describe("getEffectivePermissions", () => {
    it("should combine role permissions and overrides with scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "editor",
        scope: { type: "team", id: "team_1" },
      });

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "special:access",
        scope: { type: "team", id: "team_1" },
      });

      const result = await t.query(api.queries.getEffectivePermissions, {
        userId: "user_123",
        rolePermissions: {
          editor: ["documents:read", "documents:write"],
        },
        scope: { type: "team", id: "team_1" },
      });

      expect(result.permissions).toContain("documents:read");
      expect(result.permissions).toContain("special:access");
      expect(result.roles).toContain("editor");
    });

    it("should filter overrides by scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "special:access",
        scope: { type: "team", id: "team_1" },
      });

      const result = await t.query(api.queries.getEffectivePermissions, {
        userId: "user_123",
        rolePermissions: {},
        scope: { type: "team", id: "team_2" },
      });

      // Override is for team_1 so should not match team_2
      expect(result.permissions).not.toContain("special:access");
    });

    it("should handle expired overrides in getEffectivePermissions", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "special:access",
        expiresAt: pastTime,
      });

      const result = await t.query(api.queries.getEffectivePermissions, {
        userId: "user_123",
        rolePermissions: {},
      });

      expect(result.permissions).not.toContain("special:access");
    });
  });

  describe("getUsersWithRole", () => {
    it("should get users with a specific role", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_1",
        role: "admin",
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_2",
        role: "admin",
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_3",
        role: "viewer",
      });

      const users = await t.query(api.queries.getUsersWithRole, {
        role: "admin",
      });

      expect(users).toHaveLength(2);
      expect(users.map((u) => u.userId)).toContain("user_1");
      expect(users.map((u) => u.userId)).toContain("user_2");
    });

    it("should filter by scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_1",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_2",
        role: "admin",
        scope: { type: "team", id: "team_2" },
      });

      const users = await t.query(api.queries.getUsersWithRole, {
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      expect(users).toHaveLength(1);
      expect(users[0].userId).toBe("user_1");
    });

    it("should filter out expired assignments", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.assignRole, {
        userId: "user_1",
        role: "admin",
        expiresAt: pastTime,
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_2",
        role: "admin",
      });

      const users = await t.query(api.queries.getUsersWithRole, {
        role: "admin",
      });

      expect(users).toHaveLength(1);
      expect(users[0].userId).toBe("user_2");
    });
  });

  describe("getAuditLog", () => {
    it("should filter by action", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        enableAudit: true,
      });

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        action: "role_assigned",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.every((l) => l.action === "role_assigned")).toBe(true);
    });

    it("should get all logs without filter", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        enableAudit: true,
      });

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {});
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.length).toBeGreaterThanOrEqual(2);
    });

    it("should respect limit", async () => {
      const t = convexTest(schema, modules);

      // Create multiple audit entries
      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        enableAudit: true,
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "editor",
        enableAudit: true,
      });

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        limit: 1,
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs).toHaveLength(1);
    });

    it("should return paginated result when paginationOpts provided", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        enableAudit: true,
      });
      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "editor",
        enableAudit: true,
      });
      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        enableAudit: true,
      });

      const result = await t.query(api.queries.getAuditLog, {
        paginationOpts: { numItems: 2, cursor: null },
      });

      expect(result).toHaveProperty("page");
      expect(result).toHaveProperty("isDone");
      expect(result).toHaveProperty("continueCursor");
      if ("page" in result) {
        expect(Array.isArray(result.page)).toBe(true);
        expect(result.page.length).toBeLessThanOrEqual(2);
        if (result.page.length === 2 && !result.isDone) {
          const next = await t.query(api.queries.getAuditLog, {
            paginationOpts: {
              numItems: 2,
              cursor: result.continueCursor,
            },
          });
          expect(next).toHaveProperty("page");
          if ("page" in next) expect(next.page.length).toBeLessThanOrEqual(2);
        }
      }
    });

    it("should support pagination with userId filter", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_paginated",
        role: "admin",
        enableAudit: true,
      });

      const result = await t.query(api.queries.getAuditLog, {
        userId: "user_paginated",
        paginationOpts: { numItems: 10, cursor: null },
      });

      expect(result).toHaveProperty("page");
      const page = Array.isArray(result) ? result : result.page;
      expect(page.every((e) => e.userId === "user_paginated")).toBe(true);
    });
  });

  describe("hasRole - branch coverage", () => {
    it("should return false for expired role assignment", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        expiresAt: pastTime,
      });

      const hasRole = await t.query(api.queries.hasRole, {
        userId: "user_123",
        role: "admin",
      });

      expect(hasRole).toBe(false);
    });
  });

  describe("getUserRoles - branch coverage", () => {
    it("should exclude roles that dont match scope via matchesScope", async () => {
      const t = convexTest(schema, modules);

      // Scoped role for team_1
      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      // Query with different scope - scoped role should not match
      const roles = await t.query(api.queries.getUserRoles, {
        userId: "user_123",
        scope: { type: "team", id: "team_2" },
      });

      expect(roles).toHaveLength(0);
    });
  });

  describe("checkPermission - reason branches", () => {
    it("should use override reason when deny has a reason", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        reason: "Custom deny reason",
      });

      const result = await t.query(api.queries.checkPermission, {
        userId: "user_123",
        permission: "documents:delete",
        rolePermissions: {},
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("Custom deny reason");
    });

    it("should use default reason when deny has no reason", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
      });

      const result = await t.query(api.queries.checkPermission, {
        userId: "user_123",
        permission: "documents:delete",
        rolePermissions: {},
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("Explicitly denied by override");
    });

    it("should use override reason when allow has a reason", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        reason: "Custom allow reason",
      });

      const result = await t.query(api.queries.checkPermission, {
        userId: "user_123",
        permission: "documents:read",
        rolePermissions: {},
      });

      expect(result.allowed).toBe(true);
      expect(result.reason).toBe("Custom allow reason");
    });

    it("should use default reason when allow has no reason", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
      });

      const result = await t.query(api.queries.checkPermission, {
        userId: "user_123",
        permission: "documents:read",
        rolePermissions: {},
      });

      expect(result.allowed).toBe(true);
      expect(result.reason).toBe("Explicitly allowed by override");
    });
  });

  describe("getEffectivePermissions - expired role branch", () => {
    it("should exclude expired role assignments from effective permissions", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        expiresAt: pastTime,
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "viewer",
      });

      const result = await t.query(api.queries.getEffectivePermissions, {
        userId: "user_123",
        rolePermissions: {
          admin: ["documents:read", "documents:delete"],
          viewer: ["documents:read"],
        },
      });

      expect(result.roles).not.toContain("admin");
      expect(result.roles).toContain("viewer");
      // Only viewer's permissions
      expect(result.permissions).toContain("documents:read");
      expect(result.permissions).not.toContain("documents:delete");
    });
  });
});
