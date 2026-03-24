/**
 * Additional query tests to cover uncovered code paths
 */

import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "../schema.js";
import { api } from "../_generated/api.js";

const modules = import.meta.glob("../**/*.ts");

const TENANT = "test-tenant";

describe("queries - additional coverage", () => {
  describe("getUserRoles with scope", () => {
    it("should filter roles by scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
        rolePermissions: [],
      });

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: [],
      });

      const scopedRoles = await t.query(api.queries.getUserRoles, {
        tenantId: TENANT,
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

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        expiresAt: pastTime,
        rolePermissions: [],
      });

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: [],
      });

      const roles = await t.query(api.queries.getUserRoles, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(roles).toHaveLength(1);
      expect(roles[0].role).toBe("viewer");
    });
  });

  describe("getPermissionOverrides", () => {
    it("should get all overrides for a user", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      await t.mutation(api.unified.denyPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(overrides).toHaveLength(2);
    });

    it("should filter by permission", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      await t.mutation(api.unified.denyPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        tenantId: TENANT,
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

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        expiresAt: pastTime,
      });

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:write",
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(overrides).toHaveLength(1);
      expect(overrides[0].permission).toBe("documents:write");
    });
  });

  describe("checkPermission via unified - edge cases", () => {
    it("should handle expired overrides", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        expiresAt: pastTime,
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(result.allowed).toBe(false);
    });

    it("should handle expired role assignments", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        expiresAt: pastTime,
        rolePermissions: ["documents:read"],
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(result.allowed).toBe(false);
    });

    it("should handle scoped permission checks", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
        rolePermissions: ["documents:read"],
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
      });

      expect(result.allowed).toBe(true);
    });

    it("should deny when role has no matching permissions", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: ["documents:read"],
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(result.allowed).toBe(false);
    });
  });

  describe("checkPermission via unified - wildcard and pattern matching", () => {
    it("should allow when override is resource wildcard (documents:*)", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:*",
      });

      const readResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });
      expect(readResult.allowed).toBe(true);

      const deleteResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });
      expect(deleteResult.allowed).toBe(true);

      const otherResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "settings:read",
      });
      expect(otherResult.allowed).toBe(false);
    });

    it("should allow when override is action wildcard (*:read)", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "*:read",
      });

      const docRead = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });
      expect(docRead.allowed).toBe(true);

      const settingsRead = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "settings:read",
      });
      expect(settingsRead.allowed).toBe(true);

      const docWrite = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:write",
      });
      expect(docWrite.allowed).toBe(false);
    });

    it("should allow when override is full wildcard (*)", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "*",
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });
      expect(result.allowed).toBe(true);

      const anyResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "any:action",
      });
      expect(anyResult.allowed).toBe(true);
    });

    it("should allow when role has wildcard permission (documents:*)", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "poweruser",
        rolePermissions: ["documents:*"],
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });
      expect(result.allowed).toBe(true);
    });

    it("should deny when deny override uses wildcard (documents:*)", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read", "documents:delete"],
      });
      await t.mutation(api.unified.denyPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:*",
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toMatch(/denied|deny/i);
    });
  });

  describe("checkPermission (canAny equivalent via multiple calls)", () => {
    it("should find at least one allowed permission", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: ["documents:read"],
      });

      const deleteResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });
      const readResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });
      const updateResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:update",
      });

      // At least one should be allowed (documents:read via viewer role)
      const anyAllowed = [deleteResult, readResult, updateResult].some(
        (r) => r.allowed,
      );
      expect(anyAllowed).toBe(true);
      expect(readResult.allowed).toBe(true);
    });

    it("should return false for all when user has none of the permissions", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: ["documents:read"],
      });

      const deleteResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });
      const updateResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:update",
      });

      expect(deleteResult.allowed).toBe(false);
      expect(updateResult.allowed).toBe(false);
    });

    it("should respect deny override when checking multiple permissions", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read", "documents:delete"],
      });
      await t.mutation(api.unified.denyPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      const deleteResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });
      const readResult = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(deleteResult.allowed).toBe(false);
      expect(readResult.allowed).toBe(true);
    });
  });

  describe("getUserPermissionsFast (effective permissions)", () => {
    it("should combine role permissions and overrides with scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
        scope: { type: "team", id: "team_1" },
      });

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "special:access",
        scope: { type: "team", id: "team_1" },
      });

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
        scopeKey: "team:team_1",
      });

      const permNames = permissions.map((p) => p.permission);
      expect(permNames).toContain("documents:read");
      expect(permNames).toContain("special:access");
    });

    it("should filter by scopeKey", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "special:access",
        scope: { type: "team", id: "team_1" },
      });

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
        scopeKey: "team:team_2",
      });

      const permNames = permissions.map((p) => p.permission);
      // Override is for team_1 so should not appear in team_2 results
      expect(permNames).not.toContain("special:access");
    });

    it("should handle expired overrides in effective permissions", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "special:access",
        expiresAt: pastTime,
      });

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      const permNames = permissions.map((p) => p.permission);
      expect(permNames).not.toContain("special:access");
    });
  });

  describe("getUsersWithRole", () => {
    it("should get users with a specific role", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_1",
        role: "admin",
        rolePermissions: [],
      });

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_2",
        role: "admin",
        rolePermissions: [],
      });

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_3",
        role: "viewer",
        rolePermissions: [],
      });

      const users = await t.query(api.queries.getUsersWithRole, {
        tenantId: TENANT,
        role: "admin",
      });

      expect(users).toHaveLength(2);
      expect(users.map((u) => u.userId)).toContain("user_1");
      expect(users.map((u) => u.userId)).toContain("user_2");
    });

    it("should filter by scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_1",
        role: "admin",
        scope: { type: "team", id: "team_1" },
        rolePermissions: [],
      });

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_2",
        role: "admin",
        rolePermissions: [],
        scope: { type: "team", id: "team_2" },
      });

      const users = await t.query(api.queries.getUsersWithRole, {
        tenantId: TENANT,
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      expect(users).toHaveLength(1);
      expect(users[0].userId).toBe("user_1");
    });

    it("should filter out expired assignments", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_1",
        role: "admin",
        expiresAt: pastTime,
        rolePermissions: [],
      });

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_2",
        role: "admin",
        rolePermissions: [],
      });

      const users = await t.query(api.queries.getUsersWithRole, {
        tenantId: TENANT,
        role: "admin",
      });

      expect(users).toHaveLength(1);
      expect(users[0].userId).toBe("user_2");
    });
  });

  describe("getAuditLog", () => {
    it("should filter by action", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
        enableAudit: true,
      });

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        tenantId: TENANT,
        action: "role_assigned",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.every((l) => l.action === "role_assigned")).toBe(true);
    });

    it("should get all logs without filter", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
        enableAudit: true,
      });

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, { tenantId: TENANT });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.length).toBeGreaterThanOrEqual(2);
    });

    it("should respect limit", async () => {
      const t = convexTest(schema, modules);

      // Create multiple audit entries
      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        enableAudit: true,
        rolePermissions: [],
      });

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: [],
        enableAudit: true,
      });

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        tenantId: TENANT,
        limit: 1,
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs).toHaveLength(1);
    });

    it("should return paginated result when paginationOpts provided", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        enableAudit: true,
        rolePermissions: [],
      });
      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: [],
        enableAudit: true,
      });
      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        enableAudit: true,
      });

      const result = await t.query(api.queries.getAuditLog, {
        tenantId: TENANT,
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
            tenantId: TENANT,
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

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_paginated",
        role: "admin",
        rolePermissions: [],
        enableAudit: true,
      });

      const result = await t.query(api.queries.getAuditLog, {
        tenantId: TENANT,
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

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
        expiresAt: pastTime,
      });

      const hasRole = await t.query(api.queries.hasRole, {
        tenantId: TENANT,
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
      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
        scope: { type: "team", id: "team_1" },
      });

      // Query with different scope - scoped role should not match
      const roles = await t.query(api.queries.getUserRoles, {
        tenantId: TENANT,
        userId: "user_123",
        scope: { type: "team", id: "team_2" },
      });

      expect(roles).toHaveLength(0);
    });
  });

  describe("checkPermission via unified - reason branches", () => {
    it("should deny when deny override exists with a custom reason", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.denyPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
        reason: "Custom deny reason",
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(result.allowed).toBe(false);
    });

    it("should deny when deny override exists without a custom reason", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.denyPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(result.allowed).toBe(false);
    });

    it("should allow when allow override exists with a custom reason", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        reason: "Custom allow reason",
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(result.allowed).toBe(true);
    });

    it("should allow when allow override exists without a custom reason", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(result.allowed).toBe(true);
    });
  });

  describe("getUserPermissionsFast - expired role branch", () => {
    it("should exclude expired role assignments from effective permissions", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        expiresAt: pastTime,
        rolePermissions: ["documents:read", "documents:delete"],
      });

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: ["documents:read"],
      });

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      const permNames = permissions.map((p) => p.permission);
      // Only viewer's permissions should be present (admin is expired)
      expect(permNames).toContain("documents:read");
      expect(permNames).not.toContain("documents:delete");
    });
  });
});
