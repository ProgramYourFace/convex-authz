import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "../schema.js";
import { api } from "../_generated/api.js";

const modules = import.meta.glob("../**/*.ts");
const TENANT = "test-tenant";

describe("authz component", () => {
  describe("role assignments", () => {
    it("should assign a role to a user", async () => {
      const t = convexTest(schema, modules);

      const assignmentId = await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
      });

      expect(assignmentId).toBeDefined();
      expect(typeof assignmentId).toBe("string");
    });

    it("should get user roles", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
      });

      const roles = await t.query(api.queries.getUserRoles, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(roles).toHaveLength(1);
      expect(roles[0].role).toBe("admin");
    });

    it("should check if user has role", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: [],
      });

      const hasRole = await t.query(api.queries.hasRole, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
      });

      expect(hasRole).toBe(true);

      const hasAdmin = await t.query(api.queries.hasRole, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
      });

      expect(hasAdmin).toBe(false);
    });

    it("should revoke a role", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: [],
      });

      const revoked = await t.mutation(api.unified.revokeRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: [],
      });

      expect(revoked).toBe(true);

      const hasRole = await t.query(api.queries.hasRole, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
      });

      expect(hasRole).toBe(false);
    });

    it("should support scoped roles", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: [],
        scope: { type: "team", id: "team_456" },
      });

      const hasRoleGlobal = await t.query(api.queries.hasRole, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
      });

      // Global role check should not find scoped role
      expect(hasRoleGlobal).toBe(false);

      const hasRoleScoped = await t.query(api.queries.hasRole, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        scope: { type: "team", id: "team_456" },
      });

      expect(hasRoleScoped).toBe(true);
    });

    it("should upsert duplicate role assignments (idempotent)", async () => {
      const t = convexTest(schema, modules);

      const id1 = await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
      });

      // Assigning the same role again should succeed (upsert)
      const id2 = await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
      });

      expect(id1).toBeDefined();
      expect(id2).toBeDefined();
    });
  });

  describe("permission checks", () => {
    it("should check permission based on role", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read", "documents:write", "documents:delete"],
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(result.allowed).toBe(true);
    });

    it("should deny permission when user has no matching role", async () => {
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

    it("should support wildcard permissions", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "superadmin",
        rolePermissions: ["*:*"],
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(result.allowed).toBe(true);
    });
  });

  describe("permission overrides", () => {
    it("should grant explicit permission", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.grantPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
        reason: "Temporary access",
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(result.allowed).toBe(true);
    });

    it("should deny permission explicitly", async () => {
      const t = convexTest(schema, modules);

      // First give admin role
      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read", "documents:write", "documents:delete"],
      });

      // Then deny specific permission
      await t.mutation(api.unified.denyPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
        reason: "Access revoked",
      });

      const result = await t.query(api.unified.checkPermission, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      // Deny override should take precedence
      expect(result.allowed).toBe(false);
    });
  });

  describe("user attributes", () => {
    it("should set and get user attributes", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.setAttributeWithRecompute, {
        tenantId: TENANT,
        userId: "user_123",
        key: "department",
        value: "engineering",
      });

      const value = await t.query(api.queries.getUserAttribute, {
        tenantId: TENANT,
        userId: "user_123",
        key: "department",
      });

      expect(value).toBe("engineering");
    });

    it("should get all user attributes", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.setAttributeWithRecompute, {
        tenantId: TENANT,
        userId: "user_123",
        key: "department",
        value: "engineering",
      });

      await t.mutation(api.unified.setAttributeWithRecompute, {
        tenantId: TENANT,
        userId: "user_123",
        key: "level",
        value: 5,
      });

      const attributes = await t.query(api.queries.getUserAttributes, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(attributes).toHaveLength(2);
    });

    it("should remove user attribute", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.setAttributeWithRecompute, {
        tenantId: TENANT,
        userId: "user_123",
        key: "department",
        value: "engineering",
      });

      const removed = await t.mutation(api.mutations.removeAttribute, {
        tenantId: TENANT,
        userId: "user_123",
        key: "department",
      });

      expect(removed).toBe(true);

      const value = await t.query(api.queries.getUserAttribute, {
        tenantId: TENANT,
        userId: "user_123",
        key: "department",
      });

      expect(value).toBeNull();
    });
  });

  describe("effective permissions", () => {
    it("should compute effective permissions from roles", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
      });

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      const permNames = permissions.map((p) => p.permission);
      expect(permNames).toContain("documents:read");
      expect(permNames).toContain("documents:write");
    });

    it("should track denied permissions", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read", "documents:write", "documents:delete"],
      });

      await t.mutation(api.unified.denyPermissionUnified, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      const allowedNames = permissions
        .filter((p) => p.effect === "allow")
        .map((p) => p.permission);
      const deniedNames = permissions
        .filter((p) => p.effect === "deny")
        .map((p) => p.permission);

      expect(allowedNames).not.toContain("documents:delete");
      expect(deniedNames).toContain("documents:delete");
    });
  });

  describe("audit logging", () => {
    it("should log role assignment with audit enabled", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.assignRoleUnified, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
        assignedBy: "admin_user",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        tenantId: TENANT,
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs).toHaveLength(1);
      expect(logs[0].action).toBe("role_assigned");
      expect((logs[0].details as { role?: string }).role).toBe("admin");
    });
  });
});
