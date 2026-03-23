/**
 * Tests for O(1) indexed authorization - covers additional paths
 */

import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "../schema.js";
import { api } from "../_generated/api.js";

const modules = import.meta.glob("../**/*.ts");
const TENANT = "test-tenant";

describe("O(1) Indexed Authorization", () => {
  describe("indexed role assignment", () => {
    it("should assign role and compute permissions", async () => {
      const t = convexTest(schema, modules);

      const roleId = await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read", "documents:write", "documents:delete"],
      });

      expect(roleId).toBeDefined();

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(permissions).toHaveLength(3);
    });

    it("should check permission in O(1)", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
      });

      const canRead = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(canRead).toBe(true);

      const canDelete = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(canDelete).toBe(false);
    });

    it("should check role in O(1)", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["*:*"],
      });

      const hasAdmin = await t.query(api.indexed.hasRoleFast, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
      });

      expect(hasAdmin).toBe(true);

      const hasViewer = await t.query(api.indexed.hasRoleFast, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
      });

      expect(hasViewer).toBe(false);
    });

    it("should revoke role and remove permissions", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
      });

      const revoked = await t.mutation(api.indexed.revokeRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
      });

      expect(revoked).toBe(true);

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(permissions).toHaveLength(0);
    });

    it("checkPermissionsFast (canAny) returns true when user has one of the permissions", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: ["documents:read"],
      });

      const result = await t.query(api.indexed.checkPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
        permissions: ["documents:delete", "documents:read", "documents:update"],
      });

      expect(result).toBe(true);
    });

    it("checkPermissionsFast returns false when user has none", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: ["documents:read"],
      });

      const result = await t.query(api.indexed.checkPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
        permissions: ["documents:delete", "documents:update"],
      });

      expect(result).toBe(false);
    });

    it("assignRolesWithCompute assigns multiple roles in one transaction", async () => {
      const t = convexTest(schema, modules);

      const rolePermissionsMap: Record<string, string[]> = {
        admin: ["documents:read", "documents:write", "documents:delete"],
        editor: ["documents:read", "documents:write"],
      };

      const result = await t.mutation(api.indexed.assignRolesWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        roles: [
          { role: "admin" },
          { role: "editor", scope: { type: "team", id: "team_1" } },
        ],
        rolePermissionsMap,
      });

      expect(result.assigned).toBe(2);
      expect(result.assignmentIds).toHaveLength(2);

      const canDelete = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });
      expect(canDelete).toBe(true);

      const canWriteScoped = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:write",
        objectType: "team",
        objectId: "team_1",
      });
      expect(canWriteScoped).toBe(true);
    });

    it("revokeRolesWithCompute revokes multiple roles in one transaction", async () => {
      const t = convexTest(schema, modules);

      const rolePermissionsMap: Record<string, string[]> = {
        admin: ["documents:read", "documents:delete"],
        editor: ["documents:read", "documents:write"],
      };

      await t.mutation(api.indexed.assignRolesWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        roles: [{ role: "admin" }, { role: "editor" }],
        rolePermissionsMap,
      });

      const result = await t.mutation(api.indexed.revokeRolesWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        roles: [{ role: "admin" }, { role: "editor" }],
        rolePermissionsMap,
      });

      expect(result.revoked).toBe(2);

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });
      expect(permissions).toHaveLength(0);
    });

    it("should update existing role assignment", async () => {
      const t = convexTest(schema, modules);

      const futureTime = Date.now() + 3600000;

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read"],
      });

      // Assign same role again - should update
      const roleId = await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read"],
        expiresAt: futureTime,
      });

      expect(roleId).toBeDefined();

      const hasRole = await t.query(api.indexed.hasRoleFast, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
      });

      expect(hasRole).toBe(true);
    });

    it("should add role as source to existing permission", async () => {
      const t = convexTest(schema, modules);

      // Assign viewer with read permission
      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: ["documents:read"],
      });

      // Assign editor with same read permission (plus write)
      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
      });

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(permissions).toHaveLength(2);

      const readPerm = permissions.find((p) => p.permission === "documents:read");
      expect(readPerm).toBeDefined();
      expect(readPerm!.sources).toContain("viewer");
      expect(readPerm!.sources).toContain("editor");
    });

    it("should not duplicate source when same role is assigned again", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read"],
      });

      // Assign same role again
      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read"],
      });

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      const readPerm = permissions.find((p) => p.permission === "documents:read");
      expect(readPerm!.sources.filter((s) => s === "admin")).toHaveLength(1);
    });
  });

  describe("indexed scoped permissions", () => {
    it("should handle scoped role assignments", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
        scope: { type: "team", id: "team_456" },
      });

      const canReadGlobal = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(canReadGlobal).toBe(false);

      const canReadScoped = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        objectType: "team",
        objectId: "team_456",
      });

      expect(canReadScoped).toBe(true);
    });

    it("should handle scoped role check", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["*:*"],
        scope: { type: "org", id: "org_1" },
      });

      const hasRoleGlobal = await t.query(api.indexed.hasRoleFast, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
      });

      expect(hasRoleGlobal).toBe(false);

      const hasRoleScoped = await t.query(api.indexed.hasRoleFast, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        objectType: "org",
        objectId: "org_1",
      });

      expect(hasRoleScoped).toBe(true);
    });
  });

  describe("indexed direct permissions", () => {
    it("should grant direct permission", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.grantPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "special:access",
        reason: "VIP user",
      });

      const hasPermission = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "special:access",
      });

      expect(hasPermission).toBe(true);
    });

    it("should deny permission overriding role", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:delete"],
      });

      await t.mutation(api.indexed.denyPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
        reason: "Restricted",
      });

      const canDelete = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(canDelete).toBe(false);
    });

    it("should grant scoped permission", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.grantPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
        grantedBy: "admin_user",
      });

      const canReadScoped = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        objectType: "team",
        objectId: "team_1",
      });

      expect(canReadScoped).toBe(true);

      const canReadGlobal = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(canReadGlobal).toBe(false);
    });

    it("should update existing permission to allow", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.denyPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      // Now grant - should update existing
      await t.mutation(api.indexed.grantPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      const canRead = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(canRead).toBe(true);
    });

    it("should update existing permission to deny", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.grantPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      // Now deny - should update existing
      await t.mutation(api.indexed.denyPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      const canRead = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(canRead).toBe(false);
    });

    it("should deny scoped permission", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.denyPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
        scope: { type: "doc", id: "sensitive" },
        deniedBy: "admin_user",
      });

      const canDelete = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:delete",
        objectType: "doc",
        objectId: "sensitive",
      });

      expect(canDelete).toBe(false);
    });
  });

  describe("revokeRoleWithCompute", () => {
    it("should return false when role does not exist", async () => {
      const t = convexTest(schema, modules);

      const result = await t.mutation(api.indexed.revokeRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "nonexistent",
        rolePermissions: [],
      });

      expect(result).toBe(false);
    });

    it("should keep permissions that have other sources", async () => {
      const t = convexTest(schema, modules);

      // Both roles grant documents:read
      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: ["documents:read"],
      });

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
      });

      // Revoke viewer - documents:read should remain (from editor)
      await t.mutation(api.indexed.revokeRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: ["documents:read"],
      });

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(permissions.some((p) => p.permission === "documents:read")).toBe(true);
      expect(permissions.some((p) => p.permission === "documents:write")).toBe(true);

      // Check that viewer is removed from sources
      const readPerm = permissions.find((p) => p.permission === "documents:read");
      expect(readPerm!.sources).not.toContain("viewer");
      expect(readPerm!.sources).toContain("editor");
    });

    it("should revoke scoped role", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read"],
        scope: { type: "team", id: "team_1" },
      });

      const result = await t.mutation(api.indexed.revokeRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read"],
        scope: { type: "team", id: "team_1" },
      });

      expect(result).toBe(true);

      const hasRole = await t.query(api.indexed.hasRoleFast, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        objectType: "team",
        objectId: "team_1",
      });

      expect(hasRole).toBe(false);
    });
  });

  describe("expired entries", () => {
    it("should return false for expired permission", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.indexed.grantPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        expiresAt: pastTime,
      });

      const canRead = await t.query(api.indexed.checkPermissionFast, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
      });

      expect(canRead).toBe(false);
    });

    it("should return false for expired role", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read"],
        expiresAt: pastTime,
      });

      const hasRole = await t.query(api.indexed.hasRoleFast, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
      });

      expect(hasRole).toBe(false);
    });
  });

  describe("indexed relationships", () => {
    it("should add relationship with computed effective relations", async () => {
      const t = convexTest(schema, modules);

      const relationId = await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(relationId).toBeDefined();

      const hasRelation = await t.query(api.indexed.hasRelationFast, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(hasRelation).toBe(true);
    });

    it("should return existing ID when relation already exists", async () => {
      const t = convexTest(schema, modules);

      const id1 = await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const id2 = await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(id2).toBe(id1);
    });

    it("should add inherited relationships", async () => {
      const t = convexTest(schema, modules);

      // Setup: team -> org hierarchy
      await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "team",
        subjectId: "sales",
        relation: "parent",
        objectType: "org",
        objectId: "acme",
      });

      // Add user as member of team, with inherited viewer on org
      await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
        inheritedRelations: [
          {
            relation: "viewer",
            fromObjectType: "org",
            fromRelation: "parent",
          },
        ],
      });

      // Check direct relation
      const isMember = await t.query(api.indexed.hasRelationFast, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });
      expect(isMember).toBe(true);

      // Check inherited relation
      const isViewer = await t.query(api.indexed.hasRelationFast, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "org",
        objectId: "acme",
      });
      expect(isViewer).toBe(true);
    });

    it("should not duplicate inherited relationships", async () => {
      const t = convexTest(schema, modules);

      // Setup hierarchy
      await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "team",
        subjectId: "sales",
        relation: "parent",
        objectType: "org",
        objectId: "acme",
      });

      // Pre-create the inherited relationship
      await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "org",
        objectId: "acme",
      });

      // Now add with inherited - should not create duplicate
      await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
        inheritedRelations: [
          {
            relation: "viewer",
            fromObjectType: "org",
            fromRelation: "parent",
          },
        ],
      });

      // Should still have the relation (no error from duplicate)
      const isViewer = await t.query(api.indexed.hasRelationFast, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "org",
        objectId: "acme",
      });
      expect(isViewer).toBe(true);
    });

    it("should remove relationship and inherited", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const removed = await t.mutation(api.indexed.removeRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(removed).toBe(true);

      const hasRelation = await t.query(api.indexed.hasRelationFast, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(hasRelation).toBe(false);
    });

    it("should return false when removing non-existent relationship", async () => {
      const t = convexTest(schema, modules);

      const removed = await t.mutation(api.indexed.removeRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "nonexistent",
      });

      expect(removed).toBe(false);
    });

    it("should remove inherited relationships when removing parent", async () => {
      const t = convexTest(schema, modules);

      // Setup hierarchy
      await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "team",
        subjectId: "sales",
        relation: "parent",
        objectType: "org",
        objectId: "acme",
      });

      // Add with inherited
      await t.mutation(api.indexed.addRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
        inheritedRelations: [
          {
            relation: "viewer",
            fromObjectType: "org",
            fromRelation: "parent",
          },
        ],
        createdBy: "system",
      });

      // Remove the direct relation
      await t.mutation(api.indexed.removeRelationWithCompute, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      // Inherited should also be gone
      const isViewer = await t.query(api.indexed.hasRelationFast, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "org",
        objectId: "acme",
      });
      expect(isViewer).toBe(false);
    });
  });

  describe("batch queries", () => {
    it("should get user permissions with scope filter", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read"],
      });

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:write"],
        scope: { type: "team", id: "team_1" },
      });

      // Global scope
      const globalPerms = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
        scopeKey: "global",
      });

      expect(globalPerms.some((p) => p.permission === "documents:read")).toBe(true);
      expect(globalPerms.some((p) => p.permission === "documents:write")).toBe(false);

      // Team scope
      const teamPerms = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
        scopeKey: "team:team_1",
      });

      expect(teamPerms.some((p) => p.permission === "documents:write")).toBe(true);
    });

    it("should filter expired permissions in getUserPermissionsFast", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.indexed.grantPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        expiresAt: pastTime,
      });

      await t.mutation(api.indexed.grantPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:write",
      });

      const perms = await t.query(api.indexed.getUserPermissionsFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(perms).toHaveLength(1);
      expect(perms[0].permission).toBe("documents:write");
    });

    it("should get user roles with scope filter", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
      });

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "editor",
        rolePermissions: [],
        scope: { type: "team", id: "team_1" },
      });

      const globalRoles = await t.query(api.indexed.getUserRolesFast, {
        tenantId: TENANT,
        userId: "user_123",
        scopeKey: "global",
      });

      expect(globalRoles.some((r) => r.role === "admin")).toBe(true);
      expect(globalRoles.some((r) => r.role === "editor")).toBe(false);

      const teamRoles = await t.query(api.indexed.getUserRolesFast, {
        tenantId: TENANT,
        userId: "user_123",
        scopeKey: "team:team_1",
      });

      expect(teamRoles.some((r) => r.role === "editor")).toBe(true);
    });

    it("should filter expired roles in getUserRolesFast", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
        expiresAt: pastTime,
      });

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "viewer",
        rolePermissions: [],
      });

      const roles = await t.query(api.indexed.getUserRolesFast, {
        tenantId: TENANT,
        userId: "user_123",
      });

      expect(roles).toHaveLength(1);
      expect(roles[0].role).toBe("viewer");
    });
  });

  describe("cleanup", () => {
    it("should clean up expired permissions and roles", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.indexed.grantPermissionDirect, {
        tenantId: TENANT,
        userId: "user_123",
        permission: "documents:read",
        expiresAt: pastTime,
      });

      await t.mutation(api.indexed.assignRoleWithCompute, {
        tenantId: TENANT,
        userId: "user_123",
        role: "admin",
        rolePermissions: [],
        expiresAt: pastTime,
      });

      const result = await t.mutation(api.indexed.cleanupExpired, {
        tenantId: TENANT,
      });

      expect(result.expiredPermissions).toBeGreaterThanOrEqual(1);
      expect(result.expiredRoles).toBe(1);
    });

    it("should return zeros when nothing expired", async () => {
      const t = convexTest(schema, modules);

      const result = await t.mutation(api.indexed.cleanupExpired, {
        tenantId: TENANT,
      });

      expect(result.expiredPermissions).toBe(0);
      expect(result.expiredRoles).toBe(0);
    });
  });
});
