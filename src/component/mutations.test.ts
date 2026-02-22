/**
 * Additional mutation tests to cover uncovered code paths
 */

import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "./schema.js";
import { api } from "./_generated/api.js";

const modules = import.meta.glob("./**/*.ts");

describe("mutations - additional coverage", () => {
  describe("revokeRole", () => {
    it("should return false when revoking non-existent role", async () => {
      const t = convexTest(schema, modules);

      const result = await t.mutation(api.mutations.revokeRole, {
        userId: "user_123",
        role: "nonexistent",
      });

      expect(result).toBe(false);
    });

    it("should revoke scoped role", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      const result = await t.mutation(api.mutations.revokeRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      expect(result).toBe(true);
    });

    it("should not revoke when scope doesn't match", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      const result = await t.mutation(api.mutations.revokeRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_2" },
      });

      expect(result).toBe(false);
    });

    it("should log audit entry when enabled", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
      });

      await t.mutation(api.mutations.revokeRole, {
        userId: "user_123",
        role: "admin",
        revokedBy: "actor_1",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      const revokeLog = logs.find((l) => l.action === "role_revoked");
      expect(revokeLog).toBeDefined();
      expect(revokeLog!.actorId).toBe("actor_1");
    });

    it("should not match scoped vs unscoped", async () => {
      const t = convexTest(schema, modules);

      // Assign a scoped role
      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      // Try to revoke global (unscoped) role - shouldn't match
      const result = await t.mutation(api.mutations.revokeRole, {
        userId: "user_123",
        role: "admin",
      });

      // Since assignment has scope but revoke has no scope: a.scope exists, args.scope doesn't
      // This will fail because the scope matcher checks: if !a.scope && !args.scope -> false (a.scope exists)
      // if !a.scope || !args.scope -> true for !args.scope but a.scope exists
      // So it returns false for `!a.scope || !args.scope` -> we check: a.scope = {type:"team",...}, args.scope = undefined
      // !a.scope = false, !args.scope = true -> enters this branch -> returns false
      expect(result).toBe(false);
    });
  });

  describe("revokeAllRoles", () => {
    it("should revoke all roles for a user", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "editor",
      });

      const count = await t.mutation(api.mutations.revokeAllRoles, {
        userId: "user_123",
      });

      expect(count).toBe(2);

      const roles = await t.query(api.queries.getUserRoles, {
        userId: "user_123",
      });
      expect(roles).toHaveLength(0);
    });

    it("should revoke only matching scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "editor",
        scope: { type: "team", id: "team_2" },
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "viewer",
      });

      // Revoke only team_1 scope
      const count = await t.mutation(api.mutations.revokeAllRoles, {
        userId: "user_123",
        scope: { type: "team", id: "team_1" },
      });

      expect(count).toBe(1);

      const roles = await t.query(api.queries.getUserRoles, {
        userId: "user_123",
      });
      expect(roles).toHaveLength(2);
    });

    it("should skip assignments without scope when scope filter is set", async () => {
      const t = convexTest(schema, modules);

      // Global (no scope)
      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "viewer",
      });

      // Scoped
      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      // Try revoking with scope filter - global one should be skipped
      const count = await t.mutation(api.mutations.revokeAllRoles, {
        userId: "user_123",
        scope: { type: "team", id: "team_1" },
      });

      expect(count).toBe(1);
    });

    it("should skip assignments with different scope when scope filter is set", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "editor",
        scope: { type: "team", id: "team_2" },
      });

      const count = await t.mutation(api.mutations.revokeAllRoles, {
        userId: "user_123",
        scope: { type: "team", id: "team_1" },
      });

      expect(count).toBe(1);
    });

    it("should log audit entries when enabled", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "editor",
      });

      await t.mutation(api.mutations.revokeAllRoles, {
        userId: "user_123",
        revokedBy: "system",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      const revokeLogs = logs.filter((l) => l.action === "role_revoked");
      expect(revokeLogs).toHaveLength(2);
    });
  });

  describe("assignRoles", () => {
    it("should assign multiple roles in one transaction", async () => {
      const t = convexTest(schema, modules);

      const result = await t.mutation(api.mutations.assignRoles, {
        userId: "user_123",
        roles: [
          { role: "admin" },
          { role: "editor", scope: { type: "team", id: "team_1" } },
        ],
        enableAudit: true,
      });

      expect(result.assigned).toBe(2);
      expect(result.assignmentIds).toHaveLength(2);

      const roles = await t.query(api.queries.getUserRoles, {
        userId: "user_123",
      });
      expect(roles).toHaveLength(2);
    });

    it("should throw on duplicate role+scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
      });

      await expect(
        t.mutation(api.mutations.assignRoles, {
          userId: "user_123",
          roles: [{ role: "admin" }, { role: "editor" }],
        })
      ).rejects.toThrow(/ALREADY_EXISTS/);
    });

    it("should throw when roles exceed limit", async () => {
      const t = convexTest(schema, modules);

      const roles = Array.from({ length: 101 }, (_, i) => ({
        role: "viewer",
        scope: { type: "team", id: `team_${i}` },
      }));

      await expect(
        t.mutation(api.mutations.assignRoles, {
          userId: "user_123",
          roles,
        })
      ).rejects.toThrow(/must not exceed 100/);
    });
  });

  describe("revokeRoles", () => {
    it("should revoke multiple roles in one transaction", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
      });
      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "editor",
      });

      const result = await t.mutation(api.mutations.revokeRoles, {
        userId: "user_123",
        roles: [{ role: "admin" }, { role: "editor" }],
        enableAudit: true,
      });

      expect(result.revoked).toBe(2);

      const roles = await t.query(api.queries.getUserRoles, {
        userId: "user_123",
      });
      expect(roles).toHaveLength(0);
    });

    it("should only revoke matching scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });
      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_2" },
      });

      const result = await t.mutation(api.mutations.revokeRoles, {
        userId: "user_123",
        roles: [{ role: "admin", scope: { type: "team", id: "team_1" } }],
      });

      expect(result.revoked).toBe(1);

      const roles = await t.query(api.queries.getUserRoles, {
        userId: "user_123",
      });
      expect(roles).toHaveLength(1);
      expect(roles[0].scope).toEqual({ type: "team", id: "team_2" });
    });
  });

  describe("offboardUser", () => {
    it("should remove all roles, overrides, and attributes for user", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_off",
        role: "admin",
      });
      await t.mutation(api.mutations.grantPermission, {
        userId: "user_off",
        permission: "documents:read",
      });
      await t.mutation(api.mutations.setAttribute, {
        userId: "user_off",
        key: "dept",
        value: "eng",
      });

      const result = await t.mutation(api.mutations.offboardUser, {
        userId: "user_off",
        enableAudit: true,
      });

      expect(result.rolesRevoked).toBe(1);
      expect(result.overridesRemoved).toBe(1);
      expect(result.attributesRemoved).toBe(1);
      expect(result.relationshipsRemoved).toBe(0);
      expect(result.effectiveRelationshipsRemoved).toBe(0);

      const roles = await t.query(api.queries.getUserRoles, {
        userId: "user_off",
      });
      expect(roles).toHaveLength(0);

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_off",
      });
      expect(overrides).toHaveLength(0);

      const attrs = await t.query(api.queries.getUserAttributes, {
        userId: "user_off",
      });
      expect(attrs).toHaveLength(0);
    });

    it("should remove ReBAC relationships on full offboard (no scope)", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_rel",
        role: "viewer",
      });
      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "user_rel",
        relation: "member",
        objectType: "team",
        objectId: "team_1",
      });

      const result = await t.mutation(api.mutations.offboardUser, {
        userId: "user_rel",
      });

      expect(result.rolesRevoked).toBe(1);
      expect(result.relationshipsRemoved).toBe(1);

      const relations = await t.query(api.rebac.getSubjectRelations, {
        subjectType: "user",
        subjectId: "user_rel",
      });
      expect(relations).toHaveLength(0);
    });

    it("should not remove relationships when scope is provided", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "user_scoped_rel",
        relation: "member",
        objectType: "team",
        objectId: "team_1",
      });
      await t.mutation(api.mutations.assignRole, {
        userId: "user_scoped_rel",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      const result = await t.mutation(api.mutations.offboardUser, {
        userId: "user_scoped_rel",
        scope: { type: "team", id: "team_1" },
      });

      expect(result.rolesRevoked).toBe(1);
      expect(result.relationshipsRemoved).toBe(0);

      const relations = await t.query(api.rebac.getSubjectRelations, {
        subjectType: "user",
        subjectId: "user_scoped_rel",
      });
      expect(relations).toHaveLength(1);
    });

    it("should respect scope when provided", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_off2",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });
      await t.mutation(api.mutations.assignRole, {
        userId: "user_off2",
        role: "viewer",
        scope: { type: "team", id: "team_2" },
      });

      const result = await t.mutation(api.mutations.offboardUser, {
        userId: "user_off2",
        scope: { type: "team", id: "team_1" },
      });

      expect(result.rolesRevoked).toBe(1);

      const roles = await t.query(api.queries.getUserRoles, {
        userId: "user_off2",
      });
      expect(roles).toHaveLength(1);
      expect(roles[0].role).toBe("viewer");
      expect(roles[0].scope).toEqual({ type: "team", id: "team_2" });
    });

    it("should skip attributes and overrides when options false", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_off3",
        role: "admin",
      });
      await t.mutation(api.mutations.setAttribute, {
        userId: "user_off3",
        key: "keep",
        value: "me",
      });

      await t.mutation(api.mutations.offboardUser, {
        userId: "user_off3",
        removeAttributes: false,
        removeOverrides: false,
      });

      const roles = await t.query(api.queries.getUserRoles, {
        userId: "user_off3",
      });
      expect(roles).toHaveLength(0);

      const attrs = await t.query(api.queries.getUserAttributes, {
        userId: "user_off3",
      });
      expect(attrs).toHaveLength(1);
      expect(attrs[0].key).toBe("keep");
    });
  });

  describe("deprovisionUser", () => {
    it("should wipe all roles, overrides, attributes, and relationships in one call", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_dep",
        role: "admin",
      });
      await t.mutation(api.mutations.grantPermission, {
        userId: "user_dep",
        permission: "documents:read",
      });
      await t.mutation(api.mutations.setAttribute, {
        userId: "user_dep",
        key: "dept",
        value: "eng",
      });
      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "user_dep",
        relation: "member",
        objectType: "team",
        objectId: "team_1",
      });

      const result = await t.mutation(api.mutations.deprovisionUser, {
        userId: "user_dep",
        enableAudit: true,
      });

      expect(result.rolesRevoked).toBe(1);
      expect(result.overridesRemoved).toBe(1);
      expect(result.attributesRemoved).toBe(1);
      expect(result.relationshipsRemoved).toBe(1);

      const roles = await t.query(api.queries.getUserRoles, { userId: "user_dep" });
      expect(roles).toHaveLength(0);
      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_dep",
      });
      expect(overrides).toHaveLength(0);
      const attrs = await t.query(api.queries.getUserAttributes, {
        userId: "user_dep",
      });
      expect(attrs).toHaveLength(0);
      const relations = await t.query(api.rebac.getSubjectRelations, {
        subjectType: "user",
        subjectId: "user_dep",
      });
      expect(relations).toHaveLength(0);
    });
  });

  describe("setAttribute", () => {
    it("should update existing attribute", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.setAttribute, {
        userId: "user_123",
        key: "department",
        value: "engineering",
      });

      const result = await t.mutation(api.mutations.setAttribute, {
        userId: "user_123",
        key: "department",
        value: "sales",
      });

      expect(result).toBeDefined();

      const value = await t.query(api.queries.getUserAttribute, {
        userId: "user_123",
        key: "department",
      });
      expect(value).toBe("sales");
    });

    it("should log audit when updating existing attribute", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.setAttribute, {
        userId: "user_123",
        key: "department",
        value: "engineering",
      });

      await t.mutation(api.mutations.setAttribute, {
        userId: "user_123",
        key: "department",
        value: "sales",
        setBy: "actor_1",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.some((l) => l.action === "attribute_set")).toBe(true);
    });

    it("should log audit when creating new attribute", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.setAttribute, {
        userId: "user_123",
        key: "department",
        value: "engineering",
        setBy: "actor_1",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.some((l) => l.action === "attribute_set")).toBe(true);
    });
  });

  describe("removeAttribute", () => {
    it("should return false when attribute does not exist", async () => {
      const t = convexTest(schema, modules);

      const result = await t.mutation(api.mutations.removeAttribute, {
        userId: "user_123",
        key: "nonexistent",
      });

      expect(result).toBe(false);
    });

    it("should log audit when removing attribute", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.setAttribute, {
        userId: "user_123",
        key: "department",
        value: "engineering",
      });

      await t.mutation(api.mutations.removeAttribute, {
        userId: "user_123",
        key: "department",
        removedBy: "actor_1",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.some((l) => l.action === "attribute_removed")).toBe(true);
    });
  });

  describe("removeAllAttributes", () => {
    it("should remove all attributes for a user", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.setAttribute, {
        userId: "user_123",
        key: "department",
        value: "engineering",
      });

      await t.mutation(api.mutations.setAttribute, {
        userId: "user_123",
        key: "level",
        value: 5,
      });

      const count = await t.mutation(api.mutations.removeAllAttributes, {
        userId: "user_123",
      });

      expect(count).toBe(2);

      const attrs = await t.query(api.queries.getUserAttributes, {
        userId: "user_123",
      });
      expect(attrs).toHaveLength(0);
    });

    it("should log audit entries when enabled", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.setAttribute, {
        userId: "user_123",
        key: "department",
        value: "engineering",
      });

      await t.mutation(api.mutations.setAttribute, {
        userId: "user_123",
        key: "level",
        value: 5,
      });

      await t.mutation(api.mutations.removeAllAttributes, {
        userId: "user_123",
        removedBy: "system",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      const removeLogs = logs.filter((l) => l.action === "attribute_removed");
      expect(removeLogs).toHaveLength(2);
    });

    it("should return 0 when no attributes exist", async () => {
      const t = convexTest(schema, modules);

      const count = await t.mutation(api.mutations.removeAllAttributes, {
        userId: "user_123",
      });

      expect(count).toBe(0);
    });
  });

  describe("grantPermission", () => {
    it("should update existing override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        reason: "Initial grant",
      });

      // Grant again should update existing
      const result = await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        reason: "Updated grant",
      });

      expect(result).toBeDefined();

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(overrides).toHaveLength(1);
      expect(overrides[0].reason).toBe("Updated grant");
    });

    it("should log audit when updating existing override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
      });

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        createdBy: "actor_1",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.some((l) => l.action === "permission_granted")).toBe(true);
    });

    it("should log audit when creating new override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        createdBy: "actor_1",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.some((l) => l.action === "permission_granted")).toBe(true);
    });

    it("should handle scoped overrides", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(overrides).toHaveLength(1);
      expect(overrides[0].scope).toEqual({ type: "team", id: "team_1" });
    });
  });

  describe("denyPermission", () => {
    it("should update existing override to deny", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        reason: "Initial deny",
      });

      // Deny again should update existing
      const result = await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        reason: "Updated deny",
      });

      expect(result).toBeDefined();

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(overrides).toHaveLength(1);
      expect(overrides[0].effect).toBe("deny");
    });

    it("should log audit when updating existing deny override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
      });

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        createdBy: "actor_1",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.some((l) => l.action === "permission_denied")).toBe(true);
    });

    it("should log audit when creating new deny override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        createdBy: "actor_1",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs.some((l) => l.action === "permission_denied")).toBe(true);
    });
  });

  describe("removePermissionOverride", () => {
    it("should remove an allow override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
      });

      const result = await t.mutation(api.mutations.removePermissionOverride, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(result).toBe(true);

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
      });
      expect(overrides).toHaveLength(0);
    });

    it("should remove a deny override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
      });

      const result = await t.mutation(api.mutations.removePermissionOverride, {
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(result).toBe(true);
    });

    it("should return false when no override exists", async () => {
      const t = convexTest(schema, modules);

      const result = await t.mutation(api.mutations.removePermissionOverride, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(result).toBe(false);
    });

    it("should remove scoped override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
      });

      const result = await t.mutation(api.mutations.removePermissionOverride, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
      });

      expect(result).toBe(true);
    });

    it("should log audit when removing an allow override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
      });

      await t.mutation(api.mutations.removePermissionOverride, {
        userId: "user_123",
        permission: "documents:read",
        removedBy: "actor_1",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      // When removing an allow override, it logs "permission_denied"
      expect(logs.some((l) => l.action === "permission_denied")).toBe(true);
    });

    it("should log audit when removing a deny override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
      });

      await t.mutation(api.mutations.removePermissionOverride, {
        userId: "user_123",
        permission: "documents:delete",
        removedBy: "actor_1",
        enableAudit: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      // When removing a deny override, it logs "permission_granted"
      expect(logs.some((l) => l.action === "permission_granted")).toBe(true);
    });
  });

  describe("logPermissionCheck", () => {
    it("should log a permission check to audit log", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.logPermissionCheck, {
        userId: "user_123",
        permission: "documents:read",
        result: true,
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect(logs).toHaveLength(1);
      expect(logs[0].action).toBe("permission_check");
      expect((logs[0].details as { permission?: string }).permission).toBe("documents:read");
      expect((logs[0].details as { result?: boolean }).result).toBe(true);
    });

    it("should log with scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.logPermissionCheck, {
        userId: "user_123",
        permission: "documents:read",
        result: false,
        scope: { type: "team", id: "team_1" },
        reason: "No matching role",
      });

      const logsResult = await t.query(api.queries.getAuditLog, {
        userId: "user_123",
      });
      const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

      expect((logs[0].details as { scope?: unknown }).scope).toEqual({ type: "team", id: "team_1" });
      expect((logs[0].details as { reason?: string }).reason).toBe("No matching role");
    });
  });

  describe("cleanupExpired", () => {
    it("should clean up expired role assignments", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        expiresAt: pastTime,
      });

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "editor",
      });

      const result = await t.mutation(api.mutations.cleanupExpired, {});

      expect(result.expiredRoles).toBe(1);
    });

    it("should clean up expired permission overrides", async () => {
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

      const result = await t.mutation(api.mutations.cleanupExpired, {});

      expect(result.expiredOverrides).toBe(1);
    });

    it("should return zeros when nothing is expired", async () => {
      const t = convexTest(schema, modules);

      const result = await t.mutation(api.mutations.cleanupExpired, {});

      expect(result.expiredRoles).toBe(0);
      expect(result.expiredOverrides).toBe(0);
    });
  });

  describe("runScheduledCleanup", () => {
    it("should purge expired role assignments and overrides and return counts", async () => {
      const t = convexTest(schema, modules);
      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.assignRole, {
        userId: "user_1",
        role: "admin",
        expiresAt: pastTime,
      });
      await t.mutation(api.mutations.assignRole, {
        userId: "user_2",
        role: "editor",
      });
      await t.mutation(api.mutations.grantPermission, {
        userId: "user_1",
        permission: "documents:read",
        expiresAt: pastTime,
      });

      const result = await t.mutation(api.mutations.runScheduledCleanup, {});

      expect(result.expiredRoleAssignments).toBe(1);
      expect(result.expiredOverrides).toBe(1);
      expect(result.expiredEffectiveRoles).toBeGreaterThanOrEqual(0);
      expect(result.expiredEffectivePermissions).toBeGreaterThanOrEqual(0);
    });

    it("should return all zeros when nothing is expired", async () => {
      const t = convexTest(schema, modules);
      const result = await t.mutation(api.mutations.runScheduledCleanup, {});
      expect(result.expiredRoleAssignments).toBe(0);
      expect(result.expiredOverrides).toBe(0);
      expect(result.expiredEffectiveRoles).toBe(0);
      expect(result.expiredEffectivePermissions).toBe(0);
    });
  });

  describe("runAuditRetentionCleanup", () => {
    it("should return zeros when no policy args and no env", async () => {
      const t = convexTest(schema, modules);
      const result = await t.mutation(api.mutations.runAuditRetentionCleanup, {});
      expect(result.deletedByAge).toBe(0);
      expect(result.deletedByCount).toBe(0);
    });

    it("should not delete when maxAgeDays is 0", async () => {
      const t = convexTest(schema, modules);
      await t.mutation(api.mutations.assignRole, {
        userId: "user_1",
        role: "admin",
        enableAudit: true,
      });
      const result = await t.mutation(api.mutations.runAuditRetentionCleanup, {
        maxAgeDays: 0,
      });
      expect(result.deletedByAge).toBe(0);
    });

    it("should not delete when maxEntries is 0", async () => {
      const t = convexTest(schema, modules);
      await t.mutation(api.mutations.assignRole, {
        userId: "user_1",
        role: "admin",
        enableAudit: true,
      });
      const result = await t.mutation(api.mutations.runAuditRetentionCleanup, {
        maxEntries: 0,
      });
      expect(result.deletedByCount).toBe(0);
    });

    it("should cap entries when maxEntries is set", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_1",
        role: "admin",
        enableAudit: true,
      });
      await t.mutation(api.mutations.assignRole, {
        userId: "user_1",
        role: "editor",
        enableAudit: true,
      });
      await t.mutation(api.mutations.grantPermission, {
        userId: "user_1",
        permission: "documents:read",
        enableAudit: true,
      });

      const before = await t.query(api.queries.getAuditLog, {});
      const initialCount = Array.isArray(before) ? before.length : before.page.length;
      expect(initialCount).toBeGreaterThanOrEqual(2);

      const result = await t.mutation(api.mutations.runAuditRetentionCleanup, {
        maxEntries: 1,
      });

      expect(result.deletedByCount).toBeGreaterThanOrEqual(1);

      const after = await t.query(api.queries.getAuditLog, {});
      const afterCount = Array.isArray(after) ? after.length : after.page.length;
      expect(afterCount).toBe(1);
    });
  });

  describe("assignRole - expired duplicate handling", () => {
    it("should allow assigning role if previous assignment expired", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        expiresAt: pastTime,
      });

      // Should not throw since the previous assignment is expired
      const result = await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
      });

      expect(result).toBeDefined();
    });
  });

  describe("assignRole - scope comparison edge cases", () => {
    it("should detect duplicate scoped assignment with exact same scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      // Attempting duplicate scoped assignment should throw
      await expect(
        t.mutation(api.mutations.assignRole, {
          userId: "user_123",
          role: "admin",
          scope: { type: "team", id: "team_1" },
        })
      ).rejects.toThrow();
    });

    it("should allow assigning same role with different scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      // Different scope should be ok
      const result = await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_2" },
      });

      expect(result).toBeDefined();
    });

    it("should allow assigning global role when scoped exists", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "team", id: "team_1" },
      });

      // Global role should be a separate assignment
      const result = await t.mutation(api.mutations.assignRole, {
        userId: "user_123",
        role: "admin",
      });

      expect(result).toBeDefined();
    });
  });

  describe("grantPermission - scoped duplicate handling", () => {
    it("should update existing scoped override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
        reason: "Initial",
      });

      // Same permission, same scope - should update
      const result = await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
        reason: "Updated",
      });

      expect(result).toBeDefined();
    });

    it("should create new override for different scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
      });

      // Different scope - new override
      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_2" },
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(overrides).toHaveLength(2);
    });
  });

  describe("denyPermission - scoped duplicate handling", () => {
    it("should update existing scoped deny override", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        scope: { type: "team", id: "team_1" },
        reason: "Initial",
      });

      // Same permission, same scope - should update
      const result = await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        scope: { type: "team", id: "team_1" },
        reason: "Updated",
      });

      expect(result).toBeDefined();
    });

    it("should create new deny override for different scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        scope: { type: "team", id: "team_1" },
      });

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        scope: { type: "team", id: "team_2" },
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(overrides).toHaveLength(2);
    });
  });

  describe("grantPermission - scope mismatch branches", () => {
    it("should not find duplicate when existing has no scope but request has scope", async () => {
      const t = convexTest(schema, modules);

      // Unscoped override
      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
      });

      // Scoped override - should create new, not update
      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(overrides).toHaveLength(2);
    });

    it("should not find duplicate when existing has scope but request has no scope", async () => {
      const t = convexTest(schema, modules);

      // Scoped override
      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
      });

      // Unscoped override - should create new, not update
      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(overrides).toHaveLength(2);
    });
  });

  describe("denyPermission - scope mismatch branches", () => {
    it("should not find duplicate when existing has no scope but request has scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
      });

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        scope: { type: "team", id: "team_1" },
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(overrides).toHaveLength(2);
    });

    it("should not find duplicate when existing has scope but request has no scope", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        scope: { type: "team", id: "team_1" },
      });

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
      });

      const overrides = await t.query(api.queries.getPermissionOverrides, {
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(overrides).toHaveLength(2);
    });
  });

  describe("grantPermission - expired override in duplicate check", () => {
    it("should create new override when existing one is expired", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        expiresAt: pastTime,
      });

      // Should not find the expired override as duplicate, so creates new
      const result = await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        reason: "Fresh grant",
      });

      expect(result).toBeDefined();
    });
  });

  describe("denyPermission - expired override in duplicate check", () => {
    it("should create new override when existing one is expired", async () => {
      const t = convexTest(schema, modules);

      const pastTime = Date.now() - 10000;

      await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        expiresAt: pastTime,
      });

      // Should not find the expired override as duplicate
      const result = await t.mutation(api.mutations.denyPermission, {
        userId: "user_123",
        permission: "documents:delete",
        reason: "Fresh deny",
      });

      expect(result).toBeDefined();
    });
  });

  describe("removePermissionOverride - scope mismatch branches", () => {
    it("should not find override when existing is scoped but request is not", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
      });

      // Try removing without scope - should not match
      const result = await t.mutation(api.mutations.removePermissionOverride, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(result).toBe(false);
    });

    it("should not find override when existing is unscoped but request is scoped", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
      });

      // Try removing with scope - should not match
      const result = await t.mutation(api.mutations.removePermissionOverride, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
      });

      expect(result).toBe(false);
    });

    it("should not find override when scopes differ", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.mutations.grantPermission, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_1" },
      });

      const result = await t.mutation(api.mutations.removePermissionOverride, {
        userId: "user_123",
        permission: "documents:read",
        scope: { type: "team", id: "team_2" },
      });

      expect(result).toBe(false);
    });
  });
});
