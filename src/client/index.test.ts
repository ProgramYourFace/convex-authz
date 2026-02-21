import { describe, expect, it, vi } from "vitest";
import {
  definePermissions,
  defineRoles,
  definePolicies,
  flattenRolePermissions,
  Authz,
  IndexedAuthz,
} from "./index.js";
import type { ComponentApi } from "../component/_generated/component.js";

// ============================================================================
// Helper function tests
// ============================================================================

describe("client helpers", () => {
  describe("definePermissions", () => {
    it("should return permissions as-is for single definition", () => {
      const permissions = definePermissions({
        documents: {
          create: true,
          read: true,
          update: true,
          delete: true,
        },
        settings: {
          view: true,
          manage: true,
        },
      });

      expect(permissions.documents.create).toBe(true);
      expect(permissions.settings.manage).toBe(true);
    });

    it("should merge two permission definitions", () => {
      const p1 = { documents: { read: true, write: true } };
      const p2 = { settings: { view: true, manage: true } };

      const merged = definePermissions(p1, p2);

      expect(merged.documents.read).toBe(true);
      expect(merged.settings.view).toBe(true);
    });

    it("should merge overlapping resources across definitions", () => {
      const p1 = { documents: { read: true } };
      const p2 = { documents: { write: true }, settings: { view: true } };

      const merged = definePermissions(p1, p2);

      expect(merged.documents.read).toBe(true);
      expect(merged.documents.write).toBe(true);
      expect(merged.settings.view).toBe(true);
    });

    it("should merge three permission definitions", () => {
      const p1 = { documents: { read: true } };
      const p2 = { settings: { view: true } };
      const p3 = { billing: { manage: true } };

      const merged = definePermissions(p1, p2, p3);

      expect(merged.documents.read).toBe(true);
      expect(merged.settings.view).toBe(true);
      expect(merged.billing.manage).toBe(true);
    });
  });

  describe("defineRoles", () => {
    const permissions = definePermissions({
      documents: { create: true, read: true },
      settings: { view: true },
    });

    it("should return roles as-is for single definition", () => {
      const roles = defineRoles(permissions, {
        admin: { documents: ["create", "read"] },
        viewer: { documents: ["read"] },
      });

      expect(roles.admin.documents).toEqual(["create", "read"]);
      expect(roles.viewer.documents).toEqual(["read"]);
    });

    it("should merge two role definitions", () => {
      const r1 = { admin: { documents: ["create", "read"] as const } };
      const r2 = { viewer: { documents: ["read"] as const } };

      const merged = defineRoles(permissions, r1, r2);

      expect(merged.admin.documents).toEqual(["create", "read"]);
      expect(merged.viewer.documents).toEqual(["read"]);
    });

    it("should merge overlapping roles and deduplicate permissions", () => {
      const r1 = { admin: { documents: ["read"] as const } };
      const r2 = { admin: { documents: ["read", "create"] as const, settings: ["view"] as const } };

      const merged = defineRoles(permissions, r1, r2);

      // Permissions should be deduplicated
      expect(merged.admin.documents).toEqual(["read", "create"]);
      expect(merged.admin.settings).toEqual(["view"]);
    });

    it("should merge three role definitions", () => {
      const r1 = { admin: { documents: ["read"] as const } };
      const r2 = { viewer: { documents: ["read"] as const } };
      const r3 = { editor: { documents: ["read", "create"] as const } };

      const merged = defineRoles(permissions, r1, r2, r3);

      expect(merged.admin.documents).toEqual(["read"]);
      expect(merged.viewer.documents).toEqual(["read"]);
      expect(merged.editor.documents).toEqual(["read", "create"]);
    });

    it("should merge roles where existing role gets new resources from later defs", () => {
      const r1 = { admin: { documents: ["read"] as const } };
      const r2 = { admin: { settings: ["view"] as const } };

      const merged = defineRoles(permissions, r1, r2);

      expect(merged.admin.documents).toEqual(["read"]);
      expect(merged.admin.settings).toEqual(["view"]);
    });
  });

  describe("definePolicies", () => {
    it("should return policies as-is", () => {
      const policies = definePolicies({
        isAdmin: {
          condition: (ctx) => ctx.subject.roles.includes("admin"),
          message: "Must be admin",
        },
      });

      expect(policies.isAdmin.message).toBe("Must be admin");
    });
  });

  describe("flattenRolePermissions", () => {
    it("should flatten role permissions to strings", () => {
      const roles = {
        admin: {
          documents: ["create", "read", "update", "delete"],
          settings: ["view", "manage"],
        },
        viewer: {
          documents: ["read"],
        },
      };

      const adminPerms = flattenRolePermissions(roles, "admin");
      expect(adminPerms).toContain("documents:create");
      expect(adminPerms).toContain("documents:read");
      expect(adminPerms).toContain("settings:manage");
      expect(adminPerms).toHaveLength(6);

      const viewerPerms = flattenRolePermissions(roles, "viewer");
      expect(viewerPerms).toEqual(["documents:read"]);
    });

    it("should return empty array for unknown role", () => {
      const roles = {
        admin: { documents: ["read"] },
      };

      const perms = flattenRolePermissions(roles, "unknown");
      expect(perms).toEqual([]);
    });

    it("should skip non-array actions", () => {
      // Edge case: if a role has non-array property
      const roles = {
        admin: { documents: "read" }, // string instead of array
      } as unknown as Record<string, Record<string, string[]>>;

      const perms = flattenRolePermissions(roles, "admin");
      // Non-array value should be skipped
      expect(perms).toEqual([]);
    });
  });
});

// ============================================================================
// Authz class tests
// ============================================================================

describe("Authz class", () => {
  // Create a mock component
  function createMockComponent() {
    return {
      queries: {
        checkPermission: "queries.checkPermission",
        checkPermissions: "queries.checkPermissions",
        hasRole: "queries.hasRole",
        getUserRoles: "queries.getUserRoles",
        getEffectivePermissions: "queries.getEffectivePermissions",
        getUserAttributes: "queries.getUserAttributes",
        getAuditLog: "queries.getAuditLog",
      },
      mutations: {
        assignRole: "mutations.assignRole",
        assignRoles: "mutations.assignRoles",
        revokeRole: "mutations.revokeRole",
        revokeRoles: "mutations.revokeRoles",
        revokeAllRoles: "mutations.revokeAllRoles",
        offboardUser: "mutations.offboardUser",
        setAttribute: "mutations.setAttribute",
        removeAttribute: "mutations.removeAttribute",
        grantPermission: "mutations.grantPermission",
        denyPermission: "mutations.denyPermission",
      },
    } as unknown as ComponentApi;
  }

  const permissions = definePermissions({
    documents: { create: true, read: true, update: true, delete: true },
  });

  const roles = defineRoles(permissions, {
    admin: { documents: ["create", "read", "update", "delete"] },
    viewer: { documents: ["read"] },
  });

  describe("can", () => {
    it("should call runQuery with checkPermission and return result", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue({ allowed: true, reason: "Granted" }),
      };

      const result = await authz.can(ctx, "user_123", "documents:read");
      expect(result).toBe(true);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.checkPermission,
        expect.objectContaining({
          userId: "user_123",
          permission: "documents:read",
          scope: undefined,
          rolePermissions: {
            admin: [
              "documents:create",
              "documents:read",
              "documents:update",
              "documents:delete",
            ],
            viewer: ["documents:read"],
          },
        })
      );
    });

    it("should pass scope when provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue({ allowed: false, reason: "Denied" }),
      };

      const result = await authz.can(ctx, "user_123", "documents:read", {
        type: "team",
        id: "team_456",
      });
      expect(result).toBe(false);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.checkPermission,
        expect.objectContaining({
          scope: { type: "team", id: "team_456" },
        })
      );
    });
  });

  describe("require", () => {
    it("should not throw when permission is allowed", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue({ allowed: true, reason: "Granted" }),
      };

      await expect(
        authz.require(ctx, "user_123", "documents:read")
      ).resolves.not.toThrow();
    });

    it("should throw when permission is denied", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue({
          allowed: false,
          reason: "No matching role",
        }),
      };

      await expect(
        authz.require(ctx, "user_123", "documents:delete")
      ).rejects.toThrow("Permission denied: documents:delete - No matching role");
    });

    it("should include scope in error message when provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue({
          allowed: false,
          reason: "Denied",
        }),
      };

      await expect(
        authz.require(ctx, "user_123", "documents:delete", {
          type: "team",
          id: "team_456",
        })
      ).rejects.toThrow(
        "Permission denied: documents:delete on team:team_456 - Denied"
      );
    });
  });

  describe("hasRole", () => {
    it("should check role via runQuery", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(true),
      };

      const result = await authz.hasRole(ctx, "user_123", "admin");
      expect(result).toBe(true);
      expect(ctx.runQuery).toHaveBeenCalledWith(component.queries.hasRole, {
        userId: "user_123",
        role: "admin",
        scope: undefined,
      });
    });

    it("should pass scope when provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(false),
      };

      await authz.hasRole(ctx, "user_123", "admin", {
        type: "org",
        id: "org_1",
      });
      expect(ctx.runQuery).toHaveBeenCalledWith(component.queries.hasRole, {
        userId: "user_123",
        role: "admin",
        scope: { type: "org", id: "org_1" },
      });
    });
  });

  describe("getUserRoles", () => {
    it("should get user roles via runQuery", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const mockRoles = [{ role: "admin", scope: undefined }];
      const ctx = {
        runQuery: vi.fn().mockResolvedValue(mockRoles),
      };

      const result = await authz.getUserRoles(ctx, "user_123");
      expect(result).toEqual(mockRoles);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.getUserRoles,
        { userId: "user_123", scope: undefined }
      );
    });

    it("should pass scope when provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
      };

      await authz.getUserRoles(ctx, "user_123", {
        type: "team",
        id: "team_1",
      });
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.getUserRoles,
        { userId: "user_123", scope: { type: "team", id: "team_1" } }
      );
    });
  });

  describe("getUserPermissions", () => {
    it("should get user permissions via runQuery", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const mockPerms = {
        permissions: ["documents:read"],
        roles: ["viewer"],
        deniedPermissions: [],
      };
      const ctx = {
        runQuery: vi.fn().mockResolvedValue(mockPerms),
      };

      const result = await authz.getUserPermissions(ctx, "user_123");
      expect(result).toEqual(mockPerms);
    });

    it("should pass scope when provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue({
          permissions: [],
          roles: [],
          deniedPermissions: [],
        }),
      };

      await authz.getUserPermissions(ctx, "user_123", {
        type: "org",
        id: "org_1",
      });
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.getEffectivePermissions,
        expect.objectContaining({
          scope: { type: "org", id: "org_1" },
        })
      );
    });
  });

  describe("getUserAttributes", () => {
    it("should get user attributes via runQuery", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const mockAttrs = [{ key: "dept", value: "eng" }];
      const ctx = {
        runQuery: vi.fn().mockResolvedValue(mockAttrs),
      };

      const result = await authz.getUserAttributes(ctx, "user_123");
      expect(result).toEqual(mockAttrs);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.getUserAttributes,
        { userId: "user_123" }
      );
    });
  });

  describe("canAny", () => {
    it("should call runQuery with checkPermissions and return result.allowed", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue({
          allowed: true,
          matchedPermission: "documents:read",
        }),
      };

      const result = await authz.canAny(ctx, "user_123", [
        "documents:delete",
        "documents:read",
      ]);
      expect(result).toBe(true);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.checkPermissions,
        expect.objectContaining({
          userId: "user_123",
          permissions: ["documents:delete", "documents:read"],
          scope: undefined,
        })
      );
    });

    it("should reject empty permissions array", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });
      const ctx = { runQuery: vi.fn() };

      await expect(
        authz.canAny(ctx, "user_123", [])
      ).rejects.toThrow("permissions must not be empty");
    });
  });

  describe("assignRole", () => {
    it("should assign role via runMutation", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("assignment_id"),
      };

      const result = await authz.assignRole(ctx, "user_123", "admin");
      expect(result).toBe("assignment_id");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.assignRole,
        expect.objectContaining({
          userId: "user_123",
          role: "admin",
          enableAudit: true,
        })
      );
    });

    it("should use provided actorId", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("assignment_id"),
      };

      await authz.assignRole(
        ctx,
        "user_123",
        "admin",
        undefined,
        undefined,
        "actor_1"
      );
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.assignRole,
        expect.objectContaining({
          assignedBy: "actor_1",
        })
      );
    });

    it("should use defaultActorId when no actorId provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, {
        permissions,
        roles,
        defaultActorId: "default_actor",
      });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("assignment_id"),
      };

      await authz.assignRole(ctx, "user_123", "admin");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.assignRole,
        expect.objectContaining({
          assignedBy: "default_actor",
        })
      );
    });

    it("should pass scope and expiresAt", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("assignment_id"),
      };

      const scope = { type: "team", id: "team_1" };
      const expiresAt = Date.now() + 3600000;

      await authz.assignRole(ctx, "user_123", "admin", scope, expiresAt);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.assignRole,
        expect.objectContaining({
          scope,
          expiresAt,
        })
      );
    });
  });

  describe("revokeRole", () => {
    it("should revoke role via runMutation", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue(true),
      };

      const result = await authz.revokeRole(ctx, "user_123", "admin");
      expect(result).toBe(true);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.revokeRole,
        expect.objectContaining({
          userId: "user_123",
          role: "admin",
          enableAudit: true,
        })
      );
    });

    it("should use provided actorId", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue(true),
      };

      await authz.revokeRole(ctx, "user_123", "admin", undefined, "actor_1");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.revokeRole,
        expect.objectContaining({
          revokedBy: "actor_1",
        })
      );
    });

    it("should use defaultActorId when no actorId provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, {
        permissions,
        roles,
        defaultActorId: "default_actor",
      });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue(true),
      };

      await authz.revokeRole(ctx, "user_123", "admin");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.revokeRole,
        expect.objectContaining({
          revokedBy: "default_actor",
        })
      );
    });
  });

  describe("assignRoles", () => {
    it("should call runMutation with assignRoles", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue({
          assigned: 2,
          assignmentIds: ["id1", "id2"],
        }),
      };

      const result = await authz.assignRoles(ctx, "user_123", [
        { role: "admin" },
        { role: "viewer", scope: { type: "team", id: "t1" } },
      ]);
      expect(result.assigned).toBe(2);
      expect(result.assignmentIds).toEqual(["id1", "id2"]);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.assignRoles,
        expect.objectContaining({
          userId: "user_123",
          roles: [
            { role: "admin", scope: undefined, expiresAt: undefined, metadata: undefined },
            { role: "viewer", scope: { type: "team", id: "t1" }, expiresAt: undefined, metadata: undefined },
          ],
        })
      );
    });
  });

  describe("revokeRoles", () => {
    it("should call runMutation with revokeRoles", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue({ revoked: 2 }),
      };

      const result = await authz.revokeRoles(ctx, "user_123", [
        { role: "admin" },
        { role: "viewer" },
      ]);
      expect(result.revoked).toBe(2);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.revokeRoles,
        expect.objectContaining({
          userId: "user_123",
          roles: [{ role: "admin", scope: undefined }, { role: "viewer", scope: undefined }],
        })
      );
    });
  });

  describe("revokeAllRoles", () => {
    it("should call runMutation with revokeAllRoles", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue(3),
      };

      const result = await authz.revokeAllRoles(ctx, "user_123");
      expect(result).toBe(3);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.revokeAllRoles,
        expect.objectContaining({
          userId: "user_123",
          scope: undefined,
        })
      );
    });
  });

  describe("offboardUser", () => {
    it("should call runMutation with offboardUser", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue({
          rolesRevoked: 1,
          overridesRemoved: 0,
          attributesRemoved: 2,
          effectiveRolesRemoved: 1,
          effectivePermissionsRemoved: 3,
        }),
      };

      const result = await authz.offboardUser(ctx, "user_123", {
        scope: { type: "team", id: "t1" },
        actorId: "actor_1",
      });
      expect(result.rolesRevoked).toBe(1);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.offboardUser,
        expect.objectContaining({
          userId: "user_123",
          scope: { type: "team", id: "t1" },
          revokedBy: "actor_1",
          enableAudit: true,
        })
      );
    });
  });

  describe("setAttribute", () => {
    it("should set attribute via runMutation", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("attr_id"),
      };

      const result = await authz.setAttribute(
        ctx,
        "user_123",
        "department",
        "engineering"
      );
      expect(result).toBe("attr_id");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.setAttribute,
        expect.objectContaining({
          userId: "user_123",
          key: "department",
          value: "engineering",
          enableAudit: true,
        })
      );
    });

    it("should use provided actorId", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("attr_id"),
      };

      await authz.setAttribute(ctx, "user_123", "key", "val", "actor_1");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.setAttribute,
        expect.objectContaining({ setBy: "actor_1" })
      );
    });

    it("should use defaultActorId when no actorId", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, {
        permissions,
        roles,
        defaultActorId: "default_actor",
      });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("attr_id"),
      };

      await authz.setAttribute(ctx, "user_123", "key", "val");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.setAttribute,
        expect.objectContaining({ setBy: "default_actor" })
      );
    });
  });

  describe("removeAttribute", () => {
    it("should remove attribute via runMutation", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue(true),
      };

      const result = await authz.removeAttribute(ctx, "user_123", "department");
      expect(result).toBe(true);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.removeAttribute,
        expect.objectContaining({
          userId: "user_123",
          key: "department",
          enableAudit: true,
        })
      );
    });

    it("should use provided actorId", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue(true),
      };

      await authz.removeAttribute(ctx, "user_123", "key", "actor_1");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.removeAttribute,
        expect.objectContaining({ removedBy: "actor_1" })
      );
    });
  });

  describe("grantPermission", () => {
    it("should grant permission via runMutation", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("override_id"),
      };

      const result = await authz.grantPermission(
        ctx,
        "user_123",
        "documents:delete"
      );
      expect(result).toBe("override_id");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.grantPermission,
        expect.objectContaining({
          userId: "user_123",
          permission: "documents:delete",
          enableAudit: true,
        })
      );
    });

    it("should pass all optional parameters", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("override_id"),
      };

      const scope = { type: "doc", id: "doc_1" };
      const expiresAt = Date.now() + 3600000;

      await authz.grantPermission(
        ctx,
        "user_123",
        "documents:delete",
        scope,
        "Temporary",
        expiresAt,
        "actor_1"
      );
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.grantPermission,
        expect.objectContaining({
          scope,
          reason: "Temporary",
          expiresAt,
          createdBy: "actor_1",
        })
      );
    });

    it("should use defaultActorId", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, {
        permissions,
        roles,
        defaultActorId: "default_actor",
      });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("override_id"),
      };

      await authz.grantPermission(ctx, "user_123", "documents:delete");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.grantPermission,
        expect.objectContaining({ createdBy: "default_actor" })
      );
    });
  });

  describe("denyPermission", () => {
    it("should deny permission via runMutation", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("override_id"),
      };

      const result = await authz.denyPermission(
        ctx,
        "user_123",
        "documents:delete"
      );
      expect(result).toBe("override_id");
    });

    it("should pass all optional parameters", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("override_id"),
      };

      const scope = { type: "doc", id: "doc_1" };
      const expiresAt = Date.now() + 3600000;

      await authz.denyPermission(
        ctx,
        "user_123",
        "documents:delete",
        scope,
        "Security",
        expiresAt,
        "actor_1"
      );
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.denyPermission,
        expect.objectContaining({
          scope,
          reason: "Security",
          expiresAt,
          createdBy: "actor_1",
        })
      );
    });

    it("should use defaultActorId", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, {
        permissions,
        roles,
        defaultActorId: "default_actor",
      });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("override_id"),
      };

      await authz.denyPermission(ctx, "user_123", "documents:delete");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.denyPermission,
        expect.objectContaining({ createdBy: "default_actor" })
      );
    });
  });

  describe("getAuditLog", () => {
    it("should get audit log with no options", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
      };

      const result = await authz.getAuditLog(ctx);
      expect(result).toEqual([]);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.getAuditLog,
        expect.objectContaining({
          userId: undefined,
          action: undefined,
          limit: undefined,
        })
      );
    });

    it("should request pagination when numItems provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const paginatedResponse = {
        page: [{ _id: "1", timestamp: 1, action: "role_assigned", userId: "u", details: {} }],
        isDone: true,
        continueCursor: "cursor1",
      };

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(paginatedResponse),
      };

      const result = await authz.getAuditLog(ctx, { numItems: 50 });
      expect(result).toEqual(paginatedResponse);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.getAuditLog,
        expect.objectContaining({
          paginationOpts: { numItems: 50, cursor: null },
        })
      );
    });

    it("should request next page when cursor provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue({
          page: [],
          isDone: true,
          continueCursor: "next",
        }),
      };

      await authz.getAuditLog(ctx, { cursor: "prevCursor", numItems: 100 });
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.getAuditLog,
        expect.objectContaining({
          paginationOpts: { numItems: 100, cursor: "prevCursor" },
        })
      );
    });

    it("should pass userId filter", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
      };

      await authz.getAuditLog(ctx, { userId: "user_123" });
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.getAuditLog,
        expect.objectContaining({ userId: "user_123" })
      );
    });

    it("should pass action filter", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
      };

      await authz.getAuditLog(ctx, { action: "role_assigned" });
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.getAuditLog,
        expect.objectContaining({ action: "role_assigned" })
      );
    });

    it("should pass limit option", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
      };

      await authz.getAuditLog(ctx, { limit: 50 });
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.queries.getAuditLog,
        expect.objectContaining({ limit: 50 })
      );
    });
  });
});

// ============================================================================
// Input validation tests
// ============================================================================

describe("input validation", () => {
  function createMockComponent() {
    return {
      queries: {
        checkPermission: "queries.checkPermission",
        checkPermissions: "queries.checkPermissions",
        hasRole: "queries.hasRole",
        getUserRoles: "queries.getUserRoles",
        getEffectivePermissions: "queries.getEffectivePermissions",
        getUserAttributes: "queries.getUserAttributes",
        getAuditLog: "queries.getAuditLog",
      },
      mutations: {
        assignRole: "mutations.assignRole",
        assignRoles: "mutations.assignRoles",
        revokeRole: "mutations.revokeRole",
        revokeRoles: "mutations.revokeRoles",
        revokeAllRoles: "mutations.revokeAllRoles",
        offboardUser: "mutations.offboardUser",
        setAttribute: "mutations.setAttribute",
        removeAttribute: "mutations.removeAttribute",
        grantPermission: "mutations.grantPermission",
        denyPermission: "mutations.denyPermission",
      },
    } as unknown as ComponentApi;
  }

  function createMockIndexedComponent() {
    return {
      indexed: {
        checkPermissionFast: "indexed.checkPermissionFast",
        checkPermissionsFast: "indexed.checkPermissionsFast",
        hasRoleFast: "indexed.hasRoleFast",
        hasRelationFast: "indexed.hasRelationFast",
        getUserPermissionsFast: "indexed.getUserPermissionsFast",
        getUserRolesFast: "indexed.getUserRolesFast",
        assignRoleWithCompute: "indexed.assignRoleWithCompute",
        assignRolesWithCompute: "indexed.assignRolesWithCompute",
        revokeRoleWithCompute: "indexed.revokeRoleWithCompute",
        revokeRolesWithCompute: "indexed.revokeRolesWithCompute",
        grantPermissionDirect: "indexed.grantPermissionDirect",
        denyPermissionDirect: "indexed.denyPermissionDirect",
        addRelationWithCompute: "indexed.addRelationWithCompute",
        removeRelationWithCompute: "indexed.removeRelationWithCompute",
      },
      mutations: {
        offboardUser: "mutations.offboardUser",
      },
    } as unknown as ComponentApi;
  }

  const permissions = definePermissions({
    documents: { create: true, read: true, update: true, delete: true },
  });

  const roles = defineRoles(permissions, {
    admin: { documents: ["create", "read", "update", "delete"] },
    viewer: { documents: ["read"] },
  });

  describe("Authz", () => {
    it("throws for empty userId", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });
      const ctx = {
        runQuery: vi.fn().mockResolvedValue({ allowed: true, reason: "ok" }),
      };

      await expect(authz.can(ctx, "", "documents:read")).rejects.toThrow(
        "userId must be a non-empty string"
      );
      await expect(authz.can(ctx, "   ", "documents:read")).rejects.toThrow(
        "userId must be a non-empty string"
      );
    });

    it("throws for invalid permission format", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });
      const ctx = {
        runQuery: vi.fn().mockResolvedValue({ allowed: false, reason: "ok" }),
      };

      await expect(authz.can(ctx, "user_1", "read")).rejects.toThrow(
        'Invalid permission format: "read". Expected "resource:action"'
      );
      await expect(authz.can(ctx, "user_1", "a:b:c")).rejects.toThrow(
        'Invalid permission format: "a:b:c". Expected "resource:action"'
      );
      await expect(authz.can(ctx, "user_1", "")).rejects.toThrow(
        'Invalid permission format: "". Expected "resource:action"'
      );
    });

    it("throws for invalid scope when provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });
      const ctx = {
        runQuery: vi.fn().mockResolvedValue({ allowed: true, reason: "ok" }),
      };

      await expect(
        authz.can(ctx, "user_1", "documents:read", { type: "", id: "x" })
      ).rejects.toThrow("scope must have non-empty type when provided");

      await expect(
        authz.can(ctx, "user_1", "documents:read", { type: "t", id: "" })
      ).rejects.toThrow("scope must have non-empty id when provided");
    });

    it("throws for unknown role in assignRole and hasRole", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });
      const ctx = {
        runQuery: vi.fn().mockResolvedValue(false),
        runMutation: vi.fn().mockResolvedValue("id"),
      };

      await expect(
        authz.hasRole(ctx, "user_1", "superadmin" as "admin" & string)
      ).rejects.toThrow('Unknown role: "superadmin"');

      await expect(
        authz.assignRole(ctx, "user_1", "superadmin" as "admin" & string)
      ).rejects.toThrow('Unknown role: "superadmin"');
    });

    it("throws for invalid expiresAt when provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });
      const ctx = {
        runMutation: vi.fn().mockResolvedValue("id"),
      };

      await expect(
        authz.assignRole(ctx, "user_1", "admin", undefined, NaN)
      ).rejects.toThrow("expiresAt must be a finite number");

      await expect(
        authz.grantPermission(
          ctx,
          "user_1",
          "documents:read",
          undefined,
          undefined,
          Number.POSITIVE_INFINITY
        )
      ).rejects.toThrow("expiresAt must be a finite number");
    });

    it("throws for empty attribute key in setAttribute and removeAttribute", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });
      const ctx = {
        runMutation: vi.fn().mockResolvedValue("id"),
      };

      await expect(
        authz.setAttribute(ctx, "user_1", "", "value")
      ).rejects.toThrow("Attribute key must be a non-empty string");

      await expect(authz.removeAttribute(ctx, "user_1", "   ")).rejects.toThrow(
        "Attribute key must be a non-empty string"
      );
    });

    it("throws for invalid getAuditLog limit when provided", async () => {
      const component = createMockComponent();
      const authz = new Authz(component, { permissions, roles });
      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
      };

      await expect(
        authz.getAuditLog(ctx, { limit: -1 })
      ).rejects.toThrow("limit must be a positive integer when provided");

      await expect(
        authz.getAuditLog(ctx, { limit: 1.5 })
      ).rejects.toThrow("limit must be a positive integer when provided");
    });
  });

  describe("IndexedAuthz", () => {
    it("throws for empty userId and invalid permission", async () => {
      const component = createMockIndexedComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });
      const ctx = {
        runQuery: vi.fn().mockResolvedValue(true),
      };

      await expect(authz.can(ctx, "", "documents:read")).rejects.toThrow(
        "userId must be a non-empty string"
      );
      await expect(authz.can(ctx, "user_1", "read")).rejects.toThrow(
        'Invalid permission format: "read". Expected "resource:action"'
      );
    });

    it("throws for unknown role and invalid scope", async () => {
      const component = createMockIndexedComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });
      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
        runMutation: vi.fn().mockResolvedValue("id"),
      };

      await expect(
        authz.assignRole(ctx, "user_1", "superadmin" as "admin" & string)
      ).rejects.toThrow('Unknown role: "superadmin"');

      await expect(
        authz.getUserRoles(ctx, "user_1", { type: "", id: "x" })
      ).rejects.toThrow("scope must have non-empty type when provided");
    });

    it("throws for invalid relation args in hasRelation and addRelation", async () => {
      const component = createMockIndexedComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });
      const ctx = {
        runQuery: vi.fn().mockResolvedValue(false),
        runMutation: vi.fn().mockResolvedValue("id"),
      };

      await expect(
        authz.hasRelation(ctx, "", "alice", "member", "team", "sales")
      ).rejects.toThrow("subjectType must be a non-empty string");

      await expect(
        authz.addRelation(ctx, "user", "alice", "", "team", "sales")
      ).rejects.toThrow("relation must be a non-empty string");
    });
  });
});

// ============================================================================
// IndexedAuthz class tests
// ============================================================================

describe("IndexedAuthz class", () => {
  function createMockComponent() {
    return {
      indexed: {
        checkPermissionFast: "indexed.checkPermissionFast",
        checkPermissionsFast: "indexed.checkPermissionsFast",
        hasRoleFast: "indexed.hasRoleFast",
        hasRelationFast: "indexed.hasRelationFast",
        getUserPermissionsFast: "indexed.getUserPermissionsFast",
        getUserRolesFast: "indexed.getUserRolesFast",
        assignRoleWithCompute: "indexed.assignRoleWithCompute",
        assignRolesWithCompute: "indexed.assignRolesWithCompute",
        revokeRoleWithCompute: "indexed.revokeRoleWithCompute",
        revokeRolesWithCompute: "indexed.revokeRolesWithCompute",
        grantPermissionDirect: "indexed.grantPermissionDirect",
        denyPermissionDirect: "indexed.denyPermissionDirect",
        addRelationWithCompute: "indexed.addRelationWithCompute",
        removeRelationWithCompute: "indexed.removeRelationWithCompute",
      },
      mutations: {
        offboardUser: "mutations.offboardUser",
      },
    } as unknown as ComponentApi;
  }

  const permissions = definePermissions({
    documents: { create: true, read: true, update: true, delete: true },
  });

  const roles = defineRoles(permissions, {
    admin: { documents: ["create", "read", "update", "delete"] },
    viewer: { documents: ["read"] },
  });

  describe("can", () => {
    it("should check permission via indexed lookup", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(true),
      };

      const result = await authz.can(ctx, "user_123", "documents:read");
      expect(result).toBe(true);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.indexed.checkPermissionFast,
        {
          userId: "user_123",
          permission: "documents:read",
          objectType: undefined,
          objectId: undefined,
        }
      );
    });

    it("should pass scope as objectType/objectId", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(false),
      };

      await authz.can(ctx, "user_123", "documents:read", {
        type: "team",
        id: "team_1",
      });
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.indexed.checkPermissionFast,
        {
          userId: "user_123",
          permission: "documents:read",
          objectType: "team",
          objectId: "team_1",
        }
      );
    });
  });

  describe("require", () => {
    it("should not throw when permission is allowed", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(true),
      };

      await expect(
        authz.require(ctx, "user_123", "documents:read")
      ).resolves.not.toThrow();
    });

    it("should throw when permission is denied", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(false),
      };

      await expect(
        authz.require(ctx, "user_123", "documents:delete")
      ).rejects.toThrow("Permission denied: documents:delete");
    });

    it("should include scope in error message", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(false),
      };

      await expect(
        authz.require(ctx, "user_123", "documents:delete", {
          type: "doc",
          id: "doc_1",
        })
      ).rejects.toThrow("Permission denied: documents:delete on doc:doc_1");
    });
  });

  describe("hasRole", () => {
    it("should check role via indexed lookup", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(true),
      };

      const result = await authz.hasRole(ctx, "user_123", "admin");
      expect(result).toBe(true);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.indexed.hasRoleFast,
        {
          userId: "user_123",
          role: "admin",
          objectType: undefined,
          objectId: undefined,
        }
      );
    });

    it("should pass scope", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(false),
      };

      await authz.hasRole(ctx, "user_123", "admin", {
        type: "org",
        id: "org_1",
      });
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.indexed.hasRoleFast,
        expect.objectContaining({
          objectType: "org",
          objectId: "org_1",
        })
      );
    });
  });

  describe("hasRelation", () => {
    it("should check relation via indexed lookup", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(true),
      };

      const result = await authz.hasRelation(
        ctx,
        "user",
        "alice",
        "member",
        "team",
        "sales"
      );
      expect(result).toBe(true);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.indexed.hasRelationFast,
        {
          subjectType: "user",
          subjectId: "alice",
          relation: "member",
          objectType: "team",
          objectId: "sales",
        }
      );
    });
  });

  describe("getUserPermissions", () => {
    it("should get permissions without scope", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
      };

      await authz.getUserPermissions(ctx, "user_123");
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.indexed.getUserPermissionsFast,
        { userId: "user_123", scopeKey: undefined }
      );
    });

    it("should get permissions with scope", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
      };

      await authz.getUserPermissions(ctx, "user_123", {
        type: "team",
        id: "team_1",
      });
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.indexed.getUserPermissionsFast,
        { userId: "user_123", scopeKey: "team:team_1" }
      );
    });
  });

  describe("getUserRoles", () => {
    it("should get roles without scope", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
      };

      await authz.getUserRoles(ctx, "user_123");
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.indexed.getUserRolesFast,
        { userId: "user_123", scopeKey: undefined }
      );
    });

    it("should get roles with scope", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue([]),
      };

      await authz.getUserRoles(ctx, "user_123", {
        type: "org",
        id: "org_1",
      });
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.indexed.getUserRolesFast,
        { userId: "user_123", scopeKey: "org:org_1" }
      );
    });
  });

  describe("assignRole", () => {
    it("should assign role with computed permissions", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("role_id"),
      };

      const result = await authz.assignRole(ctx, "user_123", "admin");
      expect(result).toBe("role_id");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.assignRoleWithCompute,
        expect.objectContaining({
          userId: "user_123",
          role: "admin",
          rolePermissions: [
            "documents:create",
            "documents:read",
            "documents:update",
            "documents:delete",
          ],
        })
      );
    });

    it("should pass scope and expiresAt", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("role_id"),
      };

      const scope = { type: "team", id: "team_1" };
      const expiresAt = Date.now() + 3600000;

      await authz.assignRole(ctx, "user_123", "admin", scope, expiresAt);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.assignRoleWithCompute,
        expect.objectContaining({ scope, expiresAt })
      );
    });

    it("should use assignedBy when provided", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("role_id"),
      };

      await authz.assignRole(
        ctx,
        "user_123",
        "admin",
        undefined,
        undefined,
        "actor_1"
      );
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.assignRoleWithCompute,
        expect.objectContaining({ assignedBy: "actor_1" })
      );
    });

    it("should use defaultActorId", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, {
        permissions,
        roles,
        defaultActorId: "default_actor",
      });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("role_id"),
      };

      await authz.assignRole(ctx, "user_123", "admin");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.assignRoleWithCompute,
        expect.objectContaining({ assignedBy: "default_actor" })
      );
    });
  });

  describe("revokeRole", () => {
    it("should revoke role with computed permissions", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue(true),
      };

      const result = await authz.revokeRole(ctx, "user_123", "admin");
      expect(result).toBe(true);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.revokeRoleWithCompute,
        expect.objectContaining({
          userId: "user_123",
          role: "admin",
          rolePermissions: [
            "documents:create",
            "documents:read",
            "documents:update",
            "documents:delete",
          ],
        })
      );
    });

    it("should pass scope", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue(true),
      };

      await authz.revokeRole(ctx, "user_123", "admin", {
        type: "team",
        id: "team_1",
      });
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.revokeRoleWithCompute,
        expect.objectContaining({
          scope: { type: "team", id: "team_1" },
        })
      );
    });
  });

  describe("canAny", () => {
    it("should call runQuery with checkPermissionsFast", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runQuery: vi.fn().mockResolvedValue(true),
      };

      const result = await authz.canAny(ctx, "user_123", [
        "documents:read",
        "documents:delete",
      ]);
      expect(result).toBe(true);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        component.indexed.checkPermissionsFast,
        expect.objectContaining({
          userId: "user_123",
          permissions: ["documents:read", "documents:delete"],
        })
      );
    });
  });

  describe("assignRoles", () => {
    it("should call runMutation with assignRolesWithCompute", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue({
          assigned: 2,
          assignmentIds: ["id1", "id2"],
        }),
      };

      const result = await authz.assignRoles(ctx, "user_123", [
        { role: "admin" },
        { role: "viewer" },
      ]);
      expect(result.assigned).toBe(2);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.assignRolesWithCompute,
        expect.objectContaining({
          userId: "user_123",
          roles: expect.any(Array),
          rolePermissionsMap: expect.any(Object),
        })
      );
    });
  });

  describe("revokeRoles", () => {
    it("should call runMutation with revokeRolesWithCompute", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue({ revoked: 2 }),
      };

      const result = await authz.revokeRoles(ctx, "user_123", [
        { role: "admin" },
        { role: "viewer" },
      ]);
      expect(result.revoked).toBe(2);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.revokeRolesWithCompute,
        expect.objectContaining({
          userId: "user_123",
          roles: expect.any(Array),
          rolePermissionsMap: expect.any(Object),
        })
      );
    });
  });

  describe("revokeAllRoles", () => {
    it("should call offboardUser with removeAttributes and removeOverrides false", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue({
          rolesRevoked: 0,
          effectiveRolesRemoved: 2,
          overridesRemoved: 0,
          attributesRemoved: 0,
          effectivePermissionsRemoved: 5,
        }),
      };

      const result = await authz.revokeAllRoles(ctx, "user_123");
      expect(result).toBe(2);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.offboardUser,
        expect.objectContaining({
          userId: "user_123",
          removeAttributes: false,
          removeOverrides: false,
        })
      );
    });
  });

  describe("offboardUser", () => {
    it("should call runMutation with offboardUser", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue({
          rolesRevoked: 1,
          overridesRemoved: 0,
          attributesRemoved: 0,
          effectiveRolesRemoved: 1,
          effectivePermissionsRemoved: 3,
        }),
      };

      const result = await authz.offboardUser(ctx, "user_123");
      expect(result.rolesRevoked).toBe(1);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.mutations.offboardUser,
        expect.objectContaining({
          userId: "user_123",
          enableAudit: true,
        })
      );
    });
  });

  describe("grantPermission", () => {
    it("should grant permission", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("perm_id"),
      };

      const result = await authz.grantPermission(
        ctx,
        "user_123",
        "documents:read"
      );
      expect(result).toBe("perm_id");
    });

    it("should pass all optional parameters", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("perm_id"),
      };

      const scope = { type: "doc", id: "doc_1" };
      const expiresAt = Date.now() + 3600000;

      await authz.grantPermission(
        ctx,
        "user_123",
        "documents:read",
        scope,
        "Reason",
        expiresAt,
        "actor_1"
      );
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.grantPermissionDirect,
        expect.objectContaining({
          scope,
          reason: "Reason",
          expiresAt,
          grantedBy: "actor_1",
        })
      );
    });

    it("should use defaultActorId", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, {
        permissions,
        roles,
        defaultActorId: "default_actor",
      });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("perm_id"),
      };

      await authz.grantPermission(ctx, "user_123", "documents:read");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.grantPermissionDirect,
        expect.objectContaining({ grantedBy: "default_actor" })
      );
    });
  });

  describe("denyPermission", () => {
    it("should deny permission", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("perm_id"),
      };

      const result = await authz.denyPermission(
        ctx,
        "user_123",
        "documents:delete"
      );
      expect(result).toBe("perm_id");
    });

    it("should pass all optional parameters", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("perm_id"),
      };

      const scope = { type: "doc", id: "doc_1" };
      const expiresAt = Date.now() + 3600000;

      await authz.denyPermission(
        ctx,
        "user_123",
        "documents:delete",
        scope,
        "Security",
        expiresAt,
        "actor_1"
      );
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.denyPermissionDirect,
        expect.objectContaining({
          scope,
          reason: "Security",
          expiresAt,
          deniedBy: "actor_1",
        })
      );
    });

    it("should use defaultActorId", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, {
        permissions,
        roles,
        defaultActorId: "default_actor",
      });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("perm_id"),
      };

      await authz.denyPermission(ctx, "user_123", "documents:delete");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.denyPermissionDirect,
        expect.objectContaining({ deniedBy: "default_actor" })
      );
    });
  });

  describe("addRelation", () => {
    it("should add relation", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("rel_id"),
      };

      const result = await authz.addRelation(
        ctx,
        "user",
        "alice",
        "member",
        "team",
        "sales"
      );
      expect(result).toBe("rel_id");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.addRelationWithCompute,
        {
          subjectType: "user",
          subjectId: "alice",
          relation: "member",
          objectType: "team",
          objectId: "sales",
          inheritedRelations: undefined,
          createdBy: undefined,
        }
      );
    });

    it("should pass inherited relations and createdBy", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, {
        permissions,
        roles,
        defaultActorId: "default",
      });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("rel_id"),
      };

      const inherited = [
        {
          relation: "viewer",
          fromObjectType: "org",
          fromRelation: "parent",
        },
      ];

      await authz.addRelation(
        ctx,
        "user",
        "alice",
        "member",
        "team",
        "sales",
        inherited,
        "actor_1"
      );
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.addRelationWithCompute,
        expect.objectContaining({
          inheritedRelations: inherited,
          createdBy: "actor_1",
        })
      );
    });

    it("should use defaultActorId when no createdBy", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, {
        permissions,
        roles,
        defaultActorId: "default_actor",
      });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue("rel_id"),
      };

      await authz.addRelation(ctx, "user", "alice", "member", "team", "sales");
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.addRelationWithCompute,
        expect.objectContaining({ createdBy: "default_actor" })
      );
    });
  });

  describe("removeRelation", () => {
    it("should remove relation", async () => {
      const component = createMockComponent();
      const authz = new IndexedAuthz(component, { permissions, roles });

      const ctx = {
        runMutation: vi.fn().mockResolvedValue(true),
      };

      const result = await authz.removeRelation(
        ctx,
        "user",
        "alice",
        "member",
        "team",
        "sales"
      );
      expect(result).toBe(true);
      expect(ctx.runMutation).toHaveBeenCalledWith(
        component.indexed.removeRelationWithCompute,
        {
          subjectType: "user",
          subjectId: "alice",
          relation: "member",
          objectType: "team",
          objectId: "sales",
        }
      );
    });
  });
});
