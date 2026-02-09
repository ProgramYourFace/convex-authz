import { describe, expect, it } from "vitest";
import {
  isExpired,
  parsePermission,
  buildPermission,
  matchesPermissionPattern,
  matchesScope,
  checkOverrides,
  resolveRolePermissions,
  hasPermissionInSet,
  getRoleLevel,
  compareRoles,
  createPolicyContext,
} from "./helpers.js";

describe("helpers", () => {
  describe("isExpired", () => {
    it("should return false for undefined expiration", () => {
      expect(isExpired(undefined)).toBe(false);
    });

    it("should return false for null expiration", () => {
      expect(isExpired(null)).toBe(false);
    });

    it("should return true for past timestamp", () => {
      const pastTime = Date.now() - 1000;
      expect(isExpired(pastTime)).toBe(true);
    });

    it("should return false for future timestamp", () => {
      const futureTime = Date.now() + 10000;
      expect(isExpired(futureTime)).toBe(false);
    });
  });

  describe("parsePermission", () => {
    it("should parse permission string", () => {
      const result = parsePermission("documents:read");
      expect(result.resource).toBe("documents");
      expect(result.action).toBe("read");
    });

    it("should throw for invalid format", () => {
      expect(() => parsePermission("invalid")).toThrow();
      expect(() => parsePermission("a:b:c")).toThrow();
    });
  });

  describe("buildPermission", () => {
    it("should build permission string", () => {
      expect(buildPermission("documents", "read")).toBe("documents:read");
    });
  });

  describe("matchesPermissionPattern", () => {
    it("should match exact permission", () => {
      expect(matchesPermissionPattern("documents:read", "documents:read")).toBe(true);
    });

    it("should match wildcard all", () => {
      expect(matchesPermissionPattern("documents:read", "*")).toBe(true);
    });

    it("should match resource wildcard", () => {
      expect(matchesPermissionPattern("documents:read", "documents:*")).toBe(true);
      expect(matchesPermissionPattern("settings:read", "documents:*")).toBe(false);
    });

    it("should match action wildcard", () => {
      expect(matchesPermissionPattern("documents:read", "*:read")).toBe(true);
      expect(matchesPermissionPattern("documents:write", "*:read")).toBe(false);
    });

    it("should not match different permission", () => {
      expect(matchesPermissionPattern("documents:read", "documents:write")).toBe(false);
    });
  });

  describe("matchesScope", () => {
    it("should match when no scope (global)", () => {
      expect(matchesScope(undefined, undefined)).toBe(true);
      expect(matchesScope(undefined, { type: "team", id: "123" })).toBe(true);
    });

    it("should not match when scope but no target", () => {
      expect(matchesScope({ type: "team", id: "123" }, undefined)).toBe(false);
    });

    it("should match exact scope", () => {
      expect(
        matchesScope({ type: "team", id: "123" }, { type: "team", id: "123" })
      ).toBe(true);
    });

    it("should not match different scope", () => {
      expect(
        matchesScope({ type: "team", id: "123" }, { type: "team", id: "456" })
      ).toBe(false);
    });
  });

  describe("checkOverrides", () => {
    it("should return null when no overrides match", () => {
      expect(checkOverrides([], "documents:read")).toBeNull();
    });

    it("should return allowed for matching allow", () => {
      const overrides = [
        { permission: "documents:read", effect: "allow" as const },
      ];
      expect(checkOverrides(overrides, "documents:read")).toEqual({ allowed: true });
    });

    it("should return denied for matching deny", () => {
      const overrides = [
        { permission: "documents:read", effect: "deny" as const },
      ];
      expect(checkOverrides(overrides, "documents:read")).toEqual({ allowed: false });
    });

    it("should prefer deny over allow", () => {
      const overrides = [
        { permission: "documents:read", effect: "allow" as const },
        { permission: "documents:read", effect: "deny" as const },
      ];
      expect(checkOverrides(overrides, "documents:read")).toEqual({ allowed: false });
    });
  });

  describe("resolveRolePermissions", () => {
    it("should resolve permissions from roles", () => {
      const roleDefinitions = {
        admin: ["documents:read", "documents:write"],
        viewer: ["documents:read"],
      };

      const perms = resolveRolePermissions(["admin"], roleDefinitions);
      expect(perms.has("documents:read")).toBe(true);
      expect(perms.has("documents:write")).toBe(true);
    });

    it("should combine permissions from multiple roles", () => {
      const roleDefinitions = {
        editor: ["documents:write"],
        viewer: ["documents:read"],
      };

      const perms = resolveRolePermissions(["editor", "viewer"], roleDefinitions);
      expect(perms.size).toBe(2);
    });
  });

  describe("hasPermissionInSet", () => {
    it("should find exact permission", () => {
      const perms = new Set(["documents:read"]);
      expect(hasPermissionInSet(perms, "documents:read")).toBe(true);
    });

    it("should match wildcard", () => {
      const perms = new Set(["documents:*"]);
      expect(hasPermissionInSet(perms, "documents:read")).toBe(true);
    });

    it("should not find missing permission", () => {
      const perms = new Set(["documents:read"]);
      expect(hasPermissionInSet(perms, "documents:write")).toBe(false);
    });
  });

  describe("getRoleLevel and compareRoles", () => {
    it("should get default role levels", () => {
      expect(getRoleLevel("admin")).toBe(80);
      expect(getRoleLevel("viewer")).toBe(20);
      expect(getRoleLevel("unknown")).toBe(0);
    });

    it("should compare roles", () => {
      expect(compareRoles("admin", "viewer")).toBeGreaterThan(0);
      expect(compareRoles("viewer", "admin")).toBeLessThan(0);
      expect(compareRoles("admin", "admin")).toBe(0);
    });

    it("should use custom hierarchy", () => {
      const custom = { boss: 100, employee: 10 };
      expect(getRoleLevel("boss", custom)).toBe(100);
      expect(compareRoles("boss", "employee", custom)).toBeGreaterThan(0);
    });
  });

  describe("createPolicyContext", () => {
    it("should create policy context", () => {
      const ctx = createPolicyContext(
        "user_123",
        ["admin", "editor"],
        { department: "engineering", level: 5 },
        "documents:read"
      );

      expect(ctx.subject.userId).toBe("user_123");
      expect(ctx.subject.roles).toEqual(["admin", "editor"]);
      expect(ctx.action).toBe("documents:read");
      expect(ctx.hasRole("admin")).toBe(true);
      expect(ctx.hasRole("viewer")).toBe(false);
      expect(ctx.hasAttribute("department")).toBe(true);
      expect(ctx.getAttribute("department")).toBe("engineering");
      expect(ctx.getAttribute("missing", "default")).toBe("default");
    });

    it("should create context with resource and environment", () => {
      const ctx = createPolicyContext(
        "user_123",
        ["admin"],
        { department: "engineering" },
        "documents:read",
        { type: "document", id: "doc_1", attributes: { status: "draft" } },
        { ip: "192.168.1.1" }
      );

      expect(ctx.resource).toEqual({
        type: "document",
        id: "doc_1",
        attributes: { status: "draft" },
      });
      expect(ctx.environment.ip).toBe("192.168.1.1");
      expect(ctx.environment.timestamp).toBeDefined();
    });

    it("should handle missing environment ip", () => {
      const ctx = createPolicyContext(
        "user_123",
        [],
        {},
        "documents:read",
        undefined,
        undefined
      );

      expect(ctx.environment.ip).toBeUndefined();
      expect(ctx.resource).toBeUndefined();
    });

    it("should handle getAttribute without default for missing key", () => {
      const ctx = createPolicyContext(
        "user_123",
        [],
        {},
        "documents:read"
      );

      // getAttribute without default should return undefined
      expect(ctx.getAttribute("nonexistent")).toBeUndefined();
    });

    it("should handle hasAttribute for missing key", () => {
      const ctx = createPolicyContext(
        "user_123",
        [],
        {},
        "documents:read"
      );

      expect(ctx.hasAttribute("nonexistent")).toBe(false);
    });
  });

  describe("checkOverrides with scope", () => {
    it("should match override with matching scope", () => {
      const overrides = [
        {
          permission: "documents:read",
          effect: "allow" as const,
          scope: { type: "team", id: "team_1" },
        },
      ];
      expect(
        checkOverrides(overrides, "documents:read", { type: "team", id: "team_1" })
      ).toEqual({ allowed: true });
    });

    it("should not match override with different scope", () => {
      const overrides = [
        {
          permission: "documents:read",
          effect: "allow" as const,
          scope: { type: "team", id: "team_1" },
        },
      ];
      expect(
        checkOverrides(overrides, "documents:read", { type: "team", id: "team_2" })
      ).toBeNull();
    });
  });

  describe("resolveRolePermissions edge cases", () => {
    it("should handle roles not in definitions", () => {
      const roleDefinitions = {
        admin: ["documents:read"],
      };

      const perms = resolveRolePermissions(["unknown_role"], roleDefinitions);
      expect(perms.size).toBe(0);
    });
  });
});
