import { describe, expect, it } from "vitest";
import {
  isExpired,
  parsePermission,
  buildPermission,
  matchesPermissionPattern,
  matchesScope,
} from "../helpers.js";

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
});
