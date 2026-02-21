// @vitest-environment jsdom
import React from "react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import {
  AuthzProvider,
  useAuthz,
  useCanUser,
  useUserRoles,
  useRequirePermission,
  PermissionGate,
  type AuthzQueryRefs,
} from "./index.js";

const mockUseQuery = vi.fn();
vi.mock("convex/react", () => ({ useQuery: (ref: unknown, args: unknown) => mockUseQuery(ref, args) }));

function makeMockQueryRefs(): AuthzQueryRefs {
  return {
    checkPermission: {} as AuthzQueryRefs["checkPermission"],
    getUserRoles: {} as AuthzQueryRefs["getUserRoles"],
  };
}

describe("react hooks", () => {
  beforeEach(() => {
    mockUseQuery.mockReset();
  });
  afterEach(() => {
    cleanup();
  });

  describe("AuthzProvider and useAuthz", () => {
    it("provides queryRefs and defaultUserId to children", () => {
      const queryRefs = makeMockQueryRefs();
      function Consumer() {
        const ctx = useAuthz();
        return React.createElement("span", {
          "data-testid": "defaultUserId",
          children: ctx.defaultUserId ?? "none",
        });
      }
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          defaultUserId: "user_1",
          children: React.createElement(Consumer),
        })
      );
      expect(screen.getByTestId("defaultUserId").textContent).toBe("user_1");
    });

    it("useAuthz throws when used outside AuthzProvider", () => {
      function Consumer() {
        useAuthz();
        return null;
      }
      expect(() => render(React.createElement(Consumer))).toThrow(
        "useAuthz must be used within an AuthzProvider"
      );
    });
  });

  describe("useCanUser", () => {
    it("returns error when userId is missing and no defaultUserId", () => {
      const queryRefs = makeMockQueryRefs();
      function Consumer() {
        const result = useCanUser("documents:read");
        return React.createElement("span", {
          "data-testid": "allowed",
          children: result.error ? result.error.message : String(result.allowed),
        });
      }
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          children: React.createElement(Consumer),
        })
      );
      expect(screen.getByTestId("allowed").textContent).toContain("userId is required");
    });

    it("returns isLoading true and allowed undefined while useQuery returns undefined", () => {
      mockUseQuery.mockReturnValue(undefined);
      const queryRefs = makeMockQueryRefs();
      function Consumer() {
        const result = useCanUser("documents:read", { userId: "user_1" });
        return React.createElement("span", {
          "data-testid": "loading",
          children: String(result.isLoading),
        });
      }
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          children: React.createElement(Consumer),
        })
      );
      expect(screen.getByTestId("loading").textContent).toBe("true");
    });

    it("returns allowed true when useQuery returns true", () => {
      mockUseQuery.mockReturnValue(true);
      const queryRefs = makeMockQueryRefs();
      function Consumer() {
        const result = useCanUser("documents:read", { userId: "user_1" });
        return React.createElement("span", {
          "data-testid": "allowed",
          children: String(result.allowed),
        });
      }
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          children: React.createElement(Consumer),
        })
      );
      expect(screen.getByTestId("allowed").textContent).toBe("true");
    });

    it("returns allowed false when useQuery returns false", () => {
      mockUseQuery.mockReturnValue(false);
      const queryRefs = makeMockQueryRefs();
      function Consumer() {
        const result = useCanUser("documents:delete", { userId: "user_1" });
        return React.createElement("span", {
          "data-testid": "allowed",
          children: String(result.allowed),
        });
      }
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          children: React.createElement(Consumer),
        })
      );
      expect(screen.getByTestId("allowed").textContent).toBe("false");
    });

    it("uses defaultUserId from provider when options.userId not passed", () => {
      mockUseQuery.mockReturnValue(true);
      const queryRefs = makeMockQueryRefs();
      function Consumer() {
        const result = useCanUser("documents:read");
        return React.createElement("span", {
          "data-testid": "allowed",
          children: String(result.allowed),
        });
      }
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          defaultUserId: "default_user",
          children: React.createElement(Consumer),
        })
      );
      expect(mockUseQuery).toHaveBeenCalledWith(
        queryRefs.checkPermission,
        expect.objectContaining({ userId: "default_user", permission: "documents:read" })
      );
      expect(screen.getByTestId("allowed").textContent).toBe("true");
    });
  });

  describe("useUserRoles", () => {
    it("returns error when userId is missing", () => {
      const queryRefs = makeMockQueryRefs();
      function Consumer() {
        const result = useUserRoles();
        return React.createElement("span", {
          "data-testid": "err",
          children: result.error ? result.error.message : "ok",
        });
      }
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          children: React.createElement(Consumer),
        })
      );
      expect(screen.getByTestId("err").textContent).toContain("userId is required");
    });

    it("returns roles from useQuery", () => {
      const mockRoles = [{ role: "admin" }, { role: "viewer" }];
      mockUseQuery.mockReturnValue(mockRoles);
      const queryRefs = makeMockQueryRefs();
      function Consumer() {
        const result = useUserRoles({ userId: "user_1" });
        return React.createElement("span", {
          "data-testid": "count",
          children: result.roles.length,
        });
      }
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          children: React.createElement(Consumer),
        })
      );
      expect(screen.getByTestId("count").textContent).toBe("2");
    });
  });

  describe("useRequirePermission", () => {
    it("throws when allowed is false and not loading", () => {
      mockUseQuery.mockReturnValue(false);
      const queryRefs = makeMockQueryRefs();
      function Consumer() {
        useRequirePermission("documents:delete", { userId: "user_1" });
        return React.createElement("span", { "data-testid": "ok", children: "ok" });
      }
      expect(() =>
        render(
          React.createElement(AuthzProvider, {
            queryRefs,
            children: React.createElement(Consumer),
          })
        )
      ).toThrow("Permission denied: documents:delete");
    });

    it("does not throw when allowed is true", () => {
      mockUseQuery.mockReturnValue(true);
      const queryRefs = makeMockQueryRefs();
      function Consumer() {
        useRequirePermission("documents:read", { userId: "user_1" });
        return React.createElement("span", { "data-testid": "ok", children: "ok" });
      }
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          children: React.createElement(Consumer),
        })
      );
      expect(screen.getByTestId("ok").textContent).toBe("ok");
    });
  });

  describe("PermissionGate", () => {
    it("renders children when allowed is true", () => {
      mockUseQuery.mockReturnValue(true);
      const queryRefs = makeMockQueryRefs();
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          defaultUserId: "user_1",
          children: React.createElement(PermissionGate, {
            permission: "documents:read",
            fallback: React.createElement("span", { children: "Denied" }),
            children: React.createElement("span", { "data-testid": "content", children: "Content" }),
          }),
        })
      );
      expect(screen.getByTestId("content").textContent).toBe("Content");
    });

    it("renders fallback when allowed is false", () => {
      mockUseQuery.mockReturnValue(false);
      const queryRefs = makeMockQueryRefs();
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          defaultUserId: "user_1",
          children: React.createElement(PermissionGate, {
            permission: "documents:delete",
            fallback: React.createElement("span", { "data-testid": "denied", children: "Denied" }),
            children: React.createElement("span", { children: "Content" }),
          }),
        })
      );
      expect(screen.getByTestId("denied").textContent).toBe("Denied");
    });

    it("renders loadingFallback when loading", () => {
      mockUseQuery.mockReturnValue(undefined);
      const queryRefs = makeMockQueryRefs();
      render(
        React.createElement(AuthzProvider, {
          queryRefs,
          defaultUserId: "user_1",
          children: React.createElement(PermissionGate, {
            permission: "documents:read",
            fallback: React.createElement("span", { children: "Denied" }),
            loadingFallback: React.createElement("span", { "data-testid": "loading", children: "Loading..." }),
            children: React.createElement("span", { children: "Content" }),
          }),
        })
      );
      expect(screen.getByTestId("loading").textContent).toBe("Loading...");
    });
  });
});
