/**
 * Type-level tests for PermissionArg<P>.
 *
 * These tests verify that TypeScript catches invalid permission strings
 * at compile time. They use @ts-expect-error to assert that invalid
 * strings produce type errors.
 *
 * Run: npx vitest run src/client/type-safety.test.ts
 * Also verified by: npm run typecheck (tsc --noEmit)
 */
import { describe, test, expect } from "vitest";
import {
  Authz,
  definePermissions,
  defineRoles,
  type PermissionString,
  type PermissionArg,

} from "./index.js";
import type { ComponentApi } from "../component/_generated/component.js";

const permissions = definePermissions({
  documents: { create: true, read: true, update: true, delete: true },
  settings: { view: true, manage: true },
  billing: { view: true, manage: true },
});

const roles = defineRoles(permissions, {
  admin: {
    documents: ["create", "read", "update", "delete"],
    settings: ["view", "manage"],
    billing: ["view", "manage"],
  },
  viewer: {
    documents: ["read"],
  },
});

type P = typeof permissions;

describe("Type-safe permission strings", () => {
  test("PermissionString<P> derives correct union type", () => {
    // These should all be valid
    const p1: PermissionString<P> = "documents:read";
    const p2: PermissionString<P> = "documents:create";
    const p3: PermissionString<P> = "documents:update";
    const p4: PermissionString<P> = "documents:delete";
    const p5: PermissionString<P> = "settings:view";
    const p6: PermissionString<P> = "settings:manage";
    const p7: PermissionString<P> = "billing:view";
    const p8: PermissionString<P> = "billing:manage";

    expect(p1).toBe("documents:read");
    expect(p2).toBe("documents:create");
    expect(p3).toBe("documents:update");
    expect(p4).toBe("documents:delete");
    expect(p5).toBe("settings:view");
    expect(p6).toBe("settings:manage");
    expect(p7).toBe("billing:view");
    expect(p8).toBe("billing:manage");
  });

  test("PermissionArg<P> accepts wildcard patterns", () => {
    const w1: PermissionArg<P> = "documents:*";
    const w2: PermissionArg<P> = "settings:*";
    const w3: PermissionArg<P> = "*:read";
    const w4: PermissionArg<P> = "*:manage";
    const w5: PermissionArg<P> = "*";
    const w6: PermissionArg<P> = "*:*";

    expect(w1).toBe("documents:*");
    expect(w2).toBe("settings:*");
    expect(w3).toBe("*:read");
    expect(w4).toBe("*:manage");
    expect(w5).toBe("*");
    expect(w6).toBe("*:*");
  });

  test("invalid permission strings produce TypeScript errors", () => {
    // Each @ts-expect-error line MUST produce a TS error.
    // If TypeScript doesn't error, vitest --typecheck will fail.

    // @ts-expect-error — typo in resource name
    const _bad1: PermissionArg<P> = "documets:read";

    // @ts-expect-error — typo in action name
    const _bad2: PermissionArg<P> = "documents:reed";

    // @ts-expect-error — non-existent resource
    const _bad3: PermissionArg<P> = "users:create";

    // @ts-expect-error — non-existent action
    const _bad4: PermissionArg<P> = "documents:archive";

    // @ts-expect-error — not a valid format
    const _bad5: PermissionArg<P> = "justAString";

    // @ts-expect-error — wildcard with non-existent action
    const _bad6: PermissionArg<P> = "*:archive";

    // @ts-expect-error — wildcard with non-existent resource
    const _bad7: PermissionArg<P> = "users:*";

    expect(true).toBe(true); // test passes if TS errors are correctly expected
  });

  test("Authz.can() accepts only valid permission strings", () => {
    const component = {} as unknown as ComponentApi;
    const authz = new Authz(component, { permissions, roles, tenantId: "test" });
    const ctx = {
      runQuery: async () => ({ allowed: true, reason: "", tier: "cached" }),
      runMutation: async () => "",
    } as any;

    // These should compile:
    void authz.can(ctx, "user1", "documents:read");
    void authz.can(ctx, "user1", "settings:manage");
    void authz.can(ctx, "user1", "documents:*");
    void authz.can(ctx, "user1", "*:read");
    void authz.can(ctx, "user1", "*");

    // @ts-expect-error — typo
    void authz.can(ctx, "user1", "documets:read");

    // @ts-expect-error — non-existent action
    void authz.can(ctx, "user1", "documents:archive");

    // @ts-expect-error — non-existent resource
    void authz.can(ctx, "user1", "users:read");

    expect(true).toBe(true);
  });

  test("Authz.require() accepts only valid permission strings", () => {
    const component = {} as unknown as ComponentApi;
    const authz = new Authz(component, { permissions, roles, tenantId: "test" });
    const ctx = {
      runQuery: async () => ({ allowed: true, reason: "", tier: "cached" }),
    } as any;

    // These should compile:
    void authz.require(ctx, "user1", "documents:read");
    void authz.require(ctx, "user1", "billing:manage");

    // @ts-expect-error — typo
    void authz.require(ctx, "user1", "documets:read");

    expect(true).toBe(true);
  });

  test("Authz.canAny() accepts only valid permission arrays", () => {
    const component = {} as unknown as ComponentApi;
    const authz = new Authz(component, { permissions, roles, tenantId: "test" });
    const ctx = {
      runQuery: async () => ({ allowed: true, reason: "", tier: "cached" }),
    } as any;

    // These should compile:
    void authz.canAny(ctx, "user1", ["documents:read", "settings:view"]);
    void authz.canAny(ctx, "user1", ["documents:*", "*:read"]);

    // @ts-expect-error — invalid permission in array
    void authz.canAny(ctx, "user1", ["documents:read", "typo:action"]);

    expect(true).toBe(true);
  });

  test("Authz.grantPermission() accepts only valid permissions", () => {
    const component = {} as unknown as ComponentApi;
    const authz = new Authz(component, { permissions, roles, tenantId: "test" });
    const ctx = {
      runQuery: async () => ({ allowed: true, reason: "", tier: "cached" }),
      runMutation: async () => "id",
    } as any;

    // These should compile:
    void authz.grantPermission(ctx, "user1", "documents:read");
    void authz.grantPermission(ctx, "user1", "documents:*");

    // @ts-expect-error — invalid permission
    void authz.grantPermission(ctx, "user1", "nonexistent:perm");

    expect(true).toBe(true);
  });

  test("Authz.denyPermission() accepts only valid permissions", () => {
    const component = {} as unknown as ComponentApi;
    const authz = new Authz(component, { permissions, roles, tenantId: "test" });
    const ctx = {
      runQuery: async () => ({ allowed: true, reason: "", tier: "cached" }),
      runMutation: async () => "id",
    } as any;

    // These should compile:
    void authz.denyPermission(ctx, "user1", "documents:delete");
    void authz.denyPermission(ctx, "user1", "*:manage");

    // @ts-expect-error — invalid permission
    void authz.denyPermission(ctx, "user1", "bad:permission");

    expect(true).toBe(true);
  });
});
