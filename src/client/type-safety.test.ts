/**
 * Type-level tests for PermissionArg<P>.
 *
 * These tests verify that TypeScript catches invalid permission strings
 * at compile time using @ts-expect-error annotations. They do NOT
 * execute any Authz methods — they only verify compilation.
 *
 * Run: npx vitest run src/client/type-safety.test.ts --typecheck
 */
import { describe, test, expect } from "vitest";
import {
  type Authz,
  definePermissions,
  type PermissionString,
  type PermissionArg,
} from "./index.js";

const permissions = definePermissions({
  documents: { create: true, read: true, update: true, delete: true },
  settings: { view: true, manage: true },
  billing: { view: true, manage: true },
});

type P = typeof permissions;

describe("Type-safe permission strings", () => {
  test("PermissionString<P> derives correct union type", () => {
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
    // Each @ts-expect-error MUST produce a TS error — vitest --typecheck verifies this.

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

    expect(true).toBe(true);
  });

  test("Authz method signatures accept PermissionArg<P> (type-level only)", () => {
    // This test verifies at the TYPE level that Authz methods accept PermissionArg<P>.
    // We use a type assertion to check the function signature without calling it.

    type TestAuthz = Authz<P, Record<string, never>>;

    // can() should accept valid permissions
    type CanPermArg = Parameters<TestAuthz["can"]>[2];
    const _validCan: CanPermArg = "documents:read";
    const _validCanWild: CanPermArg = "documents:*";

    // @ts-expect-error — typo should fail
    const _badCan: CanPermArg = "documets:read";

    // require() should accept valid permissions
    type RequirePermArg = Parameters<TestAuthz["require"]>[2];
    const _validRequire: RequirePermArg = "settings:manage";

    // @ts-expect-error — invalid action
    const _badRequire: RequirePermArg = "settings:delete";

    // grantPermission() should accept valid permissions
    type GrantPermArg = Parameters<TestAuthz["grantPermission"]>[2];
    const _validGrant: GrantPermArg = "billing:view";
    const _validGrantWild: GrantPermArg = "*";

    // @ts-expect-error — invalid resource
    const _badGrant: GrantPermArg = "nonexistent:perm";

    // canAny() should accept valid permission arrays
    type CanAnyPermArg = Parameters<TestAuthz["canAny"]>[2];
    const _validCanAny: CanAnyPermArg = ["documents:read", "settings:view"];

    expect(true).toBe(true);
  });
});
