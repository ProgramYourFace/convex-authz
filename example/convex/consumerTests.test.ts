/**
 * Consumer Integration Tests — exercises the Authz class through real convexTest DB calls.
 *
 * These tests cover the gap between unit tests (mocked client) and component-level tests
 * (bypass the client class). They verify RBAC round trips, role inheritance, scope isolation,
 * tenant isolation, grant/deny overrides, ReBAC, expiry, deferred policies, require(),
 * deprovision, and recompute — all through the same code path a real app uses.
 *
 * Run: npx vitest run example/convex/consumerTests.test.ts -v
 */
import { convexTest } from "convex-test";
import { describe, test, expect } from "vitest";
import schema from "./schema.js";
import { api } from "./_generated/api.js";
import authzTest from "@djpanda/convex-authz/test";

const modules = import.meta.glob("./**/*.ts");

function setup() {
  const t = convexTest(schema, modules);
  authzTest.register(t, "authz");
  return t;
}

describe("Consumer Integration Tests (Authz class -> real DB)", () => {
  // =========================================================================
  // 1. Full RBAC round trip
  // =========================================================================
  test("assignRole -> can -> revokeRole -> can", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "alice",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "editor" });

    // Editor inherits base: documents:read, documents:create, documents:update, settings:view
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(true);
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:create",
      }),
    ).toBe(true);
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:update",
      }),
    ).toBe(true);
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "settings:view",
      }),
    ).toBe(true);

    // Editor should NOT have delete or billing
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(false);
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "billing:manage",
      }),
    ).toBe(false);

    // Revoke
    const revoked = await t.mutation(api.consumerTests.revokeRole, {
      userId,
      role: "editor",
    });
    expect(revoked).toBe(true);

    // All denied after revoke
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(false);
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:create",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 2. Role inheritance verification
  // =========================================================================
  test("role inheritance: admin inherits editor inherits base", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "bob",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "admin" });

    // Admin should have ALL permissions (from admin + editor + base)
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(true); // from base
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:create",
      }),
    ).toBe(true); // from editor
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:update",
      }),
    ).toBe(true); // from editor
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(true); // from admin
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "settings:view",
      }),
    ).toBe(true); // from base
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "settings:manage",
      }),
    ).toBe(true); // from admin
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "billing:view",
      }),
    ).toBe(true); // from admin
  });

  // =========================================================================
  // 3. Deferred policy: billing:manage requires "verified" attribute
  // =========================================================================
  test("deferred policy: billing:manage denied without verified attribute", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "policyUser",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "admin" });

    // billing:manage has a deferred policy requiring verified == true
    // Without the attribute, should be denied
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "billing:manage",
      }),
    ).toBe(false);

    // Set verified = true
    await t.mutation(api.consumerTests.setAttribute, {
      userId,
      key: "verified",
      value: true,
    });

    // Now should be allowed
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "billing:manage",
      }),
    ).toBe(true);

    // Remove attribute -> denied again
    await t.mutation(api.consumerTests.removeAttribute, {
      userId,
      key: "verified",
    });
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "billing:manage",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 4. Scope isolation
  // =========================================================================
  test("scoped role: allowed in scope, denied globally and in other scope", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "carol",
    });
    const scope = { type: "project", id: "p1" };

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
      scope,
    });

    // Allowed in correct scope
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
        scope,
      }),
    ).toBe(true);

    // Denied globally
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(false);

    // Denied in different scope
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
        scope: { type: "project", id: "p2" },
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 5. Cross-tenant isolation
  // =========================================================================
  test("tenant isolation: role in tenant A invisible in tenant B", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "dave",
    });

    // Assign admin in tenant A (consumer-test)
    await t.mutation(api.consumerTests.assignRole, { userId, role: "admin" });

    // Set verified so billing:manage passes deferred policy in tenant A
    await t.mutation(api.consumerTests.setAttribute, {
      userId,
      key: "verified",
      value: true,
    });

    // Allowed in tenant A
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(true);

    // Denied in tenant B
    expect(
      await t.query(api.consumerTests.canB, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 6. withTenant() isolation
  // =========================================================================
  test("withTenant() creates isolated scope", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "eve",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "viewer" });

    // Allowed in original tenant
    expect(
      await t.query(api.consumerTests.canWithTenant, {
        userId,
        permission: "documents:read",
        tenantId: "consumer-test",
      }),
    ).toBe(true);

    // Denied in different tenant
    expect(
      await t.query(api.consumerTests.canWithTenant, {
        userId,
        permission: "documents:read",
        tenantId: "other-tenant",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 7. Direct grant / deny round trip
  // =========================================================================
  test("grantPermission -> can -> denyPermission -> can -> grantPermission -> can", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "frank",
    });

    // Grant
    await t.mutation(api.consumerTests.grantPermission, {
      userId,
      permission: "documents:delete",
    });
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(true);

    // Deny overrides
    await t.mutation(api.consumerTests.denyPermission, {
      userId,
      permission: "documents:delete",
    });
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(false);

    // Grant again clears deny
    await t.mutation(api.consumerTests.grantPermission, {
      userId,
      permission: "documents:delete",
    });
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(true);
  });

  // =========================================================================
  // 8. Deny overrides role-based allow; direct grant survives role revoke
  // =========================================================================
  test("deny overrides role-based allow, direct grant survives revoke", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "grace",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "editor" });
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(true);

    // Deny overrides role
    await t.mutation(api.consumerTests.denyPermission, {
      userId,
      permission: "documents:read",
    });
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(false);

    // Direct grant on another permission (not covered by roles)
    await t.mutation(api.consumerTests.grantPermission, {
      userId,
      permission: "billing:view",
    });

    // Revoke role
    await t.mutation(api.consumerTests.revokeRole, { userId, role: "editor" });

    // Direct grant survives role revoke
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "billing:view",
      }),
    ).toBe(true);
  });

  // =========================================================================
  // 9. require() throws on denied
  // =========================================================================
  test("require() throws for denied permission", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "heidi",
    });

    await expect(
      t.query(api.consumerTests.requirePerm, {
        userId,
        permission: "documents:delete",
      }),
    ).rejects.toThrow();
  });

  // =========================================================================
  // 10. require() passes for allowed permission
  // =========================================================================
  test("require() passes for allowed permission", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "ivan",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "admin" });

    // documents:delete has no policy; should pass
    await t.query(api.consumerTests.requirePerm, {
      userId,
      permission: "documents:delete",
    });
  });

  // =========================================================================
  // 11. ReBAC round trip
  // =========================================================================
  test("addRelation -> hasRelation -> removeRelation -> hasRelation", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "judy",
    });

    await t.mutation(api.consumerTests.addRelation, {
      subjectType: "user",
      subjectId: userId,
      relation: "member",
      objectType: "team",
      objectId: "team-1",
    });

    expect(
      await t.query(api.consumerTests.hasRelation, {
        subjectType: "user",
        subjectId: userId,
        relation: "member",
        objectType: "team",
        objectId: "team-1",
      }),
    ).toBe(true);

    expect(
      await t.query(api.consumerTests.hasRelation, {
        subjectType: "user",
        subjectId: userId,
        relation: "member",
        objectType: "team",
        objectId: "team-2",
      }),
    ).toBe(false);

    await t.mutation(api.consumerTests.removeRelation, {
      subjectType: "user",
      subjectId: userId,
      relation: "member",
      objectType: "team",
      objectId: "team-1",
    });

    expect(
      await t.query(api.consumerTests.hasRelation, {
        subjectType: "user",
        subjectId: userId,
        relation: "member",
        objectType: "team",
        objectId: "team-1",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 12. Expiry — past-dated role is denied immediately
  // =========================================================================
  test("expired role is denied immediately", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "karl",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "admin",
      expiresAt: Date.now() - 10_000,
    });

    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 13. Attributes round trip
  // =========================================================================
  test("setAttribute / removeAttribute round trip", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "liam",
    });

    await t.mutation(api.consumerTests.setAttribute, {
      userId,
      key: "dept",
      value: "engineering",
    });
    await t.mutation(api.consumerTests.setAttribute, {
      userId,
      key: "level",
      value: 5,
    });

    const removed = await t.mutation(api.consumerTests.removeAttribute, {
      userId,
      key: "dept",
    });
    expect(removed).toBe(true);

    // Removing non-existent attribute returns false
    const removedAgain = await t.mutation(api.consumerTests.removeAttribute, {
      userId,
      key: "dept",
    });
    expect(removedAgain).toBe(false);
  });

  // =========================================================================
  // 14. Deprovision wipes everything
  // =========================================================================
  test("deprovisionUser wipes all data", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "mike",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "admin" });
    await t.mutation(api.consumerTests.grantPermission, {
      userId,
      permission: "billing:view",
    });
    await t.mutation(api.consumerTests.setAttribute, {
      userId,
      key: "dept",
      value: "eng",
    });
    await t.mutation(api.consumerTests.addRelation, {
      subjectType: "user",
      subjectId: userId,
      relation: "member",
      objectType: "team",
      objectId: "t1",
    });

    await t.mutation(api.consumerTests.deprovision, { userId });

    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(false);
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "billing:view",
      }),
    ).toBe(false);
    expect(
      await t.query(api.consumerTests.hasRelation, {
        subjectType: "user",
        subjectId: userId,
        relation: "member",
        objectType: "team",
        objectId: "t1",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 15. getUserRoles returns correct data
  // =========================================================================
  test("getUserRoles returns assigned roles", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "nancy",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "editor" });
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "viewer",
      scope: { type: "project", id: "p1" },
    });

    const roles = await t.query(api.consumerTests.getUserRoles, { userId });
    expect(roles.length).toBe(2);
    expect(
      roles
        .map((r: { role: string }) => r.role)
        .sort(),
    ).toEqual(["editor", "viewer"]);
  });

  // =========================================================================
  // 16. getUserPermissions returns correct data
  // =========================================================================
  test("getUserPermissions returns effective permissions", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "olivia",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "viewer" });

    const perms = await t.query(api.consumerTests.getUserPermissions, {
      userId,
    });
    expect(Array.isArray(perms)).toBe(true);
    expect(perms.length).toBeGreaterThan(0);

    // Viewer should have documents:read
    const permStrings = perms.map(
      (p: { permission: string }) => p.permission,
    );
    expect(permStrings).toContain("documents:read");
  });

  // =========================================================================
  // 17. Recompute rebuilds effective tables
  // =========================================================================
  test("recomputeUser rebuilds from source", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "oscar",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "admin" });
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(true);

    // Recompute should maintain the same state
    await t.mutation(api.consumerTests.recompute, { userId });
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(true);
  });

  // =========================================================================
  // 18. hasRole query
  // =========================================================================
  test("hasRole returns true for assigned role, false otherwise", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "pat",
    });

    await t.mutation(api.consumerTests.assignRole, { userId, role: "editor" });

    expect(
      await t.query(api.consumerTests.hasRole, { userId, role: "editor" }),
    ).toBe(true);
    expect(
      await t.query(api.consumerTests.hasRole, { userId, role: "admin" }),
    ).toBe(false);
    expect(
      await t.query(api.consumerTests.hasRole, { userId, role: "viewer" }),
    ).toBe(false);
  });

  // =========================================================================
  // 19. Scoped grant/deny
  // =========================================================================
  test("scoped grant is isolated from global and other scopes", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "quinn",
    });
    const scope = { type: "org", id: "org1" };

    await t.mutation(api.consumerTests.grantPermission, {
      userId,
      permission: "documents:delete",
      scope,
    });

    // Allowed in scope
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
        scope,
      }),
    ).toBe(true);

    // Denied globally
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(false);

    // Denied in different scope
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
        scope: { type: "org", id: "org2" },
      }),
    ).toBe(false);
  });
});
