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

  // =========================================================================
  // 20. Two roles sharing permission, revoke one -> still allowed
  // =========================================================================
  test("two roles sharing permission, revoke one -> still allowed", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "rachel",
    });

    // Both editor (inherits base:documents:read) and viewer grant documents:read
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
    });
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "viewer",
    });

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

    // Revoke editor — viewer still provides documents:read
    await t.mutation(api.consumerTests.revokeRole, {
      userId,
      role: "editor",
    });

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
    ).toBe(false);
  });

  // =========================================================================
  // 21. Three roles, revoke two, shared perm survives
  // =========================================================================
  test("three roles, revoke two, shared perm survives", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "sam",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "admin",
    });
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
    });
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "viewer",
    });

    await t.mutation(api.consumerTests.revokeRole, {
      userId,
      role: "admin",
    });
    await t.mutation(api.consumerTests.revokeRole, {
      userId,
      role: "editor",
    });

    // viewer still provides documents:read
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(true);
    // documents:delete was only on admin
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 22. assignRoles bulk -> all permissions correct
  // =========================================================================
  test("assignRoles bulk -> all permissions correct", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "tina",
    });

    const result = await t.mutation(api.consumerTests.assignRoles, {
      userId,
      roles: [{ role: "admin" }, { role: "viewer" }],
    });

    expect(result.assigned).toBe(2);
    expect(result.assignmentIds.length).toBe(2);

    // admin perms present
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(true);
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "settings:manage",
      }),
    ).toBe(true);
  });

  // =========================================================================
  // 23. revokeRoles bulk -> correct perms removed
  // =========================================================================
  test("revokeRoles bulk -> correct perms removed", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "uma",
    });

    await t.mutation(api.consumerTests.assignRoles, {
      userId,
      roles: [{ role: "admin" }, { role: "editor" }, { role: "viewer" }],
    });

    const result = await t.mutation(api.consumerTests.revokeRoles, {
      userId,
      roles: [{ role: "admin" }, { role: "editor" }],
    });
    expect(result.revoked).toBe(2);

    // viewer still provides documents:read
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(true);
    // documents:delete was only on admin
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 24. revokeAllRoles -> all denied
  // =========================================================================
  test("revokeAllRoles -> all denied", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "victor",
    });

    await t.mutation(api.consumerTests.assignRoles, {
      userId,
      roles: [{ role: "admin" }, { role: "editor" }],
    });

    const revoked = await t.mutation(api.consumerTests.revokeAllRoles, {
      userId,
    });
    expect(revoked).toBe(2);

    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 25. revokeAllRoles preserves direct grants
  // =========================================================================
  test("revokeAllRoles preserves direct grants", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "wendy",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "admin",
    });
    await t.mutation(api.consumerTests.grantPermission, {
      userId,
      permission: "billing:view",
    });

    await t.mutation(api.consumerTests.revokeAllRoles, { userId });

    // Role-based perm gone
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(false);
    // Direct grant preserved
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "billing:view",
      }),
    ).toBe(true);
  });

  // =========================================================================
  // 26. canAny returns true if any permission matches
  // =========================================================================
  test("canAny returns true if any permission matches", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "xander",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "viewer",
    });

    // viewer has documents:read but not documents:delete
    expect(
      await t.query(api.consumerTests.canAny, {
        userId,
        permissions: ["documents:read", "documents:delete"],
      }),
    ).toBe(true);
  });

  // =========================================================================
  // 27. canAny returns false if no permission matches
  // =========================================================================
  test("canAny returns false if no permission matches", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "yolanda",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "viewer",
    });

    expect(
      await t.query(api.consumerTests.canAny, {
        userId,
        permissions: ["documents:delete", "billing:manage"],
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 28. deny then assignRole same permission -> deny still wins
  // =========================================================================
  test("deny then assignRole same permission -> deny still wins", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "zach",
    });

    await t.mutation(api.consumerTests.denyPermission, {
      userId,
      permission: "documents:read",
    });
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
    });

    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 29. assignRole then grantPermission same permission -> grant survives revoke
  // =========================================================================
  test("assignRole then grantPermission same permission -> grant survives revoke", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "amber",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
    });
    await t.mutation(api.consumerTests.grantPermission, {
      userId,
      permission: "documents:read",
    });

    // Revoke the role
    await t.mutation(api.consumerTests.revokeRole, {
      userId,
      role: "editor",
    });

    // Direct grant survives
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(true);
  });

  // =========================================================================
  // 31. offboard removes roles, preserves overrides source when removeOverrides=false
  // =========================================================================
  test("offboard removes roles, preserves overrides when removeOverrides=false", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "blake",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "admin",
    });
    await t.mutation(api.consumerTests.grantPermission, {
      userId,
      permission: "billing:view",
    });

    const result = await t.mutation(api.consumerTests.offboardUser, {
      userId,
      removeOverrides: false,
    });

    // Role-based perm gone
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(false);

    // Overrides source rows preserved (overridesRemoved == 0)
    expect(result.overridesRemoved).toBe(0);
    // Roles were removed
    expect(result.rolesRevoked).toBe(1);

    // Direct grant survives offboard — effective table row preserved with empty sources
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "billing:view",
      }),
    ).toBe(true);
  });

  // =========================================================================
  // 32. offboard with removeOverrides=true removes everything
  // =========================================================================
  test("offboard with removeOverrides=true removes everything", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "charlie",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "admin",
    });
    await t.mutation(api.consumerTests.grantPermission, {
      userId,
      permission: "billing:view",
    });

    await t.mutation(api.consumerTests.offboardUser, {
      userId,
      removeOverrides: true,
    });

    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "billing:view",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 33. audit log captures role_assigned event
  // =========================================================================
  test("audit log captures role_assigned event", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "diana",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "admin",
    });

    const logs = await t.query(api.consumerTests.getAuditLog, {
      userId,
    });
    const logArray = Array.isArray(logs) ? logs : logs.page;
    expect(logArray.length).toBeGreaterThan(0);
    expect(
      logArray.some(
        (entry: { action: string }) => entry.action === "role_assigned",
      ),
    ).toBe(true);
  });

  // =========================================================================
  // 34. audit log captures permission_granted event
  // =========================================================================
  test("audit log captures permission_granted event", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "ethan",
    });

    await t.mutation(api.consumerTests.grantPermission, {
      userId,
      permission: "billing:view",
    });

    const logs = await t.query(api.consumerTests.getAuditLog, {
      userId,
    });
    const logArray = Array.isArray(logs) ? logs : logs.page;
    expect(logArray.length).toBeGreaterThan(0);
    expect(
      logArray.some(
        (entry: { action: string }) => entry.action === "permission_granted",
      ),
    ).toBe(true);
  });

  // =========================================================================
  // 35. same role in two different scopes -> revoke one preserves other
  // =========================================================================
  test("same role in two different scopes -> revoke one preserves other", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "fiona",
    });

    const scopeP1 = { type: "project", id: "p1" };
    const scopeP2 = { type: "project", id: "p2" };

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
      scope: scopeP1,
    });
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
      scope: scopeP2,
    });

    // Revoke only in p1
    await t.mutation(api.consumerTests.revokeRole, {
      userId,
      role: "editor",
      scope: scopeP1,
    });

    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
        scope: scopeP1,
      }),
    ).toBe(false);
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
        scope: scopeP2,
      }),
    ).toBe(true);
  });

  // =========================================================================
  // 36. global role + scoped role -> independent
  // =========================================================================
  test("global role + scoped role -> independent", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "george",
    });

    const scopeP1 = { type: "project", id: "p1" };

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "admin",
    });
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "viewer",
      scope: scopeP1,
    });

    // Revoke global admin
    await t.mutation(api.consumerTests.revokeRole, {
      userId,
      role: "admin",
    });

    // Global admin perm gone
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(false);
    // Scoped viewer still there
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
        scope: scopeP1,
      }),
    ).toBe(true);
  });

  // =========================================================================
  // 37. revokeAllRoles with scope -> only revokes in that scope
  // =========================================================================
  test("revokeAllRoles with scope -> only revokes in that scope", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "hannah",
    });

    const scopeP1 = { type: "project", id: "p1" };

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "admin",
    });
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
      scope: scopeP1,
    });

    // Revoke all roles only in scope p1
    await t.mutation(api.consumerTests.revokeAllRoles, {
      userId,
      scope: scopeP1,
    });

    // Global admin preserved
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(true);
    // Scoped editor gone
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
        scope: scopeP1,
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 39. recompute after deprovision + reassign -> clean state
  // =========================================================================
  test("recompute after deprovision + reassign -> clean state", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "iris",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "admin",
    });
    await t.mutation(api.consumerTests.deprovision, { userId });

    // Reassign viewer
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "viewer",
    });
    await t.mutation(api.consumerTests.recompute, { userId });

    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(true);
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:delete",
      }),
    ).toBe(false);
  });

  // =========================================================================
  // 40. double assignRole is idempotent
  // =========================================================================
  test("double assignRole is idempotent", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "jack",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
    });
    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
    });

    const roles = await t.query(api.consumerTests.getUserRoles, { userId });
    const editorRoles = roles.filter(
      (r: { role: string }) => r.role === "editor",
    );
    expect(editorRoles.length).toBe(1);
  });

  // =========================================================================
  // 41. double revoke returns false
  // =========================================================================
  test("double revoke returns false", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "kate",
    });

    await t.mutation(api.consumerTests.assignRole, {
      userId,
      role: "editor",
    });

    const first = await t.mutation(api.consumerTests.revokeRole, {
      userId,
      role: "editor",
    });
    expect(first).toBe(true);

    const second = await t.mutation(api.consumerTests.revokeRole, {
      userId,
      role: "editor",
    });
    expect(second).toBe(false);
  });

  // =========================================================================
  // 42. addRelation is idempotent
  // =========================================================================
  test("addRelation is idempotent", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "leo",
    });

    const id1 = await t.mutation(api.consumerTests.addRelation, {
      subjectType: "user",
      subjectId: userId,
      relation: "member",
      objectType: "team",
      objectId: "team-1",
    });

    const id2 = await t.mutation(api.consumerTests.addRelation, {
      subjectType: "user",
      subjectId: userId,
      relation: "member",
      objectType: "team",
      objectId: "team-1",
    });

    // Both return same ID (idempotent)
    expect(id1).toBe(id2);
  });
});

// =============================================================================
// ReBAC -> Permission Bridge (via defineRelationPermissions)
// =============================================================================
describe("ReBAC -> Permission Bridge (via defineRelationPermissions)", () => {
  test("addRelation with viewer grants documents:read scoped to document", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "rebac-perm-user",
    });

    await t.mutation(api.consumerTests.addRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "viewer",
      objectType: "document",
      objectId: "doc-1",
    });

    // can() with document scope -> allowed
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
        scope: { type: "document", id: "doc-1" },
      }),
    ).toBe(true);

    // can() with different document -> denied
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
        scope: { type: "document", id: "doc-2" },
      }),
    ).toBe(false);

    // can() globally -> denied
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(false);

    // hasRelation still works
    expect(
      await t.query(api.consumerTests.hasRelationWithPerms, {
        subjectType: "user",
        subjectId: userId,
        relation: "viewer",
        objectType: "document",
        objectId: "doc-1",
      }),
    ).toBe(true);
  });

  test("removeRelation revokes relation-derived permissions", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "rebac-revoke-user",
    });

    await t.mutation(api.consumerTests.addRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "editor",
      objectType: "document",
      objectId: "doc-1",
    });

    // editor grants read + update
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
        scope: { type: "document", id: "doc-1" },
      }),
    ).toBe(true);
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:update",
        scope: { type: "document", id: "doc-1" },
      }),
    ).toBe(true);

    // Remove relation
    await t.mutation(api.consumerTests.removeRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "editor",
      objectType: "document",
      objectId: "doc-1",
    });

    // Both permissions revoked
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
        scope: { type: "document", id: "doc-1" },
      }),
    ).toBe(false);
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:update",
        scope: { type: "document", id: "doc-1" },
      }),
    ).toBe(false);
  });

  test("owner relation grants read + update + delete", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "rebac-owner-user",
    });

    await t.mutation(api.consumerTests.addRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "owner",
      objectType: "document",
      objectId: "doc-1",
    });

    const scope = { type: "document", id: "doc-1" };
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
        scope,
      }),
    ).toBe(true);
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:update",
        scope,
      }),
    ).toBe(true);
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:delete",
        scope,
      }),
    ).toBe(true);

    // But not settings:manage
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "settings:manage",
        scope,
      }),
    ).toBe(false);
  });

  test("RBAC role + ReBAC relation work together", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "rebac-rbac-user",
    });

    // Assign global base role (grants documents:read globally)
    await t.mutation(api.consumerTests.assignRoleInRebacTenant, {
      userId,
      role: "base",
    });

    // Add editor relation on doc-1 (grants documents:read + documents:update scoped)
    await t.mutation(api.consumerTests.addRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "editor",
      objectType: "document",
      objectId: "doc-1",
    });

    // Global: documents:read from role
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(true);
    // Global: documents:update NOT from role (base doesn't have it)
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:update",
      }),
    ).toBe(false);

    // Scoped to doc-1: documents:update from relation
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:update",
        scope: { type: "document", id: "doc-1" },
      }),
    ).toBe(true);

    // Remove relation — scoped update goes away, global read stays
    await t.mutation(api.consumerTests.removeRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "editor",
      objectType: "document",
      objectId: "doc-1",
    });

    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
      }),
    ).toBe(true); // role still
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:update",
        scope: { type: "document", id: "doc-1" },
      }),
    ).toBe(false); // relation gone
  });

  test("multiple relations on same document — removing one preserves the other's permissions", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "rebac-multi-user",
    });

    // viewer on doc-1 (grants read)
    await t.mutation(api.consumerTests.addRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "viewer",
      objectType: "document",
      objectId: "doc-1",
    });

    // editor on doc-1 (grants read + update)
    await t.mutation(api.consumerTests.addRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "editor",
      objectType: "document",
      objectId: "doc-1",
    });

    const scope = { type: "document", id: "doc-1" };

    // Remove viewer — editor still grants read + update
    await t.mutation(api.consumerTests.removeRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "viewer",
      objectType: "document",
      objectId: "doc-1",
    });

    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
        scope,
      }),
    ).toBe(true);
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:update",
        scope,
      }),
    ).toBe(true);

    // Remove editor — now everything gone
    await t.mutation(api.consumerTests.removeRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "editor",
      objectType: "document",
      objectId: "doc-1",
    });

    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
        scope,
      }),
    ).toBe(false);
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:update",
        scope,
      }),
    ).toBe(false);
  });

  test("team:member relation grants permission scoped to team", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "rebac-team-user",
    });

    await t.mutation(api.consumerTests.addRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "member",
      objectType: "team",
      objectId: "team-1",
    });

    // Scoped to team
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
        scope: { type: "team", id: "team-1" },
      }),
    ).toBe(true);

    // Different team -> denied
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
        scope: { type: "team", id: "team-2" },
      }),
    ).toBe(false);
  });

  test("cross-tenant isolation for relation-derived permissions", async () => {
    const t = setup();
    const userId = await t.mutation(api.consumerTests.createUser, {
      name: "rebac-tenant-user",
    });

    // Add relation in rebac tenant
    await t.mutation(api.consumerTests.addRelationWithPerms, {
      subjectType: "user",
      subjectId: userId,
      relation: "viewer",
      objectType: "document",
      objectId: "doc-1",
    });

    // Allowed in rebac tenant
    expect(
      await t.query(api.consumerTests.canWithRelPerms, {
        userId,
        permission: "documents:read",
        scope: { type: "document", id: "doc-1" },
      }),
    ).toBe(true);

    // Denied in other tenant (consumer-test)
    expect(
      await t.query(api.consumerTests.can, {
        userId,
        permission: "documents:read",
        scope: { type: "document", id: "doc-1" },
      }),
    ).toBe(false);
  });
});
