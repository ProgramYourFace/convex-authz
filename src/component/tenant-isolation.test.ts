import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "./schema.js";
import { api } from "./_generated/api.js";

const modules = import.meta.glob("./**/*.ts");

const TENANT_A = "tenant-acme";
const TENANT_B = "tenant-globex";

describe("Cross-tenant role isolation", () => {
  it("role assigned in tenant A is not visible in tenant B", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.mutations.assignRole, {
      tenantId: TENANT_A,
      userId: "user1",
      role: "admin",
    });

    const rolesA = await t.query(api.queries.getUserRoles, {
      tenantId: TENANT_A,
      userId: "user1",
    });
    expect(rolesA).toHaveLength(1);
    expect(rolesA[0].role).toBe("admin");

    const rolesB = await t.query(api.queries.getUserRoles, {
      tenantId: TENANT_B,
      userId: "user1",
    });
    expect(rolesB).toHaveLength(0);
  });
});

describe("Cross-tenant permission check isolation", () => {
  it("permission granted via role in tenant A is denied in tenant B", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.mutations.assignRole, {
      tenantId: TENANT_A,
      userId: "user1",
      role: "admin",
    });

    const resultA = await t.query(api.queries.checkPermission, {
      tenantId: TENANT_A,
      userId: "user1",
      permission: "documents:read",
      rolePermissions: { admin: ["documents:read", "documents:write"] },
    });
    expect(resultA.allowed).toBe(true);

    const resultB = await t.query(api.queries.checkPermission, {
      tenantId: TENANT_B,
      userId: "user1",
      permission: "documents:read",
      rolePermissions: { admin: ["documents:read", "documents:write"] },
    });
    expect(resultB.allowed).toBe(false);
  });
});

describe("Cross-tenant attribute isolation", () => {
  it("attribute set in tenant A is not visible in tenant B", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.mutations.setAttribute, {
      tenantId: TENANT_A,
      userId: "user1",
      key: "dept",
      value: "engineering",
    });

    const attrsA = await t.query(api.queries.getUserAttributes, {
      tenantId: TENANT_A,
      userId: "user1",
    });
    expect(attrsA).toHaveLength(1);
    expect(attrsA[0].key).toBe("dept");
    expect(attrsA[0].value).toBe("engineering");

    const attrsB = await t.query(api.queries.getUserAttributes, {
      tenantId: TENANT_B,
      userId: "user1",
    });
    expect(attrsB).toHaveLength(0);
  });
});

describe("Cross-tenant permission override isolation", () => {
  it("permission override in tenant A is not visible in tenant B", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.mutations.grantPermission, {
      tenantId: TENANT_A,
      userId: "user1",
      permission: "documents:read",
    });

    const overridesA = await t.query(api.queries.getPermissionOverrides, {
      tenantId: TENANT_A,
      userId: "user1",
    });
    expect(overridesA).toHaveLength(1);
    expect(overridesA[0].permission).toBe("documents:read");

    const overridesB = await t.query(api.queries.getPermissionOverrides, {
      tenantId: TENANT_B,
      userId: "user1",
    });
    expect(overridesB).toHaveLength(0);
  });
});

describe("Cross-tenant ReBAC isolation", () => {
  it("relation in tenant A is not visible in tenant B", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.rebac.addRelation, {
      tenantId: TENANT_A,
      subjectType: "user",
      subjectId: "user1",
      relation: "member",
      objectType: "team",
      objectId: "alpha",
    });

    const hasInA = await t.query(api.rebac.hasDirectRelation, {
      tenantId: TENANT_A,
      subjectType: "user",
      subjectId: "user1",
      relation: "member",
      objectType: "team",
      objectId: "alpha",
    });
    expect(hasInA).toBe(true);

    const hasInB = await t.query(api.rebac.hasDirectRelation, {
      tenantId: TENANT_B,
      subjectType: "user",
      subjectId: "user1",
      relation: "member",
      objectType: "team",
      objectId: "alpha",
    });
    expect(hasInB).toBe(false);
  });
});

describe("Cross-tenant indexed isolation", () => {
  it("indexed role/permission in tenant A is not visible in tenant B", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.indexed.assignRoleWithCompute, {
      tenantId: TENANT_A,
      userId: "user1",
      role: "admin",
      rolePermissions: ["documents:read", "documents:write"],
    });

    const canInA = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT_A,
      userId: "user1",
      permission: "documents:read",
    });
    expect(canInA).toBe(true);

    const canInB = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT_B,
      userId: "user1",
      permission: "documents:read",
    });
    expect(canInB).toBe(false);
  });
});

describe("Cleanup without tenantId cleans all", () => {
  it("cleanupExpired without tenantId removes expired roles from all tenants", async () => {
    const t = convexTest(schema, modules);

    const pastTime = Date.now() - 3600000;

    await t.mutation(api.mutations.assignRole, {
      tenantId: TENANT_A,
      userId: "user1",
      role: "expired-role-a",
      expiresAt: pastTime,
    });

    await t.mutation(api.mutations.assignRole, {
      tenantId: TENANT_B,
      userId: "user1",
      role: "expired-role-b",
      expiresAt: pastTime,
    });

    const result = await t.mutation(api.mutations.cleanupExpired, {});

    expect(result.expiredRoles).toBe(2);

    const rolesA = await t.query(api.queries.getUserRoles, {
      tenantId: TENANT_A,
      userId: "user1",
    });
    expect(rolesA).toHaveLength(0);

    const rolesB = await t.query(api.queries.getUserRoles, {
      tenantId: TENANT_B,
      userId: "user1",
    });
    expect(rolesB).toHaveLength(0);
  });
});

describe("Cleanup with tenantId scoped", () => {
  it("cleanupExpired with tenantId only removes expired roles from that tenant", async () => {
    const t = convexTest(schema, modules);

    const pastTime = Date.now() - 3600000;

    await t.mutation(api.mutations.assignRole, {
      tenantId: TENANT_A,
      userId: "user1",
      role: "expired-role-a",
      expiresAt: pastTime,
    });

    await t.mutation(api.mutations.assignRole, {
      tenantId: TENANT_B,
      userId: "user1",
      role: "expired-role-b",
      expiresAt: pastTime,
    });

    const result = await t.mutation(api.mutations.cleanupExpired, {
      tenantId: TENANT_A,
    });

    expect(result.expiredRoles).toBe(1);

    const remainingCleanup = await t.mutation(api.mutations.cleanupExpired, {
      tenantId: TENANT_B,
    });
    expect(remainingCleanup.expiredRoles).toBe(1);
  });

  it("indexed.cleanupExpired without tenantId cleans all tenants", async () => {
    const t = convexTest(schema, modules);

    const pastTime = Date.now() - 3600000;

    await t.mutation(api.indexed.assignRoleWithCompute, {
      tenantId: TENANT_A,
      userId: "user1",
      role: "admin",
      rolePermissions: ["documents:read"],
      expiresAt: pastTime,
    });

    await t.mutation(api.indexed.assignRoleWithCompute, {
      tenantId: TENANT_B,
      userId: "user1",
      role: "admin",
      rolePermissions: ["documents:read"],
      expiresAt: pastTime,
    });

    const result = await t.mutation(api.indexed.cleanupExpired, {});
    expect(result.expiredRoles).toBe(2);
    expect(result.expiredPermissions).toBe(2);
  });

  it("indexed.cleanupExpired with tenantId scoped to that tenant", async () => {
    const t = convexTest(schema, modules);

    const pastTime = Date.now() - 3600000;

    await t.mutation(api.indexed.assignRoleWithCompute, {
      tenantId: TENANT_A,
      userId: "user1",
      role: "admin",
      rolePermissions: ["documents:read"],
      expiresAt: pastTime,
    });

    await t.mutation(api.indexed.assignRoleWithCompute, {
      tenantId: TENANT_B,
      userId: "user1",
      role: "admin",
      rolePermissions: ["documents:read"],
      expiresAt: pastTime,
    });

    const result = await t.mutation(api.indexed.cleanupExpired, {
      tenantId: TENANT_A,
    });
    expect(result.expiredRoles).toBe(1);
    expect(result.expiredPermissions).toBe(1);

    const remaining = await t.mutation(api.indexed.cleanupExpired, {
      tenantId: TENANT_B,
    });
    expect(remaining.expiredRoles).toBe(1);
    expect(remaining.expiredPermissions).toBe(1);
  });
});
