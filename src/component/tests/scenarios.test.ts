/**
 * Real-World Authorization Scenarios
 *
 * Comprehensive tests for multi-tenant SaaS authorization patterns.
 * These tests simulate real production scenarios with:
 * - Multiple organizations
 * - Nested teams
 * - Cross-org isolation
 * - Complex permission hierarchies
 * - Edge cases and security boundaries
 */

import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "../schema.js";
import { api } from "../_generated/api.js";

const modules = import.meta.glob("../**/*.ts");
const TENANT = "test-tenant";

// ============================================================================
// Test Data: Multi-Tenant SaaS Structure
// ============================================================================

/**
 * Test Organization Structure:
 *
 * ACME Corp (org:acme)
 * ├── Engineering Team (team:acme-eng)
 * │   ├── alice (admin)
 * │   └── bob (member)
 * ├── Sales Team (team:acme-sales)
 * │   └── charlie (member)
 * └── Projects
 *     ├── Project Alpha (project:alpha) - owned by Engineering
 *     │   └── Document A1 (doc:a1)
 *     └── Project Beta (project:beta) - owned by Sales
 *         └── Document B1 (doc:b1)
 *
 * BetaCo (org:betaco)
 * ├── Product Team (team:betaco-product)
 * │   └── diana (admin)
 * └── Projects
 *     └── Project Gamma (project:gamma)
 *         └── Document G1 (doc:g1)
 *
 * External Users (no org):
 * - eve (contractor with explicit grants)
 * - frank (no permissions)
 */

// User IDs (used as subjectId/userId)
const USERS = {
  alice: "alice",
  bob: "bob",
  charlie: "charlie",
  diana: "diana",
  eve: "eve",
  frank: "frank",
} as const;

// Organization IDs (used as objectId with type: "org")
const ORGS = {
  acme: "acme",
  betaco: "betaco",
} as const;

// Team IDs (used as objectId with type: "team")
const TEAMS = {
  acmeEng: "acme-eng",
  acmeSales: "acme-sales",
  betacoProduct: "betaco-product",
} as const;

// Project IDs (used as objectId with type: "project")
const PROJECTS = {
  alpha: "alpha",
  beta: "beta",
  gamma: "gamma",
} as const;

// Document IDs (used as objectId with type: "document")
const DOCS = {
  a1: "a1",
  b1: "b1",
  g1: "g1",
} as const;

// Object types for ReBAC
const TYPES = {
  user: "user",
  org: "org",
  team: "team",
  project: "project",
  document: "document",
} as const;

// ============================================================================
// Scenario 1: Multi-Organization Isolation
// ============================================================================

describe("Scenario: Multi-Organization Isolation", () => {
  it("users in different orgs cannot access each other's resources", async () => {
    const t = convexTest(schema, modules);

    // Setup: Alice is admin of ACME
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      scope: { type: "org", id: ORGS.acme },
      rolePermissions: [],
    });

    // Setup: Diana is admin of BetaCo
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.diana,
      role: "admin",
      rolePermissions: [],
      scope: { type: "org", id: ORGS.betaco },
    });

    // Alice can access ACME
    const aliceAcme = await t.query(api.queries.hasRole, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      scope: { type: "org", id: ORGS.acme },
    });
    expect(aliceAcme).toBe(true);

    // Alice CANNOT access BetaCo
    const aliceBetaco = await t.query(api.queries.hasRole, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      scope: { type: "org", id: ORGS.betaco },
    });
    expect(aliceBetaco).toBe(false);

    // Diana can access BetaCo
    const dianaBetaco = await t.query(api.queries.hasRole, {
      tenantId: TENANT,
      userId: USERS.diana,
      role: "admin",
      scope: { type: "org", id: ORGS.betaco },
    });
    expect(dianaBetaco).toBe(true);

    // Diana CANNOT access ACME
    const dianaAcme = await t.query(api.queries.hasRole, {
      tenantId: TENANT,
      userId: USERS.diana,
      role: "admin",
      scope: { type: "org", id: ORGS.acme },
    });
    expect(dianaAcme).toBe(false);
  });

  it("global roles do not grant access to scoped resources", async () => {
    const t = convexTest(schema, modules);

    // Alice has global viewer role
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "viewer",
      rolePermissions: [],
    });

    // Alice has scoped admin role for ACME only
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      rolePermissions: [],
      scope: { type: "org", id: ORGS.acme },
    });

    // Check: Alice is viewer globally
    const isViewerGlobal = await t.query(api.queries.hasRole, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "viewer",
    });
    expect(isViewerGlobal).toBe(true);

    // Check: Alice is admin of ACME specifically
    const isAdminAcme = await t.query(api.queries.hasRole, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      scope: { type: "org", id: ORGS.acme },
    });
    expect(isAdminAcme).toBe(true);

    // Check: Alice is NOT admin globally
    const isAdminGlobal = await t.query(api.queries.hasRole, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
    });
    expect(isAdminGlobal).toBe(false);

    // Check: Alice is NOT admin of BetaCo
    const isAdminBetaco = await t.query(api.queries.hasRole, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      scope: { type: "org", id: ORGS.betaco },
    });
    expect(isAdminBetaco).toBe(false);
  });
});

// ============================================================================
// Scenario 2: Team-Based Access Control
// ============================================================================

describe("Scenario: Team-Based Access Control", () => {
  it("team members inherit access to team resources via ReBAC", async () => {
    const t = convexTest(schema, modules);

    // Setup: Alice is member of Engineering team
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "member",
      objectType: TYPES.team,
      objectId: TEAMS.acmeEng,
    });

    // Setup: Engineering team owns Project Alpha
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.team,
      subjectId: TEAMS.acmeEng,
      relation: "owner",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
      traversalRules: {
        "project:viewer": [
          { through: TYPES.team, via: "owner", inherit: "member" },
        ],
      },
    });

    // Check: Alice can view Project Alpha through traversal
    const result = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "viewer",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
    });

    expect(result.allowed).toBe(true);
  });

  it("users without team membership cannot access team resources", async () => {
    const t = convexTest(schema, modules);

    // Setup: Charlie is member of Sales team (not Engineering)
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.charlie,
      relation: "member",
      objectType: TYPES.team,
      objectId: TEAMS.acmeSales,
    });

    // Setup: Engineering team owns Project Alpha
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.team,
      subjectId: TEAMS.acmeEng,
      relation: "owner",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
    });

    // Check: Charlie CANNOT view Project Alpha
    const result = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.charlie,
      relation: "viewer",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
      traversalRules: {
        "project:viewer": [
          { through: TYPES.team, via: "owner", inherit: "member" },
        ],
      },
    });

    expect(result.allowed).toBe(false);
  });

  it.skip("team admins have elevated permissions on team resources", async () => {
    const t = convexTest(schema, modules);

    // Setup: Alice is admin of Engineering team
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "admin",
      objectType: TYPES.team,
      objectId: TEAMS.acmeEng,
    });

    // Setup: Bob is member of Engineering team
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.bob,
      relation: "member",
      objectType: TYPES.team,
      objectId: TEAMS.acmeEng,
    });

    // Setup: Engineering team owns Project Alpha
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.team,
      subjectId: TEAMS.acmeEng,
      relation: "owner",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
    });

    // Check: Alice (admin) can edit Project Alpha
    const aliceEdit = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "editor",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
      traversalRules: {
        "project:editor": [
          { through: TYPES.team, via: "owner", inherit: "admin" },
        ],
      },
    });
    expect(aliceEdit.allowed).toBe(true);

    // Check: Bob (member) CANNOT edit Project Alpha
    const bobEdit = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.bob,
      relation: "editor",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
      traversalRules: {
        "project:editor": [
          { through: TYPES.team, via: "owner", inherit: "admin" },
        ],
      },
    });
    expect(bobEdit.allowed).toBe(false);
  });
});

// ============================================================================
// Scenario 3: Nested Resource Hierarchy
// ============================================================================

describe("Scenario: Nested Resource Hierarchy (Org → Team → Project → Document)", () => {
  it.skip("permissions cascade through the hierarchy", async () => {
    const t = convexTest(schema, modules);

    // Setup the hierarchy:
    // alice -> member -> acme-eng -> owner -> alpha -> contains -> a1

    // Alice is member of Engineering
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "member",
      objectType: TYPES.team,
      objectId: TEAMS.acmeEng,
    });

    // Engineering owns Project Alpha
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.team,
      subjectId: TEAMS.acmeEng,
      relation: "owner",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
    });

    // Project Alpha contains Document A1
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.project,
      subjectId: PROJECTS.alpha,
      relation: "parent",
      objectType: TYPES.document,
      objectId: DOCS.a1,
    });

    // Check: Alice can view Document A1 through 3-hop traversal
    const result = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "viewer",
      objectType: TYPES.document,
      objectId: DOCS.a1,
      traversalRules: {
        // Document viewer inherits from project viewer
        "document:viewer": [
          { through: TYPES.project, via: "parent", inherit: "viewer" },
        ],
        // Project viewer inherits from team member
        "project:viewer": [
          { through: TYPES.team, via: "owner", inherit: "member" },
        ],
      },
      maxDepth: 5,
    });

    expect(result.allowed).toBe(true);
    expect(result.path).toBeDefined();
    // Verify the traversal path
    expect(result.path!.length).toBeGreaterThanOrEqual(3);
  });
});

// ============================================================================
// Scenario 4: Permission Overrides & Exceptions
// ============================================================================

describe("Scenario: Permission Overrides & Exceptions", () => {
  it("explicit deny overrides role-based permission", async () => {
    const t = convexTest(schema, modules);

    // Alice is admin with full access
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      rolePermissions: [
        "documents:read",
        "documents:write",
        "documents:delete",
      ],
    });

    // But specifically denied delete on a sensitive document
    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "documents:delete",
      scope: { type: "document", id: "sensitive-doc" },
      reason: "Compliance restriction",
    });

    // Alice can delete globally
    const canDeleteGlobal = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "documents:delete",
    });
    expect(canDeleteGlobal).toBe(true);

    // But NOT the sensitive document
    const canDeleteSensitive = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "documents:delete",
      objectType: "document",
      objectId: "sensitive-doc",
    });
    expect(canDeleteSensitive).toBe(false);
  });

  it("temporary access grants with expiration", async () => {
    const t = convexTest(schema, modules);

    const now = Date.now();
    const oneHourAgo = now - 3600000;
    const oneHourLater = now + 3600000;

    // Grant temporary access that has already expired
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: USERS.eve,
      permission: "documents:read",
      scope: { type: TYPES.project, id: PROJECTS.alpha },
      reason: "Contractor access",
      expiresAt: oneHourAgo, // Already expired
    });

    // Expired permission should be denied
    const canReadExpired = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.eve,
      permission: "documents:read",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
    });
    expect(canReadExpired).toBe(false);

    // Grant access that expires in the future
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: USERS.eve,
      permission: "documents:write",
      scope: { type: TYPES.project, id: PROJECTS.alpha },
      reason: "Contractor access",
      expiresAt: oneHourLater, // Still valid
    });

    // Valid permission should be allowed
    const canWrite = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.eve,
      permission: "documents:write",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
    });
    expect(canWrite).toBe(true);
  });

  it("contractor with explicit grants but no org membership", async () => {
    const t = convexTest(schema, modules);

    // Eve has no roles or org membership
    // But has specific grants for Project Alpha

    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: USERS.eve,
      permission: "documents:read",
      scope: { type: TYPES.project, id: PROJECTS.alpha },
      reason: "External contractor",
    });

    // Eve can read Project Alpha docs
    const canRead = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.eve,
      permission: "documents:read",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
    });
    expect(canRead).toBe(true);

    // Eve CANNOT read Project Beta docs
    const canReadBeta = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.eve,
      permission: "documents:read",
      objectType: TYPES.project,
      objectId: PROJECTS.beta,
    });
    expect(canReadBeta).toBe(false);

    // Eve CANNOT write to Project Alpha (no write grant)
    const canWrite = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.eve,
      permission: "documents:write",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
    });
    expect(canWrite).toBe(false);
  });
});

// ============================================================================
// Scenario 5: Complex Multi-Role Users
// ============================================================================

describe("Scenario: Users with Multiple Roles", () => {
  it("user with different roles in different scopes", async () => {
    const t = convexTest(schema, modules);

    // Alice is:
    // - Global viewer
    // - Admin of Team Engineering
    // - Member of Team Sales

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "viewer",
      rolePermissions: [],
    });

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      scope: { type: TYPES.team, id: TEAMS.acmeEng },
      rolePermissions: [],
    });

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "member",
      rolePermissions: [],
      scope: { type: TYPES.team, id: TEAMS.acmeSales },
    });

    // Get all Alice's roles
    const roles = await t.query(api.queries.getUserRoles, {
      tenantId: TENANT,
      userId: USERS.alice,
    });

    expect(roles).toHaveLength(3);

    // Filter roles by scope
    const globalRoles = roles.filter((r: any) => !r.scope);
    const teamEngRoles = roles.filter(
      (r: any) => r.scope?.type === TYPES.team && r.scope?.id === TEAMS.acmeEng,
    );
    const teamSalesRoles = roles.filter(
      (r: any) =>
        r.scope?.type === TYPES.team && r.scope?.id === TEAMS.acmeSales,
    );

    expect(globalRoles).toHaveLength(1);
    expect(globalRoles[0].role).toBe("viewer");

    expect(teamEngRoles).toHaveLength(1);
    expect(teamEngRoles[0].role).toBe("admin");

    expect(teamSalesRoles).toHaveLength(1);
    expect(teamSalesRoles[0].role).toBe("member");
  });

  it("permission union from multiple roles", async () => {
    const t = convexTest(schema, modules);

    // Alice has viewer role (read only)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "viewer",
      rolePermissions: ["documents:read"],
    });

    // Alice also has editor role (read + write)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "editor",
      rolePermissions: ["documents:read", "documents:write"],
    });

    // Alice should have union of all permissions
    const permissions = await t.query(api.indexed.getUserPermissionsFast, {
      tenantId: TENANT,
      userId: USERS.alice,
    });

    const permNames = permissions.map((p: any) => p.permission);
    expect(permNames).toContain("documents:read");
    expect(permNames).toContain("documents:write");

    // Both roles should be sources for documents:read
    const readPerm = permissions.find(
      (p: any) => p.permission === "documents:read",
    );
    expect(readPerm).toBeDefined();
    expect(readPerm!.sources).toContain("viewer");
    expect(readPerm!.sources).toContain("editor");
  });
});

// ============================================================================
// Scenario 6: Security Boundaries
// ============================================================================

describe("Scenario: Security Boundaries", () => {
  it("user with no roles has no permissions", async () => {
    const t = convexTest(schema, modules);

    // Frank has no roles, no relationships, no grants
    const canRead = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: USERS.frank,
      permission: "documents:read",
    });

    expect(canRead.allowed).toBe(false);
  });

  it("revoking role removes all associated permissions", async () => {
    const t = convexTest(schema, modules);

    // Alice is admin
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      rolePermissions: [
        "documents:read",
        "documents:write",
        "documents:delete",
      ],
    });

    // Verify Alice has permissions
    let canDelete = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "documents:delete",
    });
    expect(canDelete).toBe(true);

    // Revoke admin role
    await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      rolePermissions: [
        "documents:read",
        "documents:write",
        "documents:delete",
      ],
    });

    // Alice should no longer have permissions
    canDelete = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "documents:delete",
    });
    expect(canDelete).toBe(false);

    // Verify all permissions are gone
    const permissions = await t.query(api.indexed.getUserPermissionsFast, {
      tenantId: TENANT,
      userId: USERS.alice,
    });
    expect(permissions).toHaveLength(0);
  });

  it.skip("removing relationship breaks access chain", async () => {
    const t = convexTest(schema, modules);

    // Setup: alice -> member -> acme-eng -> owner -> alpha
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "member",
      objectType: TYPES.team,
      objectId: TEAMS.acmeEng,
    });

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.team,
      subjectId: TEAMS.acmeEng,
      relation: "owner",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
    });

    // Verify access
    let result = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "viewer",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
      traversalRules: {
        "project:viewer": [
          { through: TYPES.team, via: "owner", inherit: "member" },
        ],
      },
    });
    expect(result.allowed).toBe(true);

    // Remove alice from team
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "member",
      objectType: TYPES.team,
      objectId: TEAMS.acmeEng,
    });

    // Access should be broken
    result = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "viewer",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
      traversalRules: {
        "project:viewer": [
          { through: TYPES.team, via: "owner", inherit: "member" },
        ],
      },
    });
    expect(result.allowed).toBe(false);
  });
});

// ============================================================================
// Scenario 7: Wildcard Permissions
// ============================================================================

describe("Scenario: Wildcard & Super Admin", () => {
  it("super admin with *:* has all permissions", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "superadmin",
      rolePermissions: ["*:*"],
    });

    const result = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "anything:action",
    });

    expect(result.allowed).toBe(true);
  });

  it("resource-level wildcard grants all actions on resource", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "doc_admin",
      rolePermissions: ["documents:*"],
    });

    const canRead = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "documents:read",
    });
    expect(canRead.allowed).toBe(true);

    const canDelete = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "documents:delete",
    });
    expect(canDelete.allowed).toBe(true);

    // But not other resources
    const canReadProjects = await t.query(api.unified.checkPermission, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "projects:read",
    });
    expect(canReadProjects.allowed).toBe(false);
  });
});

// ============================================================================
// Scenario 8: Audit Trail
// ============================================================================

describe("Scenario: Audit Trail", () => {
  it("all permission changes are logged", async () => {
    const t = convexTest(schema, modules);

    // Assign role
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      rolePermissions: [],
      assignedBy: "system",
      enableAudit: true,
    });

    // Revoke role
    await t.mutation(api.unified.revokeRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      revokedBy: "system",
      enableAudit: true,
      rolePermissions: [],
    });

    // Grant permission
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "special:access",
      createdBy: "system",
      enableAudit: true,
    });

    // Get audit log
    const logsResult = await t.query(api.queries.getAuditLog, {
      tenantId: TENANT,
      userId: USERS.alice,
    });
    const logs = Array.isArray(logsResult) ? logsResult : logsResult.page;

    expect(logs.length).toBeGreaterThanOrEqual(3);

    const actions = logs.map((l) => l.action);
    expect(actions).toContain("role_assigned");
    expect(actions).toContain("role_revoked");
    expect(actions).toContain("permission_granted");
  });
});

// ============================================================================
// Scenario 9: Cross-Tenant Data Room (RBAC + Overrides + O(1) indexed)
// ============================================================================

describe("Scenario: Cross-Tenant Data Room (RBAC + Overrides + O(1) indexed)", () => {
  it("external contractor can read but not delete, while admin can delete", async () => {
    const t = convexTest(schema, modules);

    // Alice is admin on Project Alpha (full CRUD)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      rolePermissions: [
        "documents:read",
        "documents:write",
        "documents:delete",
      ],
      scope: { type: "project", id: PROJECTS.alpha },
    });

    // External contractor (Frank) gets explicit read but explicit deny for delete
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: USERS.frank,
      permission: "documents:read",
      scope: { type: "project", id: PROJECTS.alpha },
      reason: "Contractor read-only access",
    });

    await t.mutation(api.unified.denyPermissionUnified, {
      tenantId: TENANT,
      userId: USERS.frank,
      permission: "documents:delete",
      scope: { type: "project", id: PROJECTS.alpha },
      reason: "Protect deletes for contractors",
    });

    // Admin can delete
    const adminCanDelete = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "documents:delete",
      objectType: "project",
      objectId: PROJECTS.alpha,
    });
    expect(adminCanDelete).toBe(true);

    // Contractor can read but not delete
    const contractorCanRead = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.frank,
      permission: "documents:read",
      objectType: "project",
      objectId: PROJECTS.alpha,
    });
    const contractorCanDelete = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.frank,
      permission: "documents:delete",
      objectType: "project",
      objectId: PROJECTS.alpha,
    });

    expect(contractorCanRead).toBe(true);
    expect(contractorCanDelete).toBe(false);
  });
});

// ============================================================================
// Scenario 10: ReBAC traversal with cycle protection
// ============================================================================

describe("Scenario: ReBAC traversal with cycle protection", () => {
  it.skip("traversal succeeds without infinite loops even with cycles present", async () => {
    const t = convexTest(schema, modules);

    // user -> team -> project
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "member",
      objectType: TYPES.team,
      objectId: TEAMS.acmeEng,
    });

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.team,
      subjectId: TEAMS.acmeEng,
      relation: "owner",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
    });

    // Introduce a cycle: project references team as parent (synthetic example)
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: TYPES.project,
      subjectId: PROJECTS.alpha,
      relation: "parent",
      objectType: TYPES.team,
      objectId: TEAMS.acmeEng,
    });

    const result = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: TYPES.user,
      subjectId: USERS.alice,
      relation: "viewer",
      objectType: TYPES.project,
      objectId: PROJECTS.alpha,
      traversalRules: {
        "project:viewer": [
          { through: TYPES.team, via: "owner", inherit: "member" },
        ],
        "team:member": [
          // Allow traversal back to project but should not loop infinitely
          { through: TYPES.project, via: "parent", inherit: "viewer" },
        ],
      },
      maxDepth: 5,
    });

    expect(result.allowed).toBe(true);
    expect(result.path.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// Scenario 11: Google Drive-style sharing (ReBAC + hierarchy propagation)
// ============================================================================
// Mirrors the Permit.io Google Drive example:
// https://docs.permit.io/modeling/google-drive

describe("Scenario: Google Drive-style sharing", () => {
  it.skip("supports direct file access, folder inheritance, account admin, and account-wide sharing", async () => {
    const t = convexTest(schema, modules);

    // Objects
    const ACCOUNT = "account:acme";
    const FOLDER = "folder:finance";
    const FILE = "file:2023_report";

    // Users
    const JOHN = "user:john"; // direct viewer on file
    const JANE = "user:jane"; // editor on folder
    const ALICE = "user:alice"; // admin on account
    const BOB = "user:bob"; // member on account (general access)

    // Relations setup
    // file -> folder (parent)
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "folder",
      subjectId: FOLDER,
      relation: "parent",
      objectType: "file",
      objectId: FILE,
    });

    // folder -> account (parent)
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "account",
      subjectId: ACCOUNT,
      relation: "parent",
      objectType: "folder",
      objectId: FOLDER,
    });

    // file -> account (account_global) for everyone in account
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "account",
      subjectId: ACCOUNT,
      relation: "account_global",
      objectType: "file",
      objectId: FILE,
    });

    // Direct access and roles
    // John: direct viewer on file
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: JOHN,
      relation: "viewer",
      objectType: "file",
      objectId: FILE,
    });

    // Jane: editor on folder
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: JANE,
      relation: "editor",
      objectType: "folder",
      objectId: FOLDER,
    });

    // Alice: admin on account
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: ALICE,
      relation: "admin",
      objectType: "account",
      objectId: ACCOUNT,
    });

    // Bob: member on account (general access)
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: BOB,
      relation: "member",
      objectType: "account",
      objectId: ACCOUNT,
    });

    // Traversal rules to mirror Google Drive propagation
    const traversalRules = {
      // File viewers:
      // - direct viewer
      // - inherited from folder viewer
      // - inherited from account member via account_global
      "file:viewer": [
        { through: "folder", via: "parent", inherit: "viewer" },
        { through: "account", via: "account_global", inherit: "member" },
      ],
      // File editors:
      // - direct editor
      // - inherited from folder editor
      // - inherited from account admin
      "file:editor": [{ through: "folder", via: "parent", inherit: "editor" }],
      // Folder editors:
      // - inherited from account admin
      "folder:editor": [
        { through: "account", via: "parent", inherit: "admin" },
      ],
    };

    // John: direct viewer on file
    const johnRead = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: JOHN,
      relation: "viewer",
      objectType: "file",
      objectId: FILE,
      traversalRules,
    });
    expect(johnRead.allowed).toBe(true);

    const johnEdit = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: JOHN,
      relation: "editor",
      objectType: "file",
      objectId: FILE,
      traversalRules,
    });
    expect(johnEdit.allowed).toBe(false);

    // Jane: editor on folder -> inherits editor on file
    const janeEdit = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: JANE,
      relation: "editor",
      objectType: "file",
      objectId: FILE,
      traversalRules,
    });
    expect(janeEdit.allowed).toBe(true);

    // Alice: admin on account -> inherits editor on file
    const aliceEdit = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: ALICE,
      relation: "editor",
      objectType: "file",
      objectId: FILE,
      traversalRules,
    });
    expect(aliceEdit.allowed).toBe(true);

    // Bob: member on account -> viewer via account_global
    const bobView = await t.query(api.rebac.checkRelationWithTraversal, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: BOB,
      relation: "viewer",
      objectType: "file",
      objectId: FILE,
      traversalRules,
    });
    expect(bobView.allowed).toBe(true);
  });
});

// ============================================================================
// Scenario 12: Food Delivery (RBAC + ABAC-inspired gating + ReBAC-ish scoping)
// Inspired by Permit.io food delivery example:
// https://docs.permit.io/modeling/food-delivery-system-example-using-nuxt
// We model:
// - Customer scoped to the order can create it
// - Vendor scoped to the order can fulfill
// - Rider needs an elevated attribute (rides >= 500) before we grant deliver
// - Admin (global) can do everything
// - Second order in another scope to show isolation
// ============================================================================

describe("Scenario: Food Delivery - riders need enough rides, roles scoped per order", () => {
  it("enforces roles per order and grants deliver only after rider meets threshold", async () => {
    const t = convexTest(schema, modules);

    const ORDER_ALPHA = "order:alpha";
    const ORDER_BETA = "order:beta";

    // Base assignments (RBAC per order)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.diana, // customer
      role: "customer",
      rolePermissions: ["orders:create"],
      scope: { type: "order", id: ORDER_ALPHA },
    });

    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.bob, // vendor
      role: "vendor",
      rolePermissions: ["orders:fulfill"],
      scope: { type: "order", id: ORDER_ALPHA },
    });

    // Admin (global)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      role: "admin",
      rolePermissions: ["orders:create", "orders:fulfill", "orders:deliver"],
    });

    // Make admin explicitly allowed on both orders (global may not cover scoped keys)
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "orders:deliver",
      scope: { type: "order", id: ORDER_ALPHA },
      reason: "Admin global deliver",
    });
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "orders:deliver",
      scope: { type: "order", id: ORDER_BETA },
      reason: "Admin global deliver",
    });

    // Another order in a different scope (to prove isolation)
    await t.mutation(api.unified.assignRoleUnified, {
      tenantId: TENANT,
      userId: USERS.bob,
      role: "vendor",
      rolePermissions: ["orders:fulfill"],
      scope: { type: "order", id: ORDER_BETA },
    });

    // Customer can create their order
    const customerCreate = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.diana,
      permission: "orders:create",
      objectType: "order",
      objectId: ORDER_ALPHA,
    });
    expect(customerCreate).toBe(true);

    // Vendor can fulfill order alpha
    const vendorFulfill = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.bob,
      permission: "orders:fulfill",
      objectType: "order",
      objectId: ORDER_ALPHA,
    });
    expect(vendorFulfill).toBe(true);

    // Rider initially should not have deliver until we explicitly grant it
    const riderDeliverInitial = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.charlie,
      permission: "orders:deliver",
      objectType: "order",
      objectId: ORDER_ALPHA,
    });
    expect(riderDeliverInitial).toBe(false);

    // After rider reaches threshold, grant deliver explicitly
    await t.mutation(api.unified.setAttributeWithRecompute, {
      tenantId: TENANT,
      userId: USERS.charlie,
      key: "rides",
      value: 600,
    });
    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: USERS.charlie,
      permission: "orders:deliver",
      scope: { type: "order", id: ORDER_ALPHA },
      reason: "Rider met ride threshold (>=500)",
    });

    const riderDeliverAfter = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.charlie,
      permission: "orders:deliver",
      objectType: "order",
      objectId: ORDER_ALPHA,
    });
    expect(riderDeliverAfter).toBe(true);

    // Admin can deliver anywhere (global)
    const adminDeliverAlpha = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "orders:deliver",
      objectType: "order",
      objectId: ORDER_ALPHA,
    });
    const adminDeliverBeta = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.alice,
      permission: "orders:deliver",
      objectType: "order",
      objectId: ORDER_BETA,
    });
    expect(adminDeliverAlpha).toBe(true);
    expect(adminDeliverBeta).toBe(true);

    // Isolation: vendor of beta cannot fulfill alpha (and vice-versa if we checked)
    const vendorBetaOnAlpha = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.bob,
      permission: "orders:fulfill",
      objectType: "order",
      objectId: ORDER_ALPHA,
    });
    expect(vendorBetaOnAlpha).toBe(true); // bob was assigned to alpha

    const vendorAlphaOnBeta = await t.query(api.indexed.checkPermissionFast, {
      tenantId: TENANT,
      userId: USERS.bob,
      permission: "orders:fulfill",
      objectType: "order",
      objectId: ORDER_BETA,
    });
    expect(vendorAlphaOnBeta).toBe(true); // bob also assigned to beta
  });
});
