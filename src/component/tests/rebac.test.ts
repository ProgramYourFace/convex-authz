/**
 * ReBAC tests - covers additional code paths
 */

import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "../schema.js";
import { api } from "../_generated/api.js";

const modules = import.meta.glob("../**/*.ts");
const TENANT = "test-tenant";

describe("ReBAC (Relationship-Based Access Control)", () => {
  describe("direct relationships", () => {
    it("should add a relationship", async () => {
      const t = convexTest(schema, modules);

      const relationId = await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(relationId).toBeDefined();
    });

    it("should return existing ID for duplicate relationship", async () => {
      const t = convexTest(schema, modules);

      const id1 = await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const id2 = await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(id2).toBe(id1);
    });

    it("should check a direct relationship", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const exists = await t.query(api.rebac.hasDirectRelation, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(exists).toBe(true);
    });

    it("should return false for non-existent relationship", async () => {
      const t = convexTest(schema, modules);

      const exists = await t.query(api.rebac.hasDirectRelation, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "owner",
        objectType: "team",
        objectId: "sales",
      });

      expect(exists).toBe(false);
    });

    it("should remove a relationship", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const removed = await t.mutation(api.unified.removeRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(removed).toBe(true);

      const exists = await t.query(api.rebac.hasDirectRelation, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(exists).toBe(false);
    });

    it("should return false when removing non-existent relationship", async () => {
      const t = convexTest(schema, modules);

      const removed = await t.mutation(api.unified.removeRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "nonexistent",
      });

      expect(removed).toBe(false);
    });

    it("should add relation with createdBy", async () => {
      const t = convexTest(schema, modules);

      const id = await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
        createdBy: "admin_user",
      });

      expect(id).toBeDefined();
    });

    it("should get all relationships for a subject", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "marketing",
      });

      const relations = await t.query(api.rebac.getSubjectRelations, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
      });

      expect(relations).toHaveLength(2);
    });

    it("should filter subject relations by objectType", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "project",
        objectId: "alpha",
      });

      const teamRelations = await t.query(api.rebac.getSubjectRelations, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        objectType: "team",
      });

      expect(teamRelations).toHaveLength(1);
      expect(teamRelations[0].objectType).toBe("team");
    });
  });

  describe("object relationships", () => {
    it("should get all subjects with relation to an object", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "bob",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const relations = await t.query(api.rebac.getObjectRelations, {
        tenantId: TENANT,
        objectType: "team",
        objectId: "sales",
      });

      expect(relations).toHaveLength(2);
      expect(
        relations.map((r: { subjectId: string }) => r.subjectId),
      ).toContain("alice");
      expect(
        relations.map((r: { subjectId: string }) => r.subjectId),
      ).toContain("bob");
    });

    it("should filter object relations by relation type", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "bob",
        relation: "admin",
        objectType: "team",
        objectId: "sales",
      });

      const members = await t.query(api.rebac.getObjectRelations, {
        tenantId: TENANT,
        objectType: "team",
        objectId: "sales",
        relation: "member",
      });

      expect(members).toHaveLength(1);
      expect(members[0].subjectId).toBe("alice");
    });
  });

  describe("relationship traversal", () => {
    it.skip("should traverse relationships with rules", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "team",
        subjectId: "sales",
        relation: "owner",
        objectType: "account",
        objectId: "acme",
      });

      const result = await t.query(api.rebac.checkRelationWithTraversal, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
        traversalRules: {
          "account:viewer": [
            { through: "team", via: "owner", inherit: "member" },
          ],
        },
      });

      expect(result.allowed).toBe(true);
      expect(result.path).toBeDefined();
    });

    it("should fail traversal when path doesn't exist", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "marketing",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "team",
        subjectId: "sales",
        relation: "owner",
        objectType: "account",
        objectId: "acme",
      });

      const result = await t.query(api.rebac.checkRelationWithTraversal, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
        traversalRules: {
          "account:viewer": [
            { through: "team", via: "owner", inherit: "member" },
          ],
        },
      });

      expect(result.allowed).toBe(false);
    });

    it.skip("should return false when no traversal rules and no direct relation", async () => {
      const t = convexTest(schema, modules);

      const result = await t.query(api.rebac.checkRelationWithTraversal, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe(
        "No direct relationship and no traversal rules provided",
      );
    });

    it.skip("should find direct relationship without traversal", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
      });

      const result = await t.query(api.rebac.checkRelationWithTraversal, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
      });

      expect(result.allowed).toBe(true);
      expect(result.reason).toBe("Direct relationship");
    });

    it("should respect maxDepth limit", async () => {
      const t = convexTest(schema, modules);

      // Create a deep chain: user -> team -> project -> account
      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "team",
        subjectId: "sales",
        relation: "owner",
        objectType: "project",
        objectId: "alpha",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "project",
        subjectId: "alpha",
        relation: "parent",
        objectType: "account",
        objectId: "acme",
      });

      // maxDepth=1 should not be able to traverse the full chain
      const result = await t.query(api.rebac.checkRelationWithTraversal, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
        traversalRules: {
          "account:viewer": [
            { through: "project", via: "parent", inherit: "viewer" },
          ],
          "project:viewer": [
            { through: "team", via: "owner", inherit: "member" },
          ],
        },
        maxDepth: 1,
      });

      expect(result.allowed).toBe(false);
    });

    it.skip("should enforce maxDepth strictly: depth-3 path fails with maxDepth 2, succeeds with maxDepth 3", async () => {
      const t = convexTest(schema, modules);

      // Chain: user -> team -> project -> account (need depth 3 to reach account)
      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });
      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "team",
        subjectId: "sales",
        relation: "owner",
        objectType: "project",
        objectId: "alpha",
      });
      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "project",
        subjectId: "alpha",
        relation: "parent",
        objectType: "account",
        objectId: "acme",
      });

      const rules = {
        "account:viewer": [
          { through: "project", via: "parent", inherit: "viewer" },
        ],
        "project:viewer": [
          { through: "team", via: "owner", inherit: "member" },
        ],
      };

      const withDepth2 = await t.query(api.rebac.checkRelationWithTraversal, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
        traversalRules: rules,
        maxDepth: 2,
      });
      expect(withDepth2.allowed).toBe(false);
      expect(withDepth2.reason).toBe("No relationship path found");

      const withDepth3 = await t.query(api.rebac.checkRelationWithTraversal, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
        traversalRules: rules,
        maxDepth: 3,
      });
      expect(withDepth3.allowed).toBe(true);
    });

    it("should return 'No relationship path found' when traversal finds nothing", async () => {
      const t = convexTest(schema, modules);

      const result = await t.query(api.rebac.checkRelationWithTraversal, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
        traversalRules: {
          "account:viewer": [
            { through: "team", via: "owner", inherit: "member" },
          ],
        },
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("No relationship path found");
    });

    it.skip("should accept maxBranching parameter and still traverse correctly", async () => {
      const t = convexTest(schema, modules);

      // Setup: user -[member]-> team, team -[owner]-> account
      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "team",
        subjectId: "sales",
        relation: "owner",
        objectType: "account",
        objectId: "acme",
      });

      // With maxBranching=1 the single parent is still found, access is granted
      const resultAllowed = await t.query(
        api.rebac.checkRelationWithTraversal,
        {
          tenantId: TENANT,
          subjectType: "user",
          subjectId: "alice",
          relation: "viewer",
          objectType: "account",
          objectId: "acme",
          traversalRules: {
            "account:viewer": [
              { through: "team", via: "owner", inherit: "member" },
            ],
          },
          maxBranching: 1,
        },
      );

      expect(resultAllowed.allowed).toBe(true);
      expect(resultAllowed.path).toBeDefined();

      // With maxBranching=0 no parents are fetched, access is denied
      const resultDenied = await t.query(api.rebac.checkRelationWithTraversal, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
        traversalRules: {
          "account:viewer": [
            { through: "team", via: "owner", inherit: "member" },
          ],
        },
        maxBranching: 0,
      });

      expect(resultDenied.allowed).toBe(false);
      expect(resultDenied.reason).toBe("No relationship path found");
    });
  });

  describe("batch operations", () => {
    it("should list accessible objects", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "marketing",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "project",
        objectId: "alpha",
      });

      const teams = await t.query(api.rebac.listAccessibleObjects, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
      });

      expect(teams).toHaveLength(2);
      expect(teams.every((t: { via: string }) => t.via === "effective")).toBe(
        true,
      );
    });

    it("should return empty for no accessible objects", async () => {
      const t = convexTest(schema, modules);

      const results = await t.query(api.rebac.listAccessibleObjects, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
      });

      expect(results).toHaveLength(0);
    });

    it("should list users with access to an object", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "bob",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      // This is not a user type, should be filtered out
      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "team",
        subjectId: "eng",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const users = await t.query(api.rebac.listUsersWithAccess, {
        tenantId: TENANT,
        objectType: "team",
        objectId: "sales",
        relation: "member",
      });

      expect(users).toHaveLength(2);
      expect(users.every((u: { via: string }) => u.via === "effective")).toBe(
        true,
      );
      expect(users.map((u: { userId: string }) => u.userId)).toContain("alice");
      expect(users.map((u: { userId: string }) => u.userId)).toContain("alice");
      expect(users.map((u: { userId: string }) => u.userId)).toContain("bob");
    });

    it("should return empty for no users with access", async () => {
      const t = convexTest(schema, modules);

      const results = await t.query(api.rebac.listUsersWithAccess, {
        tenantId: TENANT,
        objectType: "team",
        objectId: "nonexistent",
        relation: "member",
      });

      expect(results).toHaveLength(0);
    });
  });

  describe("traversal cycle detection", () => {
    it("should handle cycles in traversal without infinite loops", async () => {
      const t = convexTest(schema, modules);

      // Create a cycle: A -[parent]-> B -[parent]-> A
      // Neither has a direct relation from the user
      // This forces the BFS to visit A, then B, then try A again (hitting visited check)

      // Setup: team -[parent]-> project, project -[parent]-> team (cycle)
      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "team",
        subjectId: "alpha_team",
        relation: "parent",
        objectType: "project",
        objectId: "proj_x",
      });

      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "project",
        subjectId: "proj_x",
        relation: "parent",
        objectType: "team",
        objectId: "alpha_team",
      });

      // User has NO relation to either - traversal should exhaust the cycle
      const result = await t.query(api.rebac.checkRelationWithTraversal, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "nobody",
        relation: "viewer",
        objectType: "project",
        objectId: "proj_x",
        traversalRules: {
          "project:viewer": [
            { through: "team", via: "parent", inherit: "member" },
          ],
          "team:member": [
            { through: "project", via: "parent", inherit: "viewer" },
          ],
        },
        maxDepth: 10,
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("No relationship path found");
    });
  });
});
