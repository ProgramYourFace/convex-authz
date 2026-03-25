import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "../schema.js";
import { api } from "../_generated/api.js";
import {
  Authz,
  definePermissions,
  defineRoles,
  defineTraversalRules,
  defineRelationPermissions,
  defineCaveats,
} from "../../client/index.js";

const modules = import.meta.glob("../**/*.ts");
const TENANT = "test-tenant";

const permissions = definePermissions({
  documents: { read: true, write: true },
});

const roles = defineRoles(permissions, {});

const traversalRules = defineTraversalRules({
  "document:viewer": [{ through: "folder", via: "parent", inherit: "viewer" }],
});

const relationPermissions = defineRelationPermissions({
  "document:viewer": ["documents:read"],
});

const caveats = defineCaveats({
  isWorkHours: ({ caveatContext }) => {
    return (caveatContext as any)?.isWorkHours === "yes";
  },
});

describe("ReBAC Transitive Closures and Caveats", () => {
  it("should evaluate a transitive relationship and properly handle caveats during .canWithContext", async () => {
    const t = convexTest(schema, modules);

    // Pass traversalRules and relationPermissions to mock client methods
    const authz = new Authz(api as any, {
      permissions,
      roles,
      tenantId: TENANT,
      traversalRules,
      relationPermissions,
      caveats,
    });

    // 1. Create a folder parent relationship for a document
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "folder",
      subjectId: "folder_1",
      relation: "parent",
      objectType: "document",
      objectId: "doc_1",
      traversalRules,
      relationPermissions,
    });

    // 2. Add user to the folder with a caveat
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "viewer",
      objectType: "folder",
      objectId: "folder_1",
      caveat: "isWorkHours",
      traversalRules,
      relationPermissions,
    });

    // Check standard `can` without context, should fail since it requires work hours caveat to pass
    const ctx = {
      runQuery: (q: any, args: any) => t.query(q, args),
      runMutation: (m: any, args: any) => t.mutation(m, args),
    };

    const canReadWithoutContext = await authz.can(
      ctx as any,
      "user_1",
      "documents:read",
      { type: "document", id: "doc_1" },
    );
    expect(canReadWithoutContext).toBe(false);

    // Check with caveatContext matching
    const canReadWithContext = await authz.canWithContext(
      ctx as any,
      "user_1",
      "documents:read",
      { type: "document", id: "doc_1" },
      { isWorkHours: "yes" },
    );
    expect(canReadWithContext).toBe(true);

    // Check with caveatContext failing
    const canReadWithWrongContext = await authz.canWithContext(
      ctx as any,
      "user_1",
      "documents:read",
      { type: "document", id: "doc_1" },
      { isWorkHours: "no" },
    );
    expect(canReadWithWrongContext).toBe(false);
  });

  it("should cascade deletes when a base relationship is removed", async () => {
    const t = convexTest(schema, modules);
    const authz = new Authz(api as any, {
      permissions,
      roles,
      tenantId: TENANT,
      traversalRules,
      relationPermissions,
      caveats,
    });

    // 1. User is viewer of folder
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_2",
      relation: "viewer",
      objectType: "folder",
      objectId: "folder_2",
      traversalRules,
      relationPermissions,
    });

    // 2. Folder is parent of doc
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "folder",
      subjectId: "folder_2",
      relation: "parent",
      objectType: "document",
      objectId: "doc_2",
      traversalRules,
      relationPermissions,
    });

    const ctx = {
      runQuery: (q: any, args: any) => t.query(q, args),
      runMutation: (m: any, args: any) => t.mutation(m, args),
    };

    // User can read doc_2
    expect(
      await authz.can(ctx as any, "user_2", "documents:read", {
        type: "document",
        id: "doc_2",
      }),
    ).toBe(true);

    // 3. Remove the parent relation
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "folder",
      subjectId: "folder_2",
      relation: "parent",
      objectType: "document",
      objectId: "doc_2",
      traversalRules,
      relationPermissions,
    });

    // User can NO LONGER read doc_2
    expect(
      await authz.can(ctx as any, "user_2", "documents:read", {
        type: "document",
        id: "doc_2",
      }),
    ).toBe(false);
  });

  it.skip("should handle multiple paths with at least 3 hops and caveats, updating properly when paths are removed", async () => {
    const t = convexTest(schema, modules);
    const myTraversalRules = defineTraversalRules({
      "document:viewer": [
        { through: "folder", via: "parent", inherit: "viewer" },
      ],
      "folder:viewer": [{ through: "group", via: "parent", inherit: "viewer" }],
    });

    const authz = new Authz(api as any, {
      permissions,
      roles,
      tenantId: TENANT,
      traversalRules: myTraversalRules,
      relationPermissions,
      caveats,
    });

    const ctx = {
      runQuery: (q: any, args: any) => t.query(q, args),
      runMutation: (m: any, args: any) => t.mutation(m, args),
    };

    // Path 1: user_3 -> group_1 -> folder_1 -> doc_3 (with caveat on folder_1 -> doc_3)
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "folder",
      subjectId: "folder_1",
      relation: "parent",
      objectType: "document",
      objectId: "doc_3",
      caveat: "isWorkHours",
      traversalRules: myTraversalRules,
      relationPermissions,
    });
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "group",
      subjectId: "group_1",
      relation: "parent",
      objectType: "folder",
      objectId: "folder_1",
      traversalRules: myTraversalRules,
      relationPermissions,
    });
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_3",
      relation: "viewer",
      objectType: "group",
      objectId: "group_1",
      traversalRules: myTraversalRules,
      relationPermissions,
    });

    // User can read doc_3 if work hours
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_3",
        "documents:read",
        { type: "document", id: "doc_3" },
        { isWorkHours: "yes" },
      ),
    ).toBe(true);
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_3",
        "documents:read",
        { type: "document", id: "doc_3" },
        { isWorkHours: "no" },
      ),
    ).toBe(false);

    // Path 2: user_3 -> group_2 -> folder_2 -> doc_3 (no caveats on this path!)
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "folder",
      subjectId: "folder_2",
      relation: "parent",
      objectType: "document",
      objectId: "doc_3",
      traversalRules: myTraversalRules,
      relationPermissions,
    });
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "group",
      subjectId: "group_2",
      relation: "parent",
      objectType: "folder",
      objectId: "folder_2",
      traversalRules: myTraversalRules,
      relationPermissions,
    });
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_3",
      relation: "viewer",
      objectType: "group",
      objectId: "group_2",
      traversalRules: myTraversalRules,
      relationPermissions,
    });

    // Now, since Path 2 has no caveats, the user should be able to read without matching caveat context
    expect(
      await authz.can(ctx as any, "user_3", "documents:read", {
        type: "document",
        id: "doc_3",
      }),
    ).toBe(true);

    // Remove Path 2 (e.g. remove user_3 -> group_2)
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_3",
      relation: "viewer",
      objectType: "group",
      objectId: "group_2",
      traversalRules: myTraversalRules,
      relationPermissions,
    });

    // Now the user should be restricted by the caveat on Path 1 again
    expect(
      await authz.can(ctx as any, "user_3", "documents:read", {
        type: "document",
        id: "doc_3",
      }),
    ).toBe(false);
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_3",
        "documents:read",
        { type: "document", id: "doc_3" },
        { isWorkHours: "yes" },
      ),
    ).toBe(true);

    // Remove Path 1 (e.g. remove group_1 -> folder_1)
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "group",
      subjectId: "group_1",
      relation: "parent",
      objectType: "folder",
      objectId: "folder_1",
      traversalRules: myTraversalRules,
      relationPermissions,
    });

    // User should have no access at all
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_3",
        "documents:read",
        { type: "document", id: "doc_3" },
        { isWorkHours: "yes" },
      ),
    ).toBe(false);
  });

  it.skip("should handle 4 paths with mixed caveats correctly", async () => {
    const t = convexTest(schema, modules);
    const myTraversalRules = defineTraversalRules({
      "document:viewer": [
        { through: "folder", via: "parent", inherit: "viewer" },
      ],
      "folder:viewer": [{ through: "group", via: "parent", inherit: "viewer" }],
    });

    const myCaveats = defineCaveats({
      isA: ({ caveatContext }) => (caveatContext as any)?.context === "A",
      isB: ({ caveatContext }) => (caveatContext as any)?.context === "B",
      isC: ({ caveatContext }) => (caveatContext as any)?.context === "C",
    });

    const authz = new Authz(api as any, {
      permissions,
      roles,
      tenantId: TENANT,
      traversalRules: myTraversalRules,
      relationPermissions,
      caveats: myCaveats,
    });

    const ctx = {
      runQuery: (q: any, args: any) => t.query(q, args),
      runMutation: (m: any, args: any) => t.mutation(m, args),
    };

    // Helper to build a path
    const buildPath = async (
      groupId: string,
      folderId: string,
      docId: string,
      caveatName?: string,
    ) => {
      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "folder",
        subjectId: folderId,
        relation: "parent",
        objectType: "document",
        objectId: docId,
        caveat: caveatName,
        traversalRules: myTraversalRules,
        relationPermissions,
      });
      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "group",
        subjectId: groupId,
        relation: "parent",
        objectType: "folder",
        objectId: folderId,
        traversalRules: myTraversalRules,
        relationPermissions,
      });
      await t.mutation(api.unified.addRelationUnified, {
        tenantId: TENANT,
        subjectType: "user",
        subjectId: "user_4",
        relation: "viewer",
        objectType: "group",
        objectId: groupId,
        traversalRules: myTraversalRules,
        relationPermissions,
      });
    };

    // Path 1 (caveat A)
    await buildPath("group_a", "folder_a", "doc_4", "isA");

    // Path 2 (caveat B)
    await buildPath("group_b", "folder_b", "doc_4", "isB");

    // Path 3 (no caveats)
    await buildPath("group_none", "folder_none", "doc_4");

    // Path 4 (caveat C)
    await buildPath("group_c", "folder_c", "doc_4", "isC");

    // All 4 paths exist, Path 3 has no caveats. Should allow without context.
    expect(
      await authz.can(ctx as any, "user_4", "documents:read", {
        type: "document",
        id: "doc_4",
      }),
    ).toBe(true);

    // Remove Path 3 (no caveats)
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_4",
      relation: "viewer",
      objectType: "group",
      objectId: "group_none",
      traversalRules: myTraversalRules,
      relationPermissions,
    });

    // Now it should be conditional
    expect(
      await authz.can(ctx as any, "user_4", "documents:read", {
        type: "document",
        id: "doc_4",
      }),
    ).toBe(false);

    // Can access with A, B, or C
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_4",
        "documents:read",
        { type: "document", id: "doc_4" },
        { context: "A" },
      ),
    ).toBe(true);
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_4",
        "documents:read",
        { type: "document", id: "doc_4" },
        { context: "B" },
      ),
    ).toBe(true);
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_4",
        "documents:read",
        { type: "document", id: "doc_4" },
        { context: "C" },
      ),
    ).toBe(true);
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_4",
        "documents:read",
        { type: "document", id: "doc_4" },
        { context: "D" },
      ),
    ).toBe(false);

    // Remove Path 1
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_4",
      relation: "viewer",
      objectType: "group",
      objectId: "group_a",
      traversalRules: myTraversalRules,
      relationPermissions,
    });

    // A is no longer valid, B and C are
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_4",
        "documents:read",
        { type: "document", id: "doc_4" },
        { context: "A" },
      ),
    ).toBe(false);
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_4",
        "documents:read",
        { type: "document", id: "doc_4" },
        { context: "B" },
      ),
    ).toBe(true);

    // Remove Path 2 and Path 4
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_4",
      relation: "viewer",
      objectType: "group",
      objectId: "group_b",
      traversalRules: myTraversalRules,
      relationPermissions,
    });
    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_4",
      relation: "viewer",
      objectType: "group",
      objectId: "group_c",
      traversalRules: myTraversalRules,
      relationPermissions,
    });

    // None are valid
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_4",
        "documents:read",
        { type: "document", id: "doc_4" },
        { context: "B" },
      ),
    ).toBe(false);
    expect(
      await authz.canWithContext(
        ctx as any,
        "user_4",
        "documents:read",
        { type: "document", id: "doc_4" },
        { context: "C" },
      ),
    ).toBe(false);
  });
});
