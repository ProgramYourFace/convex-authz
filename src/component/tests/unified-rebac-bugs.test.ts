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
  "folder:viewer": [{ through: "group", via: "parent", inherit: "viewer" }],
});

const relationPermissions = defineRelationPermissions({
  "document:viewer": ["documents:read"],
});

const caveats = defineCaveats({
  isWorkHours: ({ caveatContext }) => {
    return (caveatContext as any)?.isWorkHours === "yes";
  },
});

describe("ReBAC Transitive Closures and Caveat Bugs", () => {
  it("Bug 1: should correctly clean up cascading paths in the same tuple during removeRelationUnified", async () => {
    const t = convexTest(schema, modules);
    const authz = new Authz(api as any, {
      permissions,
      roles,
      tenantId: TENANT,
      traversalRules,
      relationPermissions,
    });

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "group",
      subjectId: "group_1",
      relation: "parent",
      objectType: "folder",
      objectId: "folder_1",
      traversalRules,
      relationPermissions,
    });

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

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "viewer",
      objectType: "group",
      objectId: "group_1",
      traversalRules,
      relationPermissions,
    });

    const ctx = {
      runQuery: (q: any, args: any) => t.query(q, args),
      runMutation: (m: any, args: any) => t.mutation(m, args),
    };

    let canRead = await authz.can(ctx as any, "user_1", "documents:read", {
      type: "document",
      id: "doc_1",
    });
    expect(canRead).toBe(true);

    await t.mutation(api.unified.removeRelationUnified, {
      tenantId: TENANT,
      subjectType: "group",
      subjectId: "group_1",
      relation: "parent",
      objectType: "folder",
      objectId: "folder_1",
      traversalRules,
      relationPermissions,
    });

    canRead = await authz.can(ctx as any, "user_1", "documents:read", {
      type: "document",
      id: "doc_1",
    });
    expect(canRead).toBe(false);
  });

  it("Bug 2: Caveats on relations should not overwrite unconditional direct grants", async () => {
    const t = convexTest(schema, modules);
    const authz = new Authz(api as any, {
      permissions,
      roles,
      tenantId: TENANT,
      traversalRules,
      relationPermissions,
      caveats,
    });

    const ctx = {
      runQuery: (q: any, args: any) => t.query(q, args),
      runMutation: (m: any, args: any) => t.mutation(m, args),
    };

    await t.mutation(api.unified.grantPermissionUnified, {
      tenantId: TENANT,
      userId: "user_1",
      permission: "documents:read",
      scope: { type: "document", id: "doc_1" },
    });

    let canRead = await authz.can(ctx as any, "user_1", "documents:read", {
      type: "document",
      id: "doc_1",
    });
    expect(canRead).toBe(true);

    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "viewer",
      objectType: "document",
      objectId: "doc_1",
      caveat: "isWorkHours",
      traversalRules,
      relationPermissions,
    });

    canRead = await authz.can(ctx as any, "user_1", "documents:read", {
      type: "document",
      id: "doc_1",
    });
    expect(canRead).toBe(true);
  });

  it("Bug 3: via rule does not match against effectiveRelationships during Direction 1", async () => {
    const t = convexTest(schema, modules);
    const myRules = defineTraversalRules({
      "group:admin": [
        { through: "group", via: "owner", inherit: "member" },
      ],
      "group:manager": [
        { through: "group", via: "admin", inherit: "member" },
      ]
    });
    const myPerms = defineRelationPermissions({
      "group:manager": ["documents:read"],
    });

    const authz = new Authz(api as any, {
      permissions,
      roles,
      tenantId: TENANT,
      traversalRules: myRules,
      relationPermissions: myPerms,
    });
    
    // 1. Create a group->owner->group chain first
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "group",
      subjectId: "group_1",
      relation: "owner",
      objectType: "group",
      objectId: "group_2",
      traversalRules: myRules,
      relationPermissions: myPerms,
    });
    
    // At this point group_1 -> owner -> group_2
    
    // Now add group_0 -> member -> group_1
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "group",
      subjectId: "group_0",
      relation: "member",
      objectType: "group",
      objectId: "group_1",
      traversalRules: myRules,
      relationPermissions: myPerms,
    });

    // Now add user_1 -> member -> group_0
    await t.mutation(api.unified.addRelationUnified, {
      tenantId: TENANT,
      subjectType: "user",
      subjectId: "user_1",
      relation: "member",
      objectType: "group",
      objectId: "group_0",
      traversalRules: myRules,
      relationPermissions: myPerms,
    });

    const ctx = {
      runQuery: (q: any, args: any) => t.query(q, args),
      runMutation: (m: any, args: any) => t.mutation(m, args),
    };
    
    // The user should have admin of group_2
    const canRead = await authz.can(
      ctx as any,
      "user_1",
      "documents:read",
      { type: "group", id: "group_2" }
    );
    expect(canRead).toBe(true);
  });
});
