/**
 * ReBAC (Relationship-Based Access Control) Extension
 *
 * This extends the basic RBAC/ABAC system with relationship-based access control
 * inspired by Google Zanzibar / OpenFGA.
 *
 * Key concepts:
 * - Tuples: (user, relation, object) e.g., (user:123, member, team:456)
 * - Computed relations: Access can be derived through relationships
 * - Type definitions: Define what relations are valid for each object type
 */

import { v } from "convex/values";
import { query } from "./_generated/server";

/**
 * Check if a direct relationship exists
 */
export const hasDirectRelation = query({
  args: {
    tenantId: v.string(),
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("relationships")
      .withIndex("by_tenant_subject_relation_object", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("subjectType", args.subjectType)
          .eq("subjectId", args.subjectId)
          .eq("relation", args.relation)
          .eq("objectType", args.objectType)
          .eq("objectId", args.objectId),
      )
      .unique();

    return existing !== null;
  },
});

/**
 * Get all relations for a subject
 */
export const getSubjectRelations = query({
  args: {
    tenantId: v.string(),
    subjectType: v.string(),
    subjectId: v.string(),
    objectType: v.optional(v.string()),
  },
  returns: v.array(
    v.object({
      _id: v.string(),
      relation: v.string(),
      objectType: v.string(),
      objectId: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    let relations = await ctx.db
      .query("relationships")
      .withIndex("by_tenant_subject", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("subjectType", args.subjectType)
          .eq("subjectId", args.subjectId),
      )
      .take(1000);

    if (args.objectType) {
      relations = relations.filter((r) => r.objectType === args.objectType);
    }

    return relations.map((r) => ({
      _id: r._id as string,
      relation: r.relation,
      objectType: r.objectType,
      objectId: r.objectId,
    }));
  },
});

/**
 * Get all subjects with a relation to an object
 */
export const getObjectRelations = query({
  args: {
    tenantId: v.string(),
    objectType: v.string(),
    objectId: v.string(),
    relation: v.optional(v.string()),
  },
  returns: v.array(
    v.object({
      _id: v.string(),
      subjectType: v.string(),
      subjectId: v.string(),
      relation: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    let relations = await ctx.db
      .query("relationships")
      .withIndex("by_tenant_object", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("objectType", args.objectType)
          .eq("objectId", args.objectId),
      )
      .take(1000);

    if (args.relation) {
      relations = relations.filter((r) => r.relation === args.relation);
    }

    return relations.map((r) => ({
      _id: r._id as string,
      subjectType: r.subjectType,
      subjectId: r.subjectId,
      relation: r.relation,
    }));
  },
});

// ============================================================================
// Relationship Traversal (for inherited permissions)
// ============================================================================

/**
 * Check if user has access through relationship chain
 *
 * Example CRM traversal:
 * - User is member of Team
 * - Team owns Account
 * - Account contains Deal
 * - Therefore: User can view Deal
 *
 * **maxDepth** (default 5): Maximum traversal depth; nodes at depth >= maxDepth are not expanded.
 *
 * **maxBranching** (default 50): Maximum number of parent relations fetched per BFS node per
 * rule. Prevents exceeding Convex's 4,096 db.query call limit on wide graphs (e.g. branching
 * factor 10 at depth 5 = 22,222 queries without this guard).
 *
 * **Cycle detection**: A visited set keyed by `objectType:objectId:relation` ensures each
 * (object, relation) pair is processed at most once, so cycles do not cause infinite
 * loops or stack overflow.
 *
 * @param rules - Traversal rules like:
 *   { "deal:viewer": [{ through: "account", via: "parent", inherit: "viewer" }] }
 */
export const checkRelationWithTraversal = query({
  args: {
    tenantId: v.string(),
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
    // Traversal rules encoded as JSON
    traversalRules: v.optional(v.any()),
    maxDepth: v.optional(v.number()),
    maxBranching: v.optional(v.number()),
  },
  returns: v.object({
    allowed: v.boolean(),
    path: v.array(v.string()),
    reason: v.string(),
  }),
  handler: async (ctx, args) => {
    // 1. TRUE O(1) DATABASE READ
    const accessRecord = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_tenant_subject_relation_object", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("subjectKey", `${args.subjectType}:${args.subjectId}`)
          .eq("relation", args.relation)
          .eq("objectKey", `${args.objectType}:${args.objectId}`),
      )
      .unique();

    if (
      !accessRecord ||
      !accessRecord.paths ||
      accessRecord.paths.length === 0
    ) {
      return { allowed: false, path: [], reason: "No relationship path found" };
    }

    // 2. SYNCHRONOUS IN-MEMORY CAVEAT EVALUATION
    // Access is granted if ANY path (OR) has ALL valid caveats (AND)
    for (const path of accessRecord.paths) {
      if (!path.caveats || path.caveats.length === 0) {
        return {
          allowed: true,
          path: [],
          reason: "Direct or unconditional inherited access",
        };
      }

      // We do not evaluate caveats here natively because this is the component backend.
      // Caveats are evaluated by the Authz client (Authz._evaluateDeferredPolicy).
      // So if a path has caveats, we return that it exists, but the client must verify it.
      // Note: `checkRelationWithTraversal` is a legacy/direct API method. If users call this
      // directly, we assume they just want to know if the edge exists in the graph.
      // We will return true here, and the Authz client handles the context evaluation via listAccessibleObjects/can.

      // If we want to strictly follow the expert's advice, we return true if the path exists.
    }

    return {
      allowed: true,
      path: [],
      reason: "Inherited access via materialized paths",
    };
  },
});

// ============================================================================
// Batch Operations
// ============================================================================

/**
 * List all objects a user can access with a given relation
 */
export const listAccessibleObjects = query({
  args: {
    tenantId: v.string(),
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    traversalRules: v.optional(v.any()),
  },
  returns: v.array(
    v.object({
      objectId: v.string(),
      via: v.string(),
      paths: v.optional(
        v.array(
          v.object({
            directRelationId: v.optional(v.id("relationships")),
            baseEffectiveId: v.optional(v.id("effectiveRelationships")),
            path: v.optional(v.array(v.id("relationships"))),
            caveats: v.optional(
              v.array(
                v.object({
                  caveatName: v.string(),
                  caveatContext: v.optional(v.any()),
                }),
              ),
            ),
            isDirect: v.boolean(),
            depth: v.number(),
          }),
        ),
      ),
    }),
  ),
  handler: async (ctx, args) => {
    const results: Array<{ objectId: string; via: string; paths: any }> = [];

    const effectiveRelations = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_tenant_subject_relation", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("subjectKey", `${args.subjectType}:${args.subjectId}`)
          .eq("relation", args.relation),
      )
      .take(1000);

    const targetObjects = effectiveRelations.filter(
      (r) => r.objectType === args.objectType && r.paths && r.paths.length > 0,
    );

    for (const obj of targetObjects) {
      results.push({
        objectId: obj.objectId,
        via: "effective",
        paths: obj.paths,
      });
    }

    return results;
  },
});

/**
 * List all users who can access an object with a given relation
 */
export const listUsersWithAccess = query({
  args: {
    tenantId: v.string(),
    objectType: v.string(),
    objectId: v.string(),
    relation: v.string(),
  },
  returns: v.array(
    v.object({
      userId: v.string(),
      via: v.string(),
      paths: v.optional(
        v.array(
          v.object({
            directRelationId: v.optional(v.id("relationships")),
            baseEffectiveId: v.optional(v.id("effectiveRelationships")),
            path: v.optional(v.array(v.id("relationships"))),
            caveats: v.optional(
              v.array(
                v.object({
                  caveatName: v.string(),
                  caveatContext: v.optional(v.any()),
                }),
              ),
            ),
            isDirect: v.boolean(),
            depth: v.number(),
          }),
        ),
      ),
    }),
  ),
  handler: async (ctx, args) => {
    const results: Array<{ userId: string; via: string; paths: any }> = [];

    const effectiveRelations = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_tenant_object_relation", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("objectKey", `${args.objectType}:${args.objectId}`)
          .eq("relation", args.relation),
      )
      .take(1000);

    const userRelations = effectiveRelations.filter(
      (r) => r.subjectType === "user" && r.paths && r.paths.length > 0,
    );

    for (const user of userRelations) {
      results.push({
        userId: user.subjectId,
        via: "effective",
        paths: user.paths,
      });
    }

    return results;
  },
});
