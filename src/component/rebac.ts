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
import { mutation, query } from "./_generated/server";

// ============================================================================
// Relationship Tuple Storage
// ============================================================================

/**
 * Store a relationship tuple
 * Format: (subject, relation, object)
 * Example: (user:123, member, team:456)
 */
export const addRelation = mutation({
  args: {
    tenantId: v.string(),
    subjectType: v.string(), // e.g., "user", "team"
    subjectId: v.string(), // e.g., "123"
    relation: v.string(), // e.g., "member", "owner", "viewer"
    objectType: v.string(), // e.g., "team", "account", "deal"
    objectId: v.string(), // e.g., "456"
    createdBy: v.optional(v.string()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    // Check if relation already exists
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

    if (existing) {
      return existing._id as string;
    }

    const id = await ctx.db.insert("relationships", {
      tenantId: args.tenantId,
      subjectType: args.subjectType,
      subjectId: args.subjectId,
      relation: args.relation,
      objectType: args.objectType,
      objectId: args.objectId,
      createdBy: args.createdBy,
      createdAt: Date.now(),
    });

    return id as string;
  },
});

/**
 * Remove a relationship tuple
 */
export const removeRelation = mutation({
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

    if (existing) {
      await ctx.db.delete(existing._id);
      return true;
    }
    return false;
  },
});

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
      .collect();

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
      .collect();

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
    const maxDepth = args.maxDepth ?? 5;
    const maxBranching = args.maxBranching ?? 50;
    const visited = new Set<string>();

    // Check direct relation first
    const direct = await ctx.db
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

    if (direct) {
      return {
        allowed: true,
        path: [
          `${args.subjectType}:${args.subjectId} -[${args.relation}]-> ${args.objectType}:${args.objectId}`,
        ],
        reason: "Direct relationship",
      };
    }

    // If no traversal rules, return false
    if (!args.traversalRules) {
      return {
        allowed: false,
        path: [],
        reason: "No direct relationship and no traversal rules provided",
      };
    }

    // Parse traversal rules
    const rules = args.traversalRules as Record<
      string,
      Array<{
        through: string; // intermediate object type
        via: string; // relation from object to intermediate
        inherit: string; // relation to inherit from intermediate
      }>
    >;

    // BFS traversal to find path
    interface QueueItem {
      objectType: string;
      objectId: string;
      relation: string;
      depth: number;
      path: string[];
    }

    const queue: Array<QueueItem> = [
      {
        objectType: args.objectType,
        objectId: args.objectId,
        relation: args.relation,
        depth: 0,
        path: [],
      },
    ];

    while (queue.length > 0) {
      const current = queue.shift()!;

      if (current.depth >= maxDepth) continue;

      // Skip already-visited (objectType, objectId, relation) to prevent cycles from causing infinite traversal
      const visitKey = `${current.objectType}:${current.objectId}:${current.relation}`;
      if (visited.has(visitKey)) continue;
      visited.add(visitKey);

      // Check if subject has this relation to current object
      const hasRelation = await ctx.db
        .query("relationships")
        .withIndex("by_tenant_subject_relation_object", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("subjectType", args.subjectType)
            .eq("subjectId", args.subjectId)
            .eq("relation", current.relation)
            .eq("objectType", current.objectType)
            .eq("objectId", current.objectId),
        )
        .unique();

      if (hasRelation) {
        const finalPath = [
          ...current.path,
          `${args.subjectType}:${args.subjectId} -[${current.relation}]-> ${current.objectType}:${current.objectId}`,
        ];
        return {
          allowed: true,
          path: finalPath,
          reason: `Access via ${current.objectType}`,
        };
      }

      // Find parent objects to traverse
      // We need to find objects that point TO the current object via the 'via' relation
      // Example: If checking deal:viewer and rule says inherit from account via "parent"
      // We need to find: which account has "parent" relation pointing to this deal?
      const currentRuleKey = `${current.objectType}:${current.relation}`;
      const currentRules = rules[currentRuleKey] || [];

      for (const rule of currentRules) {
        // Find subjects that have 'via' relation TO the current object
        // E.g., find accounts that have "parent" relation to this deal
        const parentRelations = await ctx.db
          .query("relationships")
          .withIndex("by_tenant_object_relation", (q) =>
            q
              .eq("tenantId", args.tenantId)
              .eq("objectType", current.objectType)
              .eq("objectId", current.objectId)
              .eq("relation", rule.via),
          )
          .take(maxBranching);

        // Filter to only the intermediate object type we're looking for
        const parents = parentRelations.filter(
          (r) => r.subjectType === rule.through,
        );

        for (const parent of parents) {
          const nextVisitKey = `${parent.subjectType}:${parent.subjectId}:${rule.inherit}`;
          if (visited.has(nextVisitKey)) continue;
          queue.push({
            objectType: parent.subjectType,
            objectId: parent.subjectId,
            relation: rule.inherit,
            depth: current.depth + 1,
            path: [
              ...current.path,
              `${parent.subjectType}:${parent.subjectId} -[${rule.via}]-> ${current.objectType}:${current.objectId}`,
            ],
          });
        }
      }
    }

    return {
      allowed: false,
      path: [],
      reason: "No relationship path found",
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
    }),
  ),
  handler: async (ctx, args) => {
    const results: Array<{ objectId: string; via: string }> = [];

    // Direct relations
    const directRelations = await ctx.db
      .query("relationships")
      .withIndex("by_tenant_subject", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("subjectType", args.subjectType)
          .eq("subjectId", args.subjectId),
      )
      .collect();

    const directObjects = directRelations.filter(
      (r) => r.relation === args.relation && r.objectType === args.objectType,
    );

    for (const obj of directObjects) {
      results.push({ objectId: obj.objectId, via: "direct" });
    }

    // TODO: Add traversal for inherited access
    // This would require iterating through intermediate objects

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
    }),
  ),
  handler: async (ctx, args) => {
    const results: Array<{ userId: string; via: string }> = [];

    // Direct relations
    const directRelations = await ctx.db
      .query("relationships")
      .withIndex("by_tenant_object", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("objectType", args.objectType)
          .eq("objectId", args.objectId),
      )
      .collect();

    const directUsers = directRelations.filter(
      (r) => r.relation === args.relation && r.subjectType === "user",
    );

    for (const user of directUsers) {
      results.push({ userId: user.subjectId, via: "direct" });
    }

    // TODO: Add traversal for inherited access

    return results;
  },
});
