/**
 * Indexed Permission System - O(1) Lookups
 *
 * This module provides O(1) permission checks by pre-computing and caching
 * all effective permissions in a denormalized table.
 *
 * Trade-offs:
 * - Writes are slower (need to update computed permissions)
 * - Storage is higher (denormalized data)
 * - Reads are O(1) via direct index lookup
 *
 * This is the same approach used by Google Zanzibar and OpenFGA.
 */

import { v } from "convex/values";
import { mutation, query } from "./_generated/server";

// ============================================================================
// O(1) Permission Check - The Fast Path
// ============================================================================

/**
 * Check permission with O(1) lookup
 * Uses the pre-computed effectivePermissions table
 */
export const checkPermissionFast = query({
  args: {
    userId: v.string(),
    permission: v.string(),
    objectType: v.optional(v.string()),
    objectId: v.optional(v.string()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    // Build the lookup key
    const scopeKey = args.objectType && args.objectId
      ? `${args.objectType}:${args.objectId}`
      : "global";

    // O(1) indexed lookup
    const cached = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_user_permission_scope", (q) =>
        q
          .eq("userId", args.userId)
          .eq("permission", args.permission)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (!cached) {
      return false;
    }

    // Check if expired
    if (cached.expiresAt && cached.expiresAt < Date.now()) {
      return false;
    }

    return cached.effect === "allow";
  },
});

/**
 * Check if user has a role - O(1) lookup
 */
export const hasRoleFast = query({
  args: {
    userId: v.string(),
    role: v.string(),
    objectType: v.optional(v.string()),
    objectId: v.optional(v.string()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const scopeKey = args.objectType && args.objectId
      ? `${args.objectType}:${args.objectId}`
      : "global";

    // O(1) indexed lookup
    const cached = await ctx.db
      .query("effectiveRoles")
      .withIndex("by_user_role_scope", (q) =>
        q
          .eq("userId", args.userId)
          .eq("role", args.role)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (!cached) {
      return false;
    }

    // Check if expired
    if (cached.expiresAt && cached.expiresAt < Date.now()) {
      return false;
    }

    return true;
  },
});

/**
 * Check relationship - O(1) lookup
 */
export const hasRelationFast = query({
  args: {
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    // O(1) indexed lookup on computed relationships
    const cached = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_subject_relation_object", (q) =>
        q
          .eq("subjectKey", `${args.subjectType}:${args.subjectId}`)
          .eq("relation", args.relation)
          .eq("objectKey", `${args.objectType}:${args.objectId}`)
      )
      .unique();

    return cached !== null;
  },
});

// ============================================================================
// Permission Computation (Write Path)
// ============================================================================

/**
 * Assign a role and compute all resulting permissions
 * This is slower but makes reads O(1)
 */
export const assignRoleWithCompute = mutation({
  args: {
    userId: v.string(),
    role: v.string(),
    rolePermissions: v.array(v.string()), // Permissions this role grants
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
    expiresAt: v.optional(v.number()),
    assignedBy: v.optional(v.string()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    // Step 1: Store the role assignment
    const existing = await ctx.db
      .query("effectiveRoles")
      .withIndex("by_user_role_scope", (q) =>
        q
          .eq("userId", args.userId)
          .eq("role", args.role)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    let roleId: string;
    if (existing) {
      await ctx.db.patch(existing._id, {
        expiresAt: args.expiresAt,
        updatedAt: Date.now(),
      });
      roleId = existing._id as string;
    } else {
      roleId = await ctx.db.insert("effectiveRoles", {
        userId: args.userId,
        role: args.role,
        scopeKey,
        scope: args.scope,
        expiresAt: args.expiresAt,
        assignedBy: args.assignedBy,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }) as string;
    }

    // Step 2: Compute and store all permissions from this role
    for (const permission of args.rolePermissions) {
      const existingPerm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_user_permission_scope", (q) =>
          q
            .eq("userId", args.userId)
            .eq("permission", permission)
            .eq("scopeKey", scopeKey)
        )
        .unique();

      if (existingPerm) {
        // Add this role as a source
        const sources = existingPerm.sources /* v8 ignore next */ || [];
        if (!sources.includes(args.role)) {
          sources.push(args.role);
          await ctx.db.patch(existingPerm._id, {
            sources,
            updatedAt: Date.now(),
          });
        }
      } else {
        await ctx.db.insert("effectivePermissions", {
          userId: args.userId,
          permission,
          scopeKey,
          scope: args.scope,
          effect: "allow",
          sources: [args.role],
          expiresAt: args.expiresAt,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        });
      }
    }

    return roleId;
  },
});

/**
 * Revoke a role and recompute permissions
 */
export const revokeRoleWithCompute = mutation({
  args: {
    userId: v.string(),
    role: v.string(),
    rolePermissions: v.array(v.string()), // Permissions this role granted
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    // Step 1: Remove the role assignment
    const existing = await ctx.db
      .query("effectiveRoles")
      .withIndex("by_user_role_scope", (q) =>
        q
          .eq("userId", args.userId)
          .eq("role", args.role)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (!existing) {
      return false;
    }

    await ctx.db.delete(existing._id);

    // Step 2: Update permissions - remove this role as a source
    for (const permission of args.rolePermissions) {
      const existingPerm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_user_permission_scope", (q) =>
          q
            .eq("userId", args.userId)
            .eq("permission", permission)
            .eq("scopeKey", scopeKey)
        )
        .unique();

      if (existingPerm) {
        const sources = (existingPerm.sources /* v8 ignore next */ || []).filter(
          (s) => s !== args.role
        );

        if (sources.length === 0) {
          // No more sources - remove the permission
          await ctx.db.delete(existingPerm._id);
        } else {
          // Update sources
          await ctx.db.patch(existingPerm._id, {
            sources,
            updatedAt: Date.now(),
          });
        }
      }
    }

    return true;
  },
});

/**
 * Grant a direct permission override
 */
export const grantPermissionDirect = mutation({
  args: {
    userId: v.string(),
    permission: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
    reason: v.optional(v.string()),
    grantedBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    const existing = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_user_permission_scope", (q) =>
        q
          .eq("userId", args.userId)
          .eq("permission", args.permission)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (existing) {
      await ctx.db.patch(existing._id, {
        effect: "allow",
        directGrant: true,
        reason: args.reason,
        expiresAt: args.expiresAt,
        updatedAt: Date.now(),
      });
      return existing._id as string;
    }

    return await ctx.db.insert("effectivePermissions", {
      userId: args.userId,
      permission: args.permission,
      scopeKey,
      scope: args.scope,
      effect: "allow",
      directGrant: true,
      sources: [],
      reason: args.reason,
      grantedBy: args.grantedBy,
      expiresAt: args.expiresAt,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }) as string;
  },
});

/**
 * Deny a permission (override)
 */
export const denyPermissionDirect = mutation({
  args: {
    userId: v.string(),
    permission: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
    reason: v.optional(v.string()),
    deniedBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    const existing = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_user_permission_scope", (q) =>
        q
          .eq("userId", args.userId)
          .eq("permission", args.permission)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (existing) {
      await ctx.db.patch(existing._id, {
        effect: "deny",
        directDeny: true,
        reason: args.reason,
        expiresAt: args.expiresAt,
        updatedAt: Date.now(),
      });
      return existing._id as string;
    }

    return await ctx.db.insert("effectivePermissions", {
      userId: args.userId,
      permission: args.permission,
      scopeKey,
      scope: args.scope,
      effect: "deny",
      directDeny: true,
      sources: [],
      reason: args.reason,
      grantedBy: args.deniedBy,
      expiresAt: args.expiresAt,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }) as string;
  },
});

// ============================================================================
// Relationship Computation (for ReBAC)
// ============================================================================

/**
 * Add a relationship and compute transitive permissions
 */
export const addRelationWithCompute = mutation({
  args: {
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
    // Inherited relations to compute
    inheritedRelations: v.optional(
      v.array(
        v.object({
          relation: v.string(),
          fromObjectType: v.string(),
          fromRelation: v.string(),
        })
      )
    ),
    createdBy: v.optional(v.string()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const subjectKey = `${args.subjectType}:${args.subjectId}`;
    const objectKey = `${args.objectType}:${args.objectId}`;

    // Step 1: Store the direct relationship
    const existing = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_subject_relation_object", (q) =>
        q
          .eq("subjectKey", subjectKey)
          .eq("relation", args.relation)
          .eq("objectKey", objectKey)
      )
      .unique();

    if (existing) {
      return existing._id as string;
    }

    const relId = await ctx.db.insert("effectiveRelationships", {
      subjectKey,
      subjectType: args.subjectType,
      subjectId: args.subjectId,
      relation: args.relation,
      objectKey,
      objectType: args.objectType,
      objectId: args.objectId,
      isDirect: true,
      inheritedFrom: null,
      createdBy: args.createdBy,
      createdAt: Date.now(),
    }) as string;

    // Step 2: Compute inherited relationships
    if (args.inheritedRelations) {
      for (const inherited of args.inheritedRelations) {
        // Find all objects where the current object has a relation
        const parentRelations = await ctx.db
          .query("effectiveRelationships")
          .withIndex("by_subject_relation", (q) =>
            q
              .eq("subjectKey", objectKey)
              .eq("relation", inherited.fromRelation)
          )
          .collect();

        const matchingParents = parentRelations.filter(
          (r) => r.objectType === inherited.fromObjectType
        );

        // Create inherited relationships
        for (const parent of matchingParents) {
          const inheritedKey = `${args.subjectType}:${args.subjectId}`;
          const parentObjectKey = parent.objectKey;

          const existingInherited = await ctx.db
            .query("effectiveRelationships")
            .withIndex("by_subject_relation_object", (q) =>
              q
                .eq("subjectKey", inheritedKey)
                .eq("relation", inherited.relation)
                .eq("objectKey", parentObjectKey)
            )
            .unique();

          if (!existingInherited) {
            await ctx.db.insert("effectiveRelationships", {
              subjectKey: inheritedKey,
              subjectType: args.subjectType,
              subjectId: args.subjectId,
              relation: inherited.relation,
              objectKey: parentObjectKey,
              objectType: parent.objectType,
              objectId: parent.objectId,
              isDirect: false,
              inheritedFrom: relId,
              createdBy: args.createdBy,
              createdAt: Date.now(),
            });
          }
        }
      }
    }

    return relId;
  },
});

/**
 * Remove a relationship and clean up inherited permissions
 */
export const removeRelationWithCompute = mutation({
  args: {
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const subjectKey = `${args.subjectType}:${args.subjectId}`;
    const objectKey = `${args.objectType}:${args.objectId}`;

    // Find the direct relationship
    const existing = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_subject_relation_object", (q) =>
        q
          .eq("subjectKey", subjectKey)
          .eq("relation", args.relation)
          .eq("objectKey", objectKey)
      )
      .unique();

    if (!existing) {
      return false;
    }

    // Delete all inherited relationships from this one
    const inherited = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_inherited_from", (q) =>
        q.eq("inheritedFrom", existing._id as string)
      )
      .collect();

    for (const rel of inherited) {
      await ctx.db.delete(rel._id);
    }

    // Delete the direct relationship
    await ctx.db.delete(existing._id);

    return true;
  },
});

// ============================================================================
// Batch Queries - Still O(1) per item
// ============================================================================

/**
 * Get all permissions for a user - single indexed query
 */
export const getUserPermissionsFast = query({
  args: {
    userId: v.string(),
    scopeKey: v.optional(v.string()),
  },
  returns: v.array(
    v.object({
      permission: v.string(),
      effect: v.string(),
      scopeKey: v.string(),
      sources: v.array(v.string()),
    })
  ),
  handler: async (ctx, args) => {
    let permissions;

    if (args.scopeKey) {
      permissions = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_user_scope", (q) =>
          q.eq("userId", args.userId).eq("scopeKey", args.scopeKey as string)
        )
        .collect();
    } else {
      permissions = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_user", (q) => q.eq("userId", args.userId))
        .collect();
    }

    const now = Date.now();
    return permissions
      .filter((p) => !p.expiresAt || p.expiresAt > now)
      .map((p) => ({
        permission: p.permission,
        effect: p.effect,
        scopeKey: p.scopeKey,
        sources: p.sources /* v8 ignore next */ || [],
      }));
  },
});

/**
 * Get all roles for a user - single indexed query
 */
export const getUserRolesFast = query({
  args: {
    userId: v.string(),
    scopeKey: v.optional(v.string()),
  },
  returns: v.array(
    v.object({
      role: v.string(),
      scopeKey: v.string(),
      scope: v.optional(v.object({ type: v.string(), id: v.string() })),
    })
  ),
  handler: async (ctx, args) => {
    let roles;

    if (args.scopeKey) {
      roles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_user_scope", (q) =>
          q.eq("userId", args.userId).eq("scopeKey", args.scopeKey as string)
        )
        .collect();
    } else {
      roles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_user", (q) => q.eq("userId", args.userId))
        .collect();
    }

    const now = Date.now();
    return roles
      .filter((r) => !r.expiresAt || r.expiresAt > now)
      .map((r) => ({
        role: r.role,
        scopeKey: r.scopeKey,
        scope: r.scope,
      }));
  },
});

// ============================================================================
// Cleanup & Maintenance
// ============================================================================

/**
 * Clean up expired entries
 */
export const cleanupExpired = mutation({
  args: {},
  returns: v.object({
    expiredPermissions: v.number(),
    expiredRoles: v.number(),
  }),
  handler: async (ctx) => {
    const now = Date.now();
    let expiredPermissions = 0;
    let expiredRoles = 0;

    // Clean expired permissions
    const allPermissions = await ctx.db.query("effectivePermissions").collect();
    for (const perm of allPermissions) {
      if (perm.expiresAt && perm.expiresAt < now) {
        await ctx.db.delete(perm._id);
        expiredPermissions++;
      }
    }

    // Clean expired roles
    const allRoles = await ctx.db.query("effectiveRoles").collect();
    for (const role of allRoles) {
      if (role.expiresAt && role.expiresAt < now) {
        await ctx.db.delete(role._id);
        expiredRoles++;
      }
    }

    return { expiredPermissions, expiredRoles };
  },
});
