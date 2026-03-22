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
import { matchesPermissionPattern } from "./helpers";
import { scopeValidator } from "./validators";

// ============================================================================
// O(1) Permission Check - The Fast Path
// ============================================================================

/**
 * Check permission with O(1) lookup
 * Uses the pre-computed effectivePermissions table
 */
export const checkPermissionFast = query({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
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
      .query("effectivePermissions")
      .withIndex("by_tenant_user_permission_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("permission", args.permission)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (!cached) {
      return false;
    }

    if (cached.expiresAt && cached.expiresAt < Date.now()) {
      return false;
    }

    return cached.effect === "allow";
  },
});

const MAX_BULK_PERMISSIONS = 100;
const MAX_BULK_ROLES = 100;

/**
 * Check if user has any of the given permissions (canAny) - batch O(1) lookups.
 * Queries all effective permissions for userId and scope once, then checks if any requested permission is allowed.
 */
export const checkPermissionsFast = query({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permissions: v.array(v.string()),
    objectType: v.optional(v.string()),
    objectId: v.optional(v.string()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    if (args.permissions.length === 0) return false;
    if (args.permissions.length > MAX_BULK_PERMISSIONS) {
      throw new Error(
        `permissions must not exceed ${MAX_BULK_PERMISSIONS} items (got ${args.permissions.length})`
      );
    }

    const scopeKey = args.objectType && args.objectId
      ? `${args.objectType}:${args.objectId}`
      : "global";

    const now = Date.now();
    const rows = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user_scope", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId).eq("scopeKey", scopeKey)
      )
      .collect();

    const allowedPerms: string[] = [];
    const deniedPerms: string[] = [];
    for (const row of rows) {
      if (row.expiresAt && row.expiresAt < now) continue;
      if (row.effect === "allow") allowedPerms.push(row.permission);
      else if (row.effect === "deny") deniedPerms.push(row.permission);
    }

    for (const p of args.permissions) {
      let denied = false;
      for (const stored of deniedPerms) {
        if (matchesPermissionPattern(p, stored)) {
          denied = true;
          break;
        }
      }
      if (denied) continue;
      for (const stored of allowedPerms) {
        if (matchesPermissionPattern(p, stored)) return true;
      }
    }
    return false;
  },
});

/**
 * Check if user has a role - O(1) lookup
 */
export const hasRoleFast = query({
  args: {
    tenantId: v.string(),
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
      .withIndex("by_tenant_user_role_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("role", args.role)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (!cached) {
      return false;
    }

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
    tenantId: v.string(),
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
      .withIndex("by_tenant_subject_relation_object", (q) =>
        q
          .eq("tenantId", args.tenantId)
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
    tenantId: v.string(),
    userId: v.string(),
    role: v.string(),
    rolePermissions: v.array(v.string()), // Permissions this role grants
    scope: scopeValidator,
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
      .withIndex("by_tenant_user_role_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
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
        tenantId: args.tenantId,
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
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("permission", permission)
            .eq("scopeKey", scopeKey)
        )
        .unique();

      if (existingPerm) {
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
          tenantId: args.tenantId,
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
    tenantId: v.string(),
    userId: v.string(),
    role: v.string(),
    rolePermissions: v.array(v.string()), // Permissions this role granted
    scope: scopeValidator,
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    // Step 1: Remove the role assignment
    const existing = await ctx.db
      .query("effectiveRoles")
      .withIndex("by_tenant_user_role_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
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
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
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
          await ctx.db.delete(existingPerm._id);
        } else {
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
 * Assign multiple roles and compute permissions in a single transaction.
 */
export const assignRolesWithCompute = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    roles: v.array(
      v.object({
        role: v.string(),
        scope: scopeValidator,
        expiresAt: v.optional(v.number()),
        metadata: v.optional(v.any()),
      })
    ),
    rolePermissionsMap: v.record(v.string(), v.array(v.string())),
    assignedBy: v.optional(v.string()),
  },
  returns: v.object({
    assigned: v.number(),
    assignmentIds: v.array(v.string()),
  }),
  handler: async (ctx, args) => {
    if (args.roles.length === 0) {
      return { assigned: 0, assignmentIds: [] };
    }
    if (args.roles.length > MAX_BULK_ROLES) {
      throw new Error(
        `roles must not exceed ${MAX_BULK_ROLES} items (got ${args.roles.length})`
      );
    }

    const assignmentIds: string[] = [];
    let assigned = 0;

    for (const item of args.roles) {
      const rolePermissions = args.rolePermissionsMap[item.role] ?? [];
      const scopeKey = item.scope
        ? `${item.scope.type}:${item.scope.id}`
        : "global";

      const existing = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user_role_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("role", item.role)
            .eq("scopeKey", scopeKey)
        )
        .unique();

      let roleId: string;
      if (existing) {
        await ctx.db.patch(existing._id, {
          expiresAt: item.expiresAt,
          updatedAt: Date.now(),
        });
        roleId = existing._id as string;
      } else {
        roleId = await ctx.db.insert("effectiveRoles", {
          tenantId: args.tenantId,
          userId: args.userId,
          role: item.role,
          scopeKey,
          scope: item.scope,
          expiresAt: item.expiresAt,
          assignedBy: args.assignedBy,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        }) as string;
      }

      for (const permission of rolePermissions) {
        const existingPerm = await ctx.db
          .query("effectivePermissions")
          .withIndex("by_tenant_user_permission_scope", (q) =>
            q
              .eq("tenantId", args.tenantId)
              .eq("userId", args.userId)
              .eq("permission", permission)
              .eq("scopeKey", scopeKey)
          )
          .unique();

        if (existingPerm) {
          const sources = existingPerm.sources /* v8 ignore next */ || [];
          if (!sources.includes(item.role)) {
            sources.push(item.role);
            await ctx.db.patch(existingPerm._id, {
              sources,
              updatedAt: Date.now(),
            });
          }
        } else {
          await ctx.db.insert("effectivePermissions", {
            tenantId: args.tenantId,
            userId: args.userId,
            permission,
            scopeKey,
            scope: item.scope,
            effect: "allow",
            sources: [item.role],
            expiresAt: item.expiresAt,
            createdAt: Date.now(),
            updatedAt: Date.now(),
          });
        }
      }

      assignmentIds.push(roleId);
      assigned++;
    }

    return { assigned, assignmentIds };
  },
});

/**
 * Revoke multiple roles and recompute permissions in a single transaction.
 */
export const revokeRolesWithCompute = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    roles: v.array(
      v.object({
        role: v.string(),
        scope: scopeValidator,
      })
    ),
    rolePermissionsMap: v.record(v.string(), v.array(v.string())),
  },
  returns: v.object({
    revoked: v.number(),
  }),
  handler: async (ctx, args) => {
    if (args.roles.length === 0) {
      return { revoked: 0 };
    }
    if (args.roles.length > MAX_BULK_ROLES) {
      throw new Error(
        `roles must not exceed ${MAX_BULK_ROLES} items (got ${args.roles.length})`
      );
    }

    let revoked = 0;

    for (const item of args.roles) {
      const rolePermissions = args.rolePermissionsMap[item.role] ?? [];
      const scopeKey = item.scope
        ? `${item.scope.type}:${item.scope.id}`
        : "global";

      const existing = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user_role_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("role", item.role)
            .eq("scopeKey", scopeKey)
        )
        .unique();

      if (!existing) continue;

      await ctx.db.delete(existing._id);
      revoked++;

      for (const permission of rolePermissions) {
        const existingPerm = await ctx.db
          .query("effectivePermissions")
          .withIndex("by_tenant_user_permission_scope", (q) =>
            q
              .eq("tenantId", args.tenantId)
              .eq("userId", args.userId)
              .eq("permission", permission)
              .eq("scopeKey", scopeKey)
          )
          .unique();

        if (existingPerm) {
          const sources = (existingPerm.sources /* v8 ignore next */ || []).filter(
            (s) => s !== item.role
          );
          if (sources.length === 0) {
            await ctx.db.delete(existingPerm._id);
          } else {
            await ctx.db.patch(existingPerm._id, {
              sources,
              updatedAt: Date.now(),
            });
          }
        }
      }
    }

    return { revoked };
  },
});

/**
 * Grant a direct permission override
 */
export const grantPermissionDirect = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    scope: scopeValidator,
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
      .withIndex("by_tenant_user_permission_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
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
      tenantId: args.tenantId,
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
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    scope: scopeValidator,
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
      .withIndex("by_tenant_user_permission_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
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
      tenantId: args.tenantId,
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
    tenantId: v.string(),
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
      .withIndex("by_tenant_subject_relation_object", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("subjectKey", subjectKey)
          .eq("relation", args.relation)
          .eq("objectKey", objectKey)
      )
      .unique();

    if (existing) {
      return existing._id as string;
    }

    const relId = await ctx.db.insert("effectiveRelationships", {
      tenantId: args.tenantId,
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
        const parentRelations = await ctx.db
          .query("effectiveRelationships")
          .withIndex("by_tenant_subject_relation", (q) =>
            q
              .eq("tenantId", args.tenantId)
              .eq("subjectKey", objectKey)
              .eq("relation", inherited.fromRelation)
          )
          .collect();

        const matchingParents = parentRelations.filter(
          (r) => r.objectType === inherited.fromObjectType
        );

        for (const parent of matchingParents) {
          const inheritedKey = `${args.subjectType}:${args.subjectId}`;
          const parentObjectKey = parent.objectKey;

          const existingInherited = await ctx.db
            .query("effectiveRelationships")
            .withIndex("by_tenant_subject_relation_object", (q) =>
              q
                .eq("tenantId", args.tenantId)
                .eq("subjectKey", inheritedKey)
                .eq("relation", inherited.relation)
                .eq("objectKey", parentObjectKey)
            )
            .unique();

          if (!existingInherited) {
            await ctx.db.insert("effectiveRelationships", {
              tenantId: args.tenantId,
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
    tenantId: v.string(),
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

    const existing = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_tenant_subject_relation_object", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("subjectKey", subjectKey)
          .eq("relation", args.relation)
          .eq("objectKey", objectKey)
      )
      .unique();

    if (!existing) {
      return false;
    }

    const inherited = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_tenant_inherited_from", (q) =>
        q.eq("tenantId", args.tenantId).eq("inheritedFrom", existing._id as string)
      )
      .collect();

    for (const rel of inherited) {
      await ctx.db.delete(rel._id);
    }

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
    tenantId: v.string(),
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
        .withIndex("by_tenant_user_scope", (q) =>
          q.eq("tenantId", args.tenantId).eq("userId", args.userId).eq("scopeKey", args.scopeKey as string)
        )
        .collect();
    } else {
      permissions = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", args.tenantId).eq("userId", args.userId)
        )
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
    tenantId: v.string(),
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
        .withIndex("by_tenant_user_scope", (q) =>
          q.eq("tenantId", args.tenantId).eq("userId", args.userId).eq("scopeKey", args.scopeKey as string)
        )
        .collect();
    } else {
      roles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", args.tenantId).eq("userId", args.userId)
        )
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
  args: {
    tenantId: v.optional(v.string()),
  },
  returns: v.object({
    expiredPermissions: v.number(),
    expiredRoles: v.number(),
  }),
  handler: async (ctx, args) => {
    const now = Date.now();
    let expiredPermissions = 0;
    let expiredRoles = 0;

    if (args.tenantId) {
      const permissions = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user", (q) => q.eq("tenantId", args.tenantId!))
        .collect();
      for (const perm of permissions) {
        if (perm.expiresAt && perm.expiresAt < now) {
          await ctx.db.delete(perm._id);
          expiredPermissions++;
        }
      }

      const roles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user", (q) => q.eq("tenantId", args.tenantId!))
        .collect();
      for (const role of roles) {
        if (role.expiresAt && role.expiresAt < now) {
          await ctx.db.delete(role._id);
          expiredRoles++;
        }
      }
    } else {
      const allPermissions = await ctx.db
        .query("effectivePermissions")
        .collect();
      for (const perm of allPermissions) {
        if (perm.expiresAt && perm.expiresAt < now) {
          await ctx.db.delete(perm._id);
          expiredPermissions++;
        }
      }

      const allRoles = await ctx.db.query("effectiveRoles").collect();
      for (const role of allRoles) {
        if (role.expiresAt && role.expiresAt < now) {
          await ctx.db.delete(role._id);
          expiredRoles++;
        }
      }
    }

    return { expiredPermissions, expiredRoles };
  },
});
