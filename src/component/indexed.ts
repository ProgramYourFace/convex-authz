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
    const scopeKey =
      args.objectType && args.objectId
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
          .eq("scopeKey", scopeKey),
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
        `permissions must not exceed ${MAX_BULK_PERMISSIONS} items (got ${args.permissions.length})`,
      );
    }

    const scopeKey =
      args.objectType && args.objectId
        ? `${args.objectType}:${args.objectId}`
        : "global";

    const now = Date.now();
    const rows = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("scopeKey", scopeKey),
      )
      .take(1000);

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
    const scopeKey =
      args.objectType && args.objectId
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
          .eq("scopeKey", scopeKey),
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
          .eq("objectKey", `${args.objectType}:${args.objectId}`),
      )
      .take(1);

    return cached.length > 0;
  },
});

export const getEffectiveRelationshipsForCaveats = query({
  args: {
    tenantId: v.string(),
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
  },
  returns: v.array(
    v.object({
      _id: v.string(),
      path: v.optional(v.array(v.string())),
      caveats: v.optional(
        v.array(
          v.object({
            caveatName: v.string(),
            caveatContext: v.optional(v.any()),
          }),
        ),
      ),
    }),
  ),
  handler: async (ctx, args) => {
    const cached = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_tenant_subject_relation_object", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("subjectKey", `${args.subjectType}:${args.subjectId}`)
          .eq("relation", args.relation)
          .eq("objectKey", `${args.objectType}:${args.objectId}`),
      )
      .take(1000);

    return cached.map((c) => ({
      _id: c._id,
      path: c.path,
      caveats: c.caveats,
    }));
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
    }),
  ),
  handler: async (ctx, args) => {
    let permissions;

    if (args.scopeKey) {
      permissions = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("scopeKey", args.scopeKey as string),
        )
        .take(1000);
    } else {
      permissions = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", args.tenantId).eq("userId", args.userId),
        )
        .take(1000);
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
    }),
  ),
  handler: async (ctx, args) => {
    let roles;

    if (args.scopeKey) {
      roles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("scopeKey", args.scopeKey as string),
        )
        .take(1000);
    } else {
      roles = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", args.tenantId).eq("userId", args.userId),
        )
        .take(1000);
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
    const CLEANUP_BATCH = 500;
    const now = Date.now();
    let expiredPermissions = 0;
    let expiredRoles = 0;

    // Clean up expired effective permissions in batches
    while (true) {
      const permissions = args.tenantId
        ? await ctx.db
            .query("effectivePermissions")
            .withIndex("by_tenant_user", (q) =>
              q.eq("tenantId", args.tenantId!),
            )
            .take(CLEANUP_BATCH)
        : await ctx.db
            .query("effectivePermissions")
            .order("asc")
            .take(CLEANUP_BATCH);
      if (permissions.length === 0) break;
      let deletedAny = false;
      for (const perm of permissions) {
        if (perm.expiresAt && perm.expiresAt < now) {
          await ctx.db.delete(perm._id);
          expiredPermissions++;
          deletedAny = true;
        }
      }
      if (permissions.length < CLEANUP_BATCH || !deletedAny) break;
    }

    // Clean up expired effective roles in batches
    while (true) {
      const roles = args.tenantId
        ? await ctx.db
            .query("effectiveRoles")
            .withIndex("by_tenant_user", (q) =>
              q.eq("tenantId", args.tenantId!),
            )
            .take(CLEANUP_BATCH)
        : await ctx.db.query("effectiveRoles").order("asc").take(CLEANUP_BATCH);
      if (roles.length === 0) break;
      let deletedAny = false;
      for (const role of roles) {
        if (role.expiresAt && role.expiresAt < now) {
          await ctx.db.delete(role._id);
          expiredRoles++;
          deletedAny = true;
        }
      }
      if (roles.length < CLEANUP_BATCH || !deletedAny) break;
    }

    return { expiredPermissions, expiredRoles };
  },
});
