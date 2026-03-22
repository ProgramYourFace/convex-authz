/**
 * Unified Tiered Permission Check
 *
 * Implements a tiered resolution strategy for O(1) permission checks
 * against the pre-computed effectivePermissions table.
 *
 * Tiers:
 *   1. Exact match via "by_tenant_user_permission_scope" index  (O(1))
 *   2. Wildcard fallback via "by_tenant_user_scope" index       (scan user+scope rows)
 *   3. No match -> denied
 */

import { v } from "convex/values";
import { mutation, query } from "./_generated/server.js";
import { scopeValidator } from "./validators.js";
import { isExpired, matchesPermissionPattern, matchesScope } from "./helpers.js";

export const checkPermission = query({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    scope: scopeValidator,
  },
  returns: v.object({
    allowed: v.boolean(),
    reason: v.string(),
    tier: v.string(),
    policyName: v.optional(v.string()),
  }),
  handler: async (ctx, args) => {
    // Compute scopeKey
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    // ── Tier 1: O(1) exact lookup ──────────────────────────────────────
    const exact = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user_permission_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("permission", args.permission)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (exact && !isExpired(exact.expiresAt)) {
      if (exact.effect === "deny") {
        return {
          allowed: false,
          reason: exact.reason ?? "Denied",
          tier: "cached",
        };
      }

      // effect === "allow"
      const policyResult = exact.policyResult ?? null;

      if (policyResult === null || policyResult === "allow") {
        return { allowed: true, reason: "Allowed", tier: "cached" };
      }

      if (policyResult === "deferred") {
        return {
          allowed: true,
          reason: "Allowed (policy deferred)",
          tier: "deferred",
          policyName: exact.policyName,
        };
      }

      // policyResult === "deny"
      return {
        allowed: false,
        reason: exact.reason ?? "Denied by policy",
        tier: "cached",
      };
    }

    // ── Tier 2: Wildcard fallback ──────────────────────────────────────
    const rows = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("scopeKey", scopeKey)
      )
      .collect();

    // Check deny patterns first (deny wins)
    for (const row of rows) {
      if (isExpired(row.expiresAt)) continue;
      if (
        row.effect === "deny" &&
        matchesPermissionPattern(args.permission, row.permission)
      ) {
        return {
          allowed: false,
          reason: row.reason ?? "Denied by wildcard pattern",
          tier: "cached",
        };
      }
    }

    // Then check allow patterns
    for (const row of rows) {
      if (isExpired(row.expiresAt)) continue;
      if (
        row.effect === "allow" &&
        matchesPermissionPattern(args.permission, row.permission)
      ) {
        // Respect policyResult on wildcard matches too
        const policyResult = row.policyResult ?? null;

        if (policyResult === "deny") {
          continue; // skip this allow — policy overrode it
        }

        if (policyResult === "deferred") {
          return {
            allowed: true,
            reason: "Allowed by wildcard (policy deferred)",
            tier: "deferred",
            policyName: row.policyName,
          };
        }

        return {
          allowed: true,
          reason: "Allowed by wildcard pattern",
          tier: "cached",
        };
      }
    }

    // ── Tier 3: No permission found ────────────────────────────────────
    return {
      allowed: false,
      reason: "No permission granted",
      tier: "none",
    };
  },
});

/**
 * Unified Role Assignment
 *
 * Writes to BOTH source tables (roleAssignments) AND effective tables
 * (effectiveRoles, effectivePermissions) in a single transaction.
 */
export const assignRoleUnified = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    role: v.string(),
    rolePermissions: v.array(v.string()),
    scope: scopeValidator,
    expiresAt: v.optional(v.number()),
    assignedBy: v.optional(v.string()),
    metadata: v.optional(v.any()),
    enableAudit: v.optional(v.boolean()),
    policyClassifications: v.optional(v.record(v.string(), v.union(
      v.null(),
      v.literal("allow"),
      v.literal("deny"),
      v.literal("deferred"),
    ))),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const now = Date.now();

    // 1. Compute scopeKey
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    // 2. Check for duplicate in roleAssignments
    const existing = await ctx.db
      .query("roleAssignments")
      .withIndex("by_tenant_user_and_role", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("role", args.role)
      )
      .collect();

    for (const row of existing) {
      if (matchesScope(row.scope, args.scope) && !isExpired(row.expiresAt)) {
        return row._id;
      }
    }

    // 3. Insert into roleAssignments (source of truth)
    const assignmentId = await ctx.db.insert("roleAssignments", {
      tenantId: args.tenantId,
      userId: args.userId,
      role: args.role,
      scope: args.scope,
      expiresAt: args.expiresAt,
      assignedBy: args.assignedBy,
      metadata: args.metadata,
    });

    // 4. Upsert into effectiveRoles
    const existingEffectiveRole = await ctx.db
      .query("effectiveRoles")
      .withIndex("by_tenant_user_role_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("role", args.role)
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (existingEffectiveRole) {
      await ctx.db.patch(existingEffectiveRole._id, {
        assignedBy: args.assignedBy,
        expiresAt: args.expiresAt,
        updatedAt: now,
      });
    } else {
      await ctx.db.insert("effectiveRoles", {
        tenantId: args.tenantId,
        userId: args.userId,
        role: args.role,
        scopeKey,
        scope: args.scope,
        assignedBy: args.assignedBy,
        expiresAt: args.expiresAt,
        createdAt: now,
        updatedAt: now,
      });
    }

    // 5. Process each permission in rolePermissions
    for (const permission of args.rolePermissions) {
      const classification = args.policyClassifications?.[permission] ?? null;

      // Skip permissions where policy evaluated to "deny"
      if (classification === "deny") {
        continue;
      }

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
        // Add role to sources if not already present
        const sources = existingPerm.sources.includes(args.role)
          ? existingPerm.sources
          : [...existingPerm.sources, args.role];
        await ctx.db.patch(existingPerm._id, {
          sources,
          updatedAt: now,
        });
      } else {
        await ctx.db.insert("effectivePermissions", {
          tenantId: args.tenantId,
          userId: args.userId,
          permission,
          scopeKey,
          scope: args.scope,
          effect: "allow",
          sources: [args.role],
          createdAt: now,
          updatedAt: now,
          ...(classification === "deferred"
            ? { policyResult: "deferred", policyName: permission }
            : classification === "allow"
              ? { policyResult: "allow" }
              : {}),
        });
      }
    }

    // 6. Audit log
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: now,
        action: "role_assigned",
        userId: args.userId,
        actorId: args.assignedBy,
        details: {
          role: args.role,
          scope: args.scope,
        },
      });
    }

    // 7. Return assignment ID
    return assignmentId;
  },
});
