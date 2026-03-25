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
import { isExpired, matchesPermissionPattern } from "./helpers.js";

function buildInvolvedTokens(paths: any[]): string {
  const tokens = new Set<string>();
  for (const p of paths) {
    if (p.directRelationId) tokens.add(p.directRelationId);
    if (p.baseEffectiveId) tokens.add(p.baseEffectiveId);
    if (p.path) {
      for (const id of p.path) tokens.add(id);
    }
  }
  return Array.from(tokens).join(" ");
}

// Helper for ReBAC updates to effectivePermissions
async function updatePermissionsForRelation(
  ctx: any,
  tenantId: string | undefined,
  subjectType: string,
  subjectId: string,
  relation: string,
  objectType: string,
  objectId: string,
  relationPermissions: Record<string, string[]> | undefined,
  now: number,
) {
  if (!relationPermissions) return;

  const relationKey = `${objectType}:${relation}`;
  const permissions = relationPermissions[relationKey] ?? [];
  if (permissions.length === 0) return;

  const subjectKey = `${subjectType}:${subjectId}`;
  const objectKey = `${objectType}:${objectId}`;

  // Find all effective relationships for this path
  const paths = await ctx.db
    .query("effectiveRelationships")
    .withIndex("by_tenant_subject_relation_object", (q: any) =>
      q
        .eq("tenantId", tenantId)
        .eq("subjectKey", subjectKey)
        .eq("relation", relation)
        .eq("objectKey", objectKey),
    )
    .take(1000);

  const scopeKey = `${objectType}:${objectId}`;
  const scope = { type: objectType, id: objectId };
  const sourceLabel = `relation:${relation}`;
  const userId =
    subjectType === "user" ? subjectId : `${subjectType}:${subjectId}`;

  const hasAnyPath =
    paths.length > 0 && paths.some((p: any) => p.paths && p.paths.length > 0);
  let allHaveCaveats = true;
  if (hasAnyPath) {
    for (const row of paths) {
      for (const p of row.paths) {
        if (!p.caveats || p.caveats.length === 0) {
          allHaveCaveats = false;
          break;
        }
      }
      if (!allHaveCaveats) break;
    }
  }

  for (const permission of permissions) {
    const existingPerm = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user_permission_scope", (q: any) =>
        q
          .eq("tenantId", tenantId)
          .eq("userId", userId)
          .eq("permission", permission)
          .eq("scopeKey", scopeKey),
      )
      .unique();

    if (!hasAnyPath) {
      // Remove source
      if (existingPerm) {
        const updatedSources = existingPerm.sources.filter(
          (s: string) => s !== sourceLabel,
        );
        if (
          updatedSources.length === 0 &&
          !existingPerm.directGrant &&
          !existingPerm.directDeny
        ) {
          await ctx.db.delete(existingPerm._id);
        } else if (updatedSources.length !== existingPerm.sources.length) {
          await ctx.db.patch(existingPerm._id, {
            sources: updatedSources,
            updatedAt: now,
          });
        }
      }
      continue;
    }

    // Add source and update policyResult if needed
    if (existingPerm) {
      const sources = existingPerm.sources.includes(sourceLabel)
        ? existingPerm.sources
        : [...existingPerm.sources, sourceLabel];

      const patchData: any = { sources, updatedAt: now };

      if (allHaveCaveats) {
        if (existingPerm.policyResult !== "deferred") {
          patchData.policyResult = "deferred";
          patchData.policyName = "$relation_caveats";
        }
      } else {
        if (
          existingPerm.policyResult === "deferred" &&
          existingPerm.policyName === "$relation_caveats"
        ) {
          patchData.policyResult = "allow";
          patchData.policyName = undefined;
        }
      }

      await ctx.db.patch(existingPerm._id, patchData);
    } else {
      await ctx.db.insert("effectivePermissions", {
        tenantId,
        userId,
        permission,
        scopeKey,
        scope,
        effect: "allow",
        sources: [sourceLabel],
        createdAt: now,
        updatedAt: now,
        ...(allHaveCaveats
          ? { policyResult: "deferred", policyName: "$relation_caveats" }
          : {}),
      });
    }
  }
}

/**
 * Exact scope equality check for duplicate detection.
 * Unlike matchesScope (which is asymmetric — global matches everything),
 * this returns true only when both scopes are identical.
 */
function scopeEquals(
  a: { type: string; id: string } | undefined,
  b: { type: string; id: string } | undefined,
): boolean {
  if (a === undefined && b === undefined) return true;
  if (a === undefined || b === undefined) return false;
  return a.type === b.type && a.id === b.id;
}

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
    sources: v.optional(v.array(v.string())),
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
          .eq("scopeKey", scopeKey),
      )
      .unique();

    // Fast path: exact deny → return immediately, no scan needed
    if (exact && !isExpired(exact.expiresAt) && exact.effect === "deny") {
      return {
        allowed: false,
        reason: exact.reason ?? "Denied",
        tier: "cached",
      };
    }

    // If checking a scoped permission, also check global denies
    if (scopeKey !== "global") {
      const globalRows = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("scopeKey", "global"),
        )
        .take(4000);

      for (const row of globalRows) {
        if (isExpired(row.expiresAt)) continue;
        if (
          row.effect === "deny" &&
          matchesPermissionPattern(args.permission, row.permission)
        ) {
          return {
            allowed: false,
            reason: "Denied by global pattern",
            tier: "cached",
          };
        }
      }
    }

    // Fast path: exact allow with no wildcards to worry about
    // We still need to check for wildcard deny patterns that could override.
    // Lazy-load the full scan only when needed.
    if (exact && !isExpired(exact.expiresAt) && exact.effect === "allow") {
      // Check if any wildcard deny patterns exist that could override this allow.
      // Load all rows for this user+scope (the "slow" scan).
      const rows = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("scopeKey", scopeKey),
        )
        .take(4000);

      // Check deny patterns first — a wildcard deny overrides exact allow
      for (const row of rows) {
        if (isExpired(row.expiresAt)) continue;
        if (
          row.effect === "deny" &&
          row.permission !== args.permission && // skip exact match (already checked)
          matchesPermissionPattern(args.permission, row.permission)
        ) {
          return {
            allowed: false,
            reason: row.reason ?? "Denied",
            tier: "cached",
          };
        }
      }

      // No deny pattern found — return the exact allow
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
          sources: exact.sources,
        };
      }

      // policyResult === "deny" — static policy denied this
      return {
        allowed: false,
        reason: exact.reason ?? "Denied by policy",
        tier: "cached",
      };
    }

    // ── Tier 2: No exact match — wildcard fallback ──────────────────
    // Load all rows for pattern matching
    const rows = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("scopeKey", scopeKey),
      )
      .take(4000);

    // Deny patterns first
    for (const row of rows) {
      if (isExpired(row.expiresAt)) continue;
      if (
        row.effect === "deny" &&
        matchesPermissionPattern(args.permission, row.permission)
      ) {
        return {
          allowed: false,
          reason: row.reason ?? "Denied",
          tier: "cached",
        };
      }
    }

    // Allow patterns
    for (const row of rows) {
      if (isExpired(row.expiresAt)) continue;
      if (
        row.effect === "allow" &&
        matchesPermissionPattern(args.permission, row.permission)
      ) {
        const policyResult = row.policyResult ?? null;
        if (policyResult === "deny") continue;

        if (policyResult === "deferred") {
          return {
            allowed: true,
            reason: "Allowed by pattern (policy deferred)",
            tier: "deferred",
            policyName: row.policyName,
            sources: row.sources,
          };
        }

        return {
          allowed: true,
          reason: "Allowed by pattern",
          tier: "cached",
        };
      }
    }

    // ── No permission found ──────────────────────────────────────────
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
    policyClassifications: v.optional(
      v.record(
        v.string(),
        v.union(
          v.null(),
          v.literal("allow"),
          v.literal("deny"),
          v.literal("deferred"),
        ),
      ),
    ),
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
          .eq("role", args.role),
      )
      .take(100);

    for (const row of existing) {
      if (scopeEquals(row.scope, args.scope) && !isExpired(row.expiresAt)) {
        // Extend expiry: only update if new value is later or removes expiry entirely.
        // Passing a shorter expiresAt is a no-op (prevents accidental expiry reduction).
        // To shorten expiry, revoke and re-assign.
        const shouldExtend =
          args.expiresAt === undefined ||
          (row.expiresAt !== undefined && args.expiresAt > row.expiresAt);
        if (shouldExtend && args.expiresAt !== row.expiresAt) {
          const newExpiry = args.expiresAt;
          // 1. Update source table
          await ctx.db.patch(row._id, { expiresAt: newExpiry });
          // 2. Update effectiveRoles
          const scopeKey = args.scope
            ? `${args.scope.type}:${args.scope.id}`
            : "global";
          const effRole = await ctx.db
            .query("effectiveRoles")
            .withIndex("by_tenant_user_role_scope", (q) =>
              q
                .eq("tenantId", args.tenantId)
                .eq("userId", args.userId)
                .eq("role", args.role)
                .eq("scopeKey", scopeKey),
            )
            .unique();
          if (effRole) {
            await ctx.db.patch(effRole._id, {
              expiresAt: newExpiry,
              updatedAt: Date.now(),
            });
          }
          // 3. Update effectivePermissions for this role's permissions
          for (const permission of args.rolePermissions) {
            const effPerm = await ctx.db
              .query("effectivePermissions")
              .withIndex("by_tenant_user_permission_scope", (q) =>
                q
                  .eq("tenantId", args.tenantId)
                  .eq("userId", args.userId)
                  .eq("permission", permission)
                  .eq("scopeKey", scopeKey),
              )
              .unique();
            if (effPerm && effPerm.sources.includes(args.role)) {
              // Recompute merged expiresAt considering all sources
              // Since we can't cheaply check all other sources' expiry,
              // just set to the new (extended) value
              const mergedExpiry =
                effPerm.expiresAt === undefined
                  ? undefined
                  : newExpiry === undefined
                    ? undefined
                    : Math.max(effPerm.expiresAt, newExpiry);
              await ctx.db.patch(effPerm._id, {
                expiresAt: mergedExpiry,
                updatedAt: Date.now(),
              });
            }
          }
        }
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
          .eq("scopeKey", scopeKey),
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
            .eq("scopeKey", scopeKey),
        )
        .unique();

      if (existingPerm) {
        // Add role to sources if not already present
        const sources = existingPerm.sources.includes(args.role)
          ? existingPerm.sources
          : [...existingPerm.sources, args.role];
        // Also update policyResult if the new classification is more specific
        const patchData: Record<string, unknown> = { sources, updatedAt: now };
        if (classification === "deferred" && !existingPerm.policyResult) {
          patchData.policyResult = "deferred";
          patchData.policyName = permission;
        } else if (classification === "allow" && !existingPerm.policyResult) {
          patchData.policyResult = "allow";
        }
        // Compute merged expiresAt: no-expiry (undefined) wins over any expiry
        const existingExpiry = existingPerm.expiresAt;
        const newExpiry = args.expiresAt;
        const mergedExpiresAt =
          existingExpiry === undefined || newExpiry === undefined
            ? undefined
            : Math.max(existingExpiry, newExpiry);
        patchData.expiresAt = mergedExpiresAt;
        await ctx.db.patch(existingPerm._id, patchData);
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

/**
 * Unified Role Revocation
 *
 * Removes a role from BOTH source tables (roleAssignments) AND effective tables
 * (effectiveRoles, effectivePermissions) in a single transaction.
 */
export const revokeRoleUnified = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    role: v.string(),
    rolePermissions: v.array(v.string()),
    scope: scopeValidator,
    revokedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const now = Date.now();

    // 1. Compute scopeKey
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    // 2. Find the role assignment in roleAssignments
    const assignments = await ctx.db
      .query("roleAssignments")
      .withIndex("by_tenant_user_and_role", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("role", args.role),
      )
      .take(100);

    const assignment = assignments.find((row) =>
      scopeEquals(row.scope, args.scope),
    );

    if (!assignment) {
      return false;
    }

    // 3. Delete from roleAssignments
    await ctx.db.delete(assignment._id);

    // 4. Delete from effectiveRoles
    const effectiveRole = await ctx.db
      .query("effectiveRoles")
      .withIndex("by_tenant_user_role_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("role", args.role)
          .eq("scopeKey", scopeKey),
      )
      .unique();

    if (effectiveRole) {
      await ctx.db.delete(effectiveRole._id);
    }

    // 5. For each permission the revoked role granted, update effectivePermissions
    for (const permission of args.rolePermissions) {
      const effectivePerm = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user_permission_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("permission", permission)
            .eq("scopeKey", scopeKey),
        )
        .unique();

      if (!effectivePerm) continue;

      const updatedSources = effectivePerm.sources.filter(
        (s) => s !== args.role,
      );

      if (
        updatedSources.length === 0 &&
        !effectivePerm.directGrant &&
        !effectivePerm.directDeny
      ) {
        // No more sources, no direct grant, no direct deny — delete the row
        await ctx.db.delete(effectivePerm._id);
      } else if (updatedSources.length !== effectivePerm.sources.length) {
        // Role was in sources; patch with updated array
        await ctx.db.patch(effectivePerm._id, {
          sources: updatedSources,
          updatedAt: now,
        });
      }
    }

    // 6. Audit log
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: now,
        action: "role_revoked",
        userId: args.userId,
        actorId: args.revokedBy,
        details: {
          role: args.role,
          scope: args.scope,
        },
      });
    }

    // 7. Return true
    return true;
  },
});

/**
 * Unified Permission Grant
 *
 * Writes a direct permission grant to BOTH permissionOverrides (source of truth)
 * AND effectivePermissions (cache) in a single transaction.
 */
export const grantPermissionUnified = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    scope: scopeValidator,
    reason: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    createdBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const now = Date.now();

    // 1. Compute scopeKey
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    // 2. Upsert into permissionOverrides
    const existingOverrides = await ctx.db
      .query("permissionOverrides")
      .withIndex("by_tenant_user_and_permission", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("permission", args.permission),
      )
      .take(100);

    const existingOverride = existingOverrides.find((row) =>
      scopeEquals(row.scope, args.scope),
    );

    let overrideId: string;

    if (existingOverride) {
      await ctx.db.patch(existingOverride._id, {
        effect: "allow",
        reason: args.reason,
        expiresAt: args.expiresAt,
        createdBy: args.createdBy,
      });
      overrideId = existingOverride._id;
    } else {
      overrideId = await ctx.db.insert("permissionOverrides", {
        tenantId: args.tenantId,
        userId: args.userId,
        permission: args.permission,
        effect: "allow",
        scope: args.scope,
        reason: args.reason,
        expiresAt: args.expiresAt,
        createdBy: args.createdBy,
      });
    }

    // 3. Upsert into effectivePermissions
    const existingPerm = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user_permission_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("permission", args.permission)
          .eq("scopeKey", scopeKey),
      )
      .unique();

    if (existingPerm) {
      // Compute merged expiry: if existing row has sources with role-based grants,
      // the expiry should be the later of existing vs new (and undefined = no expiry wins)
      const mergedExpiresAt =
        existingPerm.sources.length > 0
          ? existingPerm.expiresAt === undefined || args.expiresAt === undefined
            ? undefined
            : Math.max(existingPerm.expiresAt, args.expiresAt)
          : args.expiresAt;

      await ctx.db.patch(existingPerm._id, {
        directGrant: true,
        directDeny: undefined,
        effect: "allow",
        policyResult: undefined, // explicit grant overrides any policy result
        policyName: undefined,
        reason: args.reason,
        expiresAt: mergedExpiresAt,
        updatedAt: now,
      });
    } else {
      await ctx.db.insert("effectivePermissions", {
        tenantId: args.tenantId,
        userId: args.userId,
        permission: args.permission,
        scopeKey,
        scope: args.scope,
        effect: "allow",
        sources: [],
        directGrant: true,
        reason: args.reason,
        expiresAt: args.expiresAt,
        createdAt: now,
        updatedAt: now,
      });
    }

    // 4. Audit log
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: now,
        action: "permission_granted",
        userId: args.userId,
        actorId: args.createdBy,
        details: {
          permission: args.permission,
          scope: args.scope,
        },
      });
    }

    // 5. Return override ID
    return overrideId;
  },
});

/**
 * Set Attribute With Recompute
 *
 * Writes a user attribute to userAttributes AND re-evaluates static policies
 * for that user by accepting pre-evaluated policy results from the client layer.
 *
 * The key insight: ABAC policy functions live in client-side TypeScript code,
 * NOT in the Convex component. The client pre-evaluates policies with the new
 * attribute value and passes the results as policyReEvaluations.
 */
export const setAttributeWithRecompute = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    key: v.string(),
    value: v.any(),
    setBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
    // v2: pre-evaluated policy results from client
    // Map of permission -> new policy result after attribute change
    policyReEvaluations: v.optional(
      v.record(v.string(), v.union(v.literal("allow"), v.literal("deny"))),
    ),
  },
  returns: v.string(), // attribute ID
  handler: async (ctx, args) => {
    const now = Date.now();

    // 1. Upsert into userAttributes using "by_tenant_user_and_key" index
    const existingAttr = await ctx.db
      .query("userAttributes")
      .withIndex("by_tenant_user_and_key", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("key", args.key),
      )
      .unique();

    let attributeId: string;

    if (existingAttr) {
      await ctx.db.patch(existingAttr._id, { value: args.value });
      attributeId = existingAttr._id;
    } else {
      attributeId = await ctx.db.insert("userAttributes", {
        tenantId: args.tenantId,
        userId: args.userId,
        key: args.key,
        value: args.value,
      });
    }

    // 2. Apply policyReEvaluations to effectivePermissions
    if (args.policyReEvaluations) {
      // Hoist query outside the loop to avoid N×full-scan
      const allEffectivePerms = await ctx.db
        .query("effectivePermissions")
        .withIndex("by_tenant_user", (q) =>
          q.eq("tenantId", args.tenantId).eq("userId", args.userId),
        )
        .take(4000);

      for (const [permission, newResult] of Object.entries(
        args.policyReEvaluations,
      )) {
        const matchingPerms = allEffectivePerms.filter(
          (p) => p.permission === permission,
        );

        for (const effectivePerm of matchingPerms) {
          if (newResult === "deny" && effectivePerm.effect === "allow") {
            // Mark as denied via policyResult
            await ctx.db.patch(effectivePerm._id, {
              policyResult: "deny",
              updatedAt: now,
            });
          } else if (
            newResult === "allow" &&
            effectivePerm.policyResult === "deny"
          ) {
            // Policy now allows — restore allow state
            await ctx.db.patch(effectivePerm._id, {
              policyResult: "allow",
              effect: "allow",
              updatedAt: now,
            });
          }
        }
      }
    }

    // 3. Audit log
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: now,
        action: "attribute_set",
        userId: args.userId,
        actorId: args.setBy,
        details: {
          attribute: {
            key: args.key,
            value:
              typeof args.value === "string" && args.value.length > 1000
                ? args.value.slice(0, 1000) + "...[truncated]"
                : args.value,
          },
        },
      });
    }

    // 4. Return the attribute ID
    return attributeId;
  },
});

/**
 * Unified Relation Add
 *
 * Writes a direct relationship to BOTH relationships (source of truth)
 * AND effectiveRelationships (materialized view) in a single transaction.
 *
 * Note: Only writes the direct relationship. Transitive closure
 * computation will be added in a future enhancement.
 */
export const addRelationUnified = mutation({
  args: {
    tenantId: v.string(),
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
    caveat: v.optional(v.string()),
    caveatContext: v.optional(v.any()),
    createdBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
    relationPermissions: v.optional(v.record(v.string(), v.array(v.string()))),
    traversalRules: v.optional(v.any()),
    maxDepth: v.optional(v.number()),
  },
  returns: v.string(), // relation ID
  handler: async (ctx, args) => {
    const now = Date.now();
    const maxDepth = args.maxDepth ?? 5;

    // 1. Check for duplicate in relationships (idempotent)
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
      // Check if effectiveRelationships is missing
      const existingEffective = await ctx.db
        .query("effectiveRelationships")
        .withIndex("by_tenant_subject_relation_object", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("subjectKey", `${args.subjectType}:${args.subjectId}`)
            .eq("relation", args.relation)
            .eq("objectKey", `${args.objectType}:${args.objectId}`),
        )
        .first();

      if (existingEffective) {
        // Path is already tracked in existingEffective.paths, return it
        const hasPath = existingEffective.paths.some(
          (p: any) => p.directRelationId === existing._id,
        );
        if (hasPath) return existing._id;
      }
    }

    // 2. Insert into relationships (source of truth)
    const relationId = existing
      ? existing._id
      : await ctx.db.insert("relationships", {
          tenantId: args.tenantId,
          subjectType: args.subjectType,
          subjectId: args.subjectId,
          relation: args.relation,
          objectType: args.objectType,
          objectId: args.objectId,
          createdBy: args.createdBy,
          createdAt: now,
          ...(args.caveat !== undefined ? { caveat: args.caveat } : {}),
          ...(args.caveatContext !== undefined
            ? { caveatContext: args.caveatContext }
            : {}),
        });

    // 3. Setup Traversal
    const rules = args.traversalRules || {};
    const queue: any[] = [];

    // Add the direct relationship path
    const directCaveats = args.caveat
      ? [{ caveatName: args.caveat, caveatContext: args.caveatContext }]
      : [];

    queue.push({
      subjectType: args.subjectType,
      subjectId: args.subjectId,
      relation: args.relation,
      objectType: args.objectType,
      objectId: args.objectId,
      directRelationId: relationId,
      baseEffectiveId: undefined,
      path: [relationId],
      caveats: directCaveats,
      depth: 0,
    });

    // Direction 2: Find existing paths that can be extended by this new relation
    for (const [targetKey, ruleList] of Object.entries(rules)) {
      const [targetType, targetRelation] = targetKey.split(":");
      for (const rule of ruleList as any[]) {
        if (
          rule.via === args.relation &&
          rule.through === args.subjectType &&
          targetType === args.objectType
        ) {
          // Find all existing paths where subject -> rule.inherit -> args.subjectId
          const basePaths = await ctx.db
            .query("effectiveRelationships")
            .withIndex("by_tenant_object", (q) =>
              q
                .eq("tenantId", args.tenantId)
                .eq("objectKey", `${args.subjectType}:${args.subjectId}`),
            )
            .take(1000);

          for (const bp of basePaths) {
            if (bp.relation !== rule.inherit) continue;

            for (const p of bp.paths) {
              // Cycle check
              if (p.path?.includes(relationId)) continue;

              queue.push({
                subjectType: bp.subjectType,
                subjectId: bp.subjectId,
                relation: targetRelation,
                objectType: args.objectType,
                objectId: args.objectId,
                directRelationId: relationId,
                baseEffectiveId: bp._id,
                path: [...(p.path || []), relationId],
                caveats: [...(p.caveats || []), ...directCaveats],
                depth: (p.depth || 0) + 1,
              });
            }
          }
        }
      }
    }

    // Process BFS Queue
    const affectedTuples = new Set<string>();

    while (queue.length > 0) {
      const current = queue.shift()!;

      // Stop if exceeding max depth
      if (current.depth > maxDepth) continue;

      // Insert or Update into effectiveRelationships
      const subjectKey = `${current.subjectType}:${current.subjectId}`;
      const objectKey = `${current.objectType}:${current.objectId}`;

      const existingEffectiveRow = await ctx.db
        .query("effectiveRelationships")
        .withIndex("by_tenant_subject_relation_object", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("subjectKey", subjectKey)
            .eq("relation", current.relation)
            .eq("objectKey", objectKey),
        )
        .first();

      let effectiveId: string;
      const newPathObj = {
        isDirect: current.baseEffectiveId === undefined,
        directRelationId: current.directRelationId,
        baseEffectiveId: current.baseEffectiveId,
        path: current.path,
        caveats: current.caveats,
        depth: current.depth,
      };

      if (existingEffectiveRow) {
        effectiveId = existingEffectiveRow._id;
        // Check if path already exists
        const hasPath = existingEffectiveRow.paths.some(
          (p: any) =>
            p.directRelationId === current.directRelationId &&
            p.baseEffectiveId === current.baseEffectiveId,
        );
        if (!hasPath) {
          const newPaths = [...existingEffectiveRow.paths, newPathObj];
          await ctx.db.patch(existingEffectiveRow._id, {
            paths: newPaths,
            involvedTokens: buildInvolvedTokens(newPaths),
          });
        } else {
          continue; // Already processed this exact path extension
        }
      } else {
        effectiveId = await ctx.db.insert("effectiveRelationships", {
          tenantId: args.tenantId,
          subjectKey,
          subjectType: current.subjectType,
          subjectId: current.subjectId,
          relation: current.relation,
          objectKey,
          objectType: current.objectType,
          objectId: current.objectId,
          paths: [newPathObj],
          involvedTokens: buildInvolvedTokens([newPathObj]),
          createdBy: args.createdBy,
          createdAt: now,
        });
      }

      // Track tuple for permission updates
      affectedTuples.add(
        `${current.subjectType}:${current.subjectId}:${current.relation}:${current.objectType}:${current.objectId}`,
      );

      // Step 3: Direction 1 - find rules that extend forward from the newly inserted effectiveRelationship
      for (const [targetKey, ruleList] of Object.entries(rules)) {
        const [targetType, targetRelation] = targetKey.split(":");
        for (const rule of ruleList as any[]) {
          if (
            rule.inherit === current.relation &&
            rule.through === current.objectType
          ) {
            // Find direct relations to extend with
            const directPaths = await ctx.db
              .query("relationships")
              .withIndex("by_tenant_subject_relation_object", (q) =>
                q
                  .eq("tenantId", args.tenantId)
                  .eq("subjectType", current.objectType)
                  .eq("subjectId", current.objectId)
                  .eq("relation", rule.via)
                  .eq("objectType", targetType),
              )
              .take(100);

            for (const dp of directPaths) {
              if (current.path.includes(dp._id)) continue; // cycle detection

              const newCaveats = dp.caveat
                ? [{ caveatName: dp.caveat, caveatContext: dp.caveatContext }]
                : [];
              queue.push({
                subjectType: current.subjectType,
                subjectId: current.subjectId,
                relation: targetRelation,
                objectType: targetType,
                objectId: dp.objectId,
                directRelationId: dp._id,
                baseEffectiveId: effectiveId,
                path: [...current.path, dp._id],
                caveats: [...current.caveats, ...newCaveats],
                depth: current.depth + 1,
              });
            }
          }
        }
      }
    }

    // 4. Bridge: write relation-derived permissions to effectivePermissions
    for (const tuple of affectedTuples) {
      const [subjType, subjId, rel, objType, objId] = tuple.split(":");
      await updatePermissionsForRelation(
        ctx,
        args.tenantId,
        subjType,
        subjId,
        rel,
        objType,
        objId,
        args.relationPermissions,
        now,
      );
    }

    // 5. Audit log
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: now,
        action: "relation_added",
        userId:
          args.subjectType === "user"
            ? args.subjectId
            : (args.createdBy ?? "system"),
        actorId: args.createdBy,
        details: {
          relation: args.relation,
          subject: `${args.subjectType}:${args.subjectId}`,
          object: `${args.objectType}:${args.objectId}`,
        },
      });
    }

    // 6. Return relation ID
    return relationId as string;
  },
});

/**
 * Unified Relation Remove
 *
 * Removes a relationship from BOTH relationships (source of truth)
 * AND effectiveRelationships (materialized view) in a single transaction.
 * Also cleans up any inherited relationships derived from this one.
 */
export const removeRelationUnified = mutation({
  args: {
    tenantId: v.string(),
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
    removedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
    relationPermissions: v.optional(v.record(v.string(), v.array(v.string()))),
    traversalRules: v.optional(v.any()), // included for symmetry, though not strictly needed for deletion
  },
  returns: v.boolean(), // true if found and removed
  handler: async (ctx, args) => {
    const now = Date.now();

    // 1. Find in relationships
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

    if (!existing) {
      return false;
    }

    // 2. Delete from relationships
    await ctx.db.delete(existing._id);

    // 3. Delete cascading effectiveRelationships
    const affectedTuples = new Set<string>();

    // V2: Query utilizing the `search_involved_tokens` index.
    // This allows us to quickly find ONLY the effectiveRelationships that depend on the
    // deleted direct relationship (`existing._id`), bypassing the need to scan all tenant tuples!
    const tokenQuery = args.tenantId
      ? ctx.db
          .query("effectiveRelationships")
          .withSearchIndex("search_involved_tokens", (q) =>
            q
              .search("involvedTokens", existing._id)
              .eq("tenantId", args.tenantId),
          )
      : ctx.db
          .query("effectiveRelationships")
          .withSearchIndex("search_involved_tokens", (q) =>
            q.search("involvedTokens", existing._id),
          );

    const affectedRows = await tokenQuery.take(1000);
    console.log(
      "affectedRows count for",
      existing._id,
      "is",
      affectedRows.length,
    );

    for (const de of affectedRows) {
      let isModified = false;
      let currentPaths = de.paths;
      let prevLength = currentPaths.length;

      // Keep filtering until no more paths are removed (to handle cascading paths within the same row)
      while (true) {
        currentPaths = currentPaths.filter(
          (p: any) =>
            p.directRelationId !== existing._id &&
            !p.path?.includes(existing._id) &&
            // Also filter out if baseEffectiveId was in this very row and that path was just removed
            !(
              de._id === p.baseEffectiveId &&
              !currentPaths.some(
                (cp: any) => cp.directRelationId === p.baseEffectiveId,
              )
            ),
        );

        if (currentPaths.length === prevLength) break;
        isModified = true;
        prevLength = currentPaths.length;
      }

      if (isModified || de.paths.length !== currentPaths.length) {
        if (currentPaths.length === 0) {
          await ctx.db.delete(de._id);
        } else {
          await ctx.db.patch(de._id, {
            paths: currentPaths,
            involvedTokens: buildInvolvedTokens(currentPaths),
          });
        }

        affectedTuples.add(
          `${de.subjectType}:${de.subjectId}:${de.relation}:${de.objectType}:${de.objectId}`,
        );
      }
    }

    // 4. Bridge: re-evaluate relation-derived permissions
    for (const tuple of affectedTuples) {
      const [subjType, subjId, rel, objType, objId] = tuple.split(":");
      await updatePermissionsForRelation(
        ctx,
        args.tenantId,
        subjType,
        subjId,
        rel,
        objType,
        objId,
        args.relationPermissions,
        now,
      );
    }

    // 5. Audit log
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: now,
        action: "relation_removed",
        userId:
          args.subjectType === "user"
            ? args.subjectId
            : (args.removedBy ?? "system"),
        actorId: args.removedBy,
        details: {
          relation: args.relation,
          subject: `${args.subjectType}:${args.subjectId}`,
          object: `${args.objectType}:${args.objectId}`,
        },
      });
    }

    // 6. Return true
    return true;
  },
});

/**
 * Recompute User
 *
 * Full recomputation of a user's effective tables from source tables.
 * Designed for post-deploy rebuilds when role<->permission mappings change.
 *
 * Algorithm:
 *   1. Delete all effectiveRoles for this user.
 *   2. Delete all effectivePermissions for this user that are NOT directGrant or directDeny.
 *   3. Read all current roleAssignments for this user.
 *   4. For each non-expired role assignment, re-insert effectiveRoles and upsert effectivePermissions.
 */
export const recomputeUser = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    rolePermissionsMap: v.record(v.string(), v.array(v.string())),
    policyClassifications: v.optional(
      v.record(
        v.string(),
        v.union(
          v.null(),
          v.literal("allow"),
          v.literal("deny"),
          v.literal("deferred"),
        ),
      ),
    ),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const now = Date.now();

    // ── Step 1: Delete all effectiveRoles for this user ──────────────────
    const existingEffectiveRoles = await ctx.db
      .query("effectiveRoles")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId),
      )
      .take(4000);

    for (const row of existingEffectiveRoles) {
      await ctx.db.delete(row._id);
    }

    // ── Step 2: Delete non-direct effectivePermissions for this user ─────
    const existingEffectivePerms = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId),
      )
      .take(4000);

    for (const row of existingEffectivePerms) {
      // Keep direct grants and direct denies — those come from permissionOverrides
      if (row.directGrant === true || row.directDeny === true) {
        // Clear stale policy data from direct rows
        if (row.policyResult !== undefined) {
          await ctx.db.patch(row._id, {
            policyResult: undefined,
            policyName: undefined,
          });
        }
        continue;
      }
      await ctx.db.delete(row._id);
    }

    // ── Step 3: Read all current roleAssignments for this user ───────────
    const roleAssignments = await ctx.db
      .query("roleAssignments")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId),
      )
      .take(4000);

    // ── Step 4: Rebuild effectiveRoles and effectivePermissions ──────────
    for (const assignment of roleAssignments) {
      // Skip expired assignments
      if (assignment.expiresAt !== undefined && assignment.expiresAt < now) {
        continue;
      }

      const scopeKey = assignment.scope
        ? `${assignment.scope.type}:${assignment.scope.id}`
        : "global";

      // Insert into effectiveRoles
      await ctx.db.insert("effectiveRoles", {
        tenantId: args.tenantId,
        userId: args.userId,
        role: assignment.role,
        scopeKey,
        scope: assignment.scope,
        assignedBy: assignment.assignedBy,
        expiresAt: assignment.expiresAt,
        createdAt: now,
        updatedAt: now,
      });

      // Look up permissions for this role from rolePermissionsMap
      const permissions = args.rolePermissionsMap[assignment.role] ?? [];

      for (const permission of permissions) {
        const classification = args.policyClassifications?.[permission] ?? null;

        // Skip if policy evaluated to "deny"
        if (classification === "deny") {
          continue;
        }

        // Check if an effectivePermissions row already exists (could be a direct grant/deny kept above)
        const existingPerm = await ctx.db
          .query("effectivePermissions")
          .withIndex("by_tenant_user_permission_scope", (q) =>
            q
              .eq("tenantId", args.tenantId)
              .eq("userId", args.userId)
              .eq("permission", permission)
              .eq("scopeKey", scopeKey),
          )
          .unique();

        if (existingPerm) {
          // Add role to sources if not already present
          const sources = existingPerm.sources.includes(assignment.role)
            ? existingPerm.sources
            : [...existingPerm.sources, assignment.role];
          // Compute merged expiresAt: no-expiry (undefined) wins over any expiry
          const existingExpiry = existingPerm.expiresAt;
          const newExpiry = assignment.expiresAt;
          const mergedExpiresAt =
            existingExpiry === undefined || newExpiry === undefined
              ? undefined
              : Math.max(existingExpiry, newExpiry);
          const patchData: Record<string, unknown> = {
            sources,
            expiresAt: mergedExpiresAt,
            updatedAt: now,
          };
          // Propagate policyClassifications to existing rows (e.g., directGrant rows preserved in step 2)
          if (
            classification === "deferred" &&
            existingPerm.policyResult !== "deferred"
          ) {
            patchData.policyResult = "deferred";
            patchData.policyName = permission;
          } else if (classification === "allow" && !existingPerm.policyResult) {
            patchData.policyResult = "allow";
          }
          await ctx.db.patch(existingPerm._id, patchData);
        } else {
          await ctx.db.insert("effectivePermissions", {
            tenantId: args.tenantId,
            userId: args.userId,
            permission,
            scopeKey,
            scope: assignment.scope,
            effect: "allow",
            sources: [assignment.role],
            expiresAt: assignment.expiresAt,
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
    }

    return null;
  },
});

export const denyPermissionUnified = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    scope: scopeValidator,
    reason: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    createdBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const now = Date.now();

    // 1. Compute scopeKey
    const scopeKey = args.scope
      ? `${args.scope.type}:${args.scope.id}`
      : "global";

    // 2. Upsert into permissionOverrides with effect: "deny"
    const existingOverrides = await ctx.db
      .query("permissionOverrides")
      .withIndex("by_tenant_user_and_permission", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("permission", args.permission),
      )
      .take(100);

    const existingOverride = existingOverrides.find((row) =>
      scopeEquals(row.scope, args.scope),
    );

    let overrideId: string;

    if (existingOverride) {
      await ctx.db.patch(existingOverride._id, {
        effect: "deny",
        reason: args.reason,
        expiresAt: args.expiresAt,
        createdBy: args.createdBy,
      });
      overrideId = existingOverride._id;
    } else {
      overrideId = await ctx.db.insert("permissionOverrides", {
        tenantId: args.tenantId,
        userId: args.userId,
        permission: args.permission,
        effect: "deny",
        scope: args.scope,
        reason: args.reason,
        expiresAt: args.expiresAt,
        createdBy: args.createdBy,
      });
    }

    // 3. Upsert into effectivePermissions with effect: "deny", directDeny: true
    const existingPerm = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user_permission_scope", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("permission", args.permission)
          .eq("scopeKey", scopeKey),
      )
      .unique();

    if (existingPerm) {
      // Compute merged expiry: if existing row has sources with role-based grants,
      // the expiry should be the later of existing vs new (and undefined = no expiry wins)
      const mergedExpiresAt =
        existingPerm.sources.length > 0
          ? existingPerm.expiresAt === undefined || args.expiresAt === undefined
            ? undefined
            : Math.max(existingPerm.expiresAt, args.expiresAt)
          : args.expiresAt;

      await ctx.db.patch(existingPerm._id, {
        directDeny: true,
        directGrant: undefined,
        effect: "deny",
        reason: args.reason,
        expiresAt: mergedExpiresAt,
        updatedAt: now,
      });
    } else {
      await ctx.db.insert("effectivePermissions", {
        tenantId: args.tenantId,
        userId: args.userId,
        permission: args.permission,
        scopeKey,
        scope: args.scope,
        effect: "deny",
        sources: [],
        directDeny: true,
        reason: args.reason,
        expiresAt: args.expiresAt,
        createdAt: now,
        updatedAt: now,
      });
    }

    // 4. Audit log
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: now,
        action: "permission_denied",
        userId: args.userId,
        actorId: args.createdBy,
        details: {
          permission: args.permission,
          scope: args.scope,
        },
      });
    }

    // 5. Return override ID
    return overrideId;
  },
});

// Must match MAX_BULK_ROLES in client/validation.ts — duplicated here
// because component code cannot import from client.
const MAX_BULK_ROLES = 20;

/**
 * Unified Bulk Role Assignment
 *
 * Assigns multiple roles to a user, writing to BOTH source tables (roleAssignments)
 * AND effective tables (effectiveRoles, effectivePermissions) in a single transaction.
 */
export const assignRolesUnified = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    roles: v.array(
      v.object({
        role: v.string(),
        scope: scopeValidator,
        expiresAt: v.optional(v.number()),
        metadata: v.optional(v.any()),
      }),
    ),
    rolePermissionsMap: v.record(v.string(), v.array(v.string())),
    assignedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
    policyClassifications: v.optional(
      v.record(
        v.string(),
        v.union(
          v.null(),
          v.literal("allow"),
          v.literal("deny"),
          v.literal("deferred"),
        ),
      ),
    ),
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
        `roles must not exceed ${MAX_BULK_ROLES} items (got ${args.roles.length})`,
      );
    }

    const now = Date.now();
    const assignmentIds: string[] = [];
    let assigned = 0;

    for (const item of args.roles) {
      // 1. Compute scopeKey
      const scopeKey = item.scope
        ? `${item.scope.type}:${item.scope.id}`
        : "global";

      // 2. Check for duplicate in roleAssignments
      const existing = await ctx.db
        .query("roleAssignments")
        .withIndex("by_tenant_user_and_role", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("role", item.role),
        )
        .take(100);

      let isDuplicate = false;
      for (const row of existing) {
        if (scopeEquals(row.scope, item.scope) && !isExpired(row.expiresAt)) {
          // Extend expiry: only update if new value is later or removes expiry entirely.
          // Passing a shorter expiresAt is a no-op (prevents accidental expiry reduction).
          // To shorten expiry, revoke and re-assign.
          const shouldExtend =
            item.expiresAt === undefined ||
            (row.expiresAt !== undefined && item.expiresAt > row.expiresAt);
          if (shouldExtend && item.expiresAt !== row.expiresAt) {
            const newExpiry = item.expiresAt;
            // Update source table
            await ctx.db.patch(row._id, { expiresAt: newExpiry });
            // Update effectiveRoles
            const effRole = await ctx.db
              .query("effectiveRoles")
              .withIndex("by_tenant_user_role_scope", (q) =>
                q
                  .eq("tenantId", args.tenantId)
                  .eq("userId", args.userId)
                  .eq("role", item.role)
                  .eq("scopeKey", scopeKey),
              )
              .unique();
            if (effRole) {
              await ctx.db.patch(effRole._id, {
                expiresAt: newExpiry,
                updatedAt: now,
              });
            }
            // Update effectivePermissions for this role's permissions
            const permissions = args.rolePermissionsMap[item.role] ?? [];
            for (const permission of permissions) {
              const effPerm = await ctx.db
                .query("effectivePermissions")
                .withIndex("by_tenant_user_permission_scope", (q) =>
                  q
                    .eq("tenantId", args.tenantId)
                    .eq("userId", args.userId)
                    .eq("permission", permission)
                    .eq("scopeKey", scopeKey),
                )
                .unique();
              if (effPerm && effPerm.sources.includes(item.role)) {
                const mergedExpiry =
                  effPerm.expiresAt === undefined
                    ? undefined
                    : newExpiry === undefined
                      ? undefined
                      : Math.max(effPerm.expiresAt, newExpiry);
                await ctx.db.patch(effPerm._id, {
                  expiresAt: mergedExpiry,
                  updatedAt: now,
                });
              }
            }
          }
          isDuplicate = true;
          break;
        }
      }

      if (isDuplicate) {
        continue;
      }

      // 3. Insert into roleAssignments (source of truth)
      const assignmentId = await ctx.db.insert("roleAssignments", {
        tenantId: args.tenantId,
        userId: args.userId,
        role: item.role,
        scope: item.scope,
        expiresAt: item.expiresAt,
        assignedBy: args.assignedBy,
        metadata: item.metadata,
      });
      assignmentIds.push(assignmentId as string);
      assigned++;

      // 4. Upsert into effectiveRoles
      const existingEffectiveRole = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user_role_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("role", item.role)
            .eq("scopeKey", scopeKey),
        )
        .unique();

      if (existingEffectiveRole) {
        await ctx.db.patch(existingEffectiveRole._id, {
          assignedBy: args.assignedBy,
          expiresAt: item.expiresAt,
          updatedAt: now,
        });
      } else {
        await ctx.db.insert("effectiveRoles", {
          tenantId: args.tenantId,
          userId: args.userId,
          role: item.role,
          scopeKey,
          scope: item.scope,
          assignedBy: args.assignedBy,
          expiresAt: item.expiresAt,
          createdAt: now,
          updatedAt: now,
        });
      }

      // 5. Process each permission the role grants (from rolePermissionsMap)
      const permissions = args.rolePermissionsMap[item.role] ?? [];
      for (const permission of permissions) {
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
              .eq("scopeKey", scopeKey),
          )
          .unique();

        if (existingPerm) {
          // Add role to sources if not already present
          const sources = existingPerm.sources.includes(item.role)
            ? existingPerm.sources
            : [...existingPerm.sources, item.role];
          const patchData: Record<string, unknown> = {
            sources,
            updatedAt: now,
          };
          if (classification === "deferred" && !existingPerm.policyResult) {
            patchData.policyResult = "deferred";
            patchData.policyName = permission;
          } else if (classification === "allow" && !existingPerm.policyResult) {
            patchData.policyResult = "allow";
          }
          // Compute merged expiresAt: no-expiry (undefined) wins over any expiry
          const existingExpiry = existingPerm.expiresAt;
          const newExpiry = item.expiresAt;
          const mergedExpiresAt =
            existingExpiry === undefined || newExpiry === undefined
              ? undefined
              : Math.max(existingExpiry, newExpiry);
          patchData.expiresAt = mergedExpiresAt;
          await ctx.db.patch(existingPerm._id, patchData);
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

      // 6. Audit log entry per role if enableAudit
      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: now,
          action: "role_assigned",
          userId: args.userId,
          actorId: args.assignedBy,
          details: {
            role: item.role,
            scope: item.scope,
          },
        });
      }
    }

    return { assigned, assignmentIds };
  },
});

/**
 * Unified Bulk Role Revocation
 *
 * Revokes multiple roles from a user, removing from BOTH source tables (roleAssignments)
 * AND effective tables (effectiveRoles, effectivePermissions) in a single transaction.
 */
export const revokeRolesUnified = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    roles: v.array(
      v.object({
        role: v.string(),
        scope: scopeValidator,
      }),
    ),
    rolePermissionsMap: v.record(v.string(), v.array(v.string())),
    revokedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.object({ revoked: v.number() }),
  handler: async (ctx, args) => {
    if (args.roles.length === 0) {
      return { revoked: 0 };
    }
    if (args.roles.length > MAX_BULK_ROLES) {
      throw new Error(
        `roles must not exceed ${MAX_BULK_ROLES} items (got ${args.roles.length})`,
      );
    }

    const now = Date.now();
    let revoked = 0;

    for (const item of args.roles) {
      // 1. Compute scopeKey
      const scopeKey = item.scope
        ? `${item.scope.type}:${item.scope.id}`
        : "global";

      // 2. Find the role assignment in roleAssignments
      const assignments = await ctx.db
        .query("roleAssignments")
        .withIndex("by_tenant_user_and_role", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("role", item.role),
        )
        .take(100);

      const assignment = assignments.find((row) =>
        scopeEquals(row.scope, item.scope),
      );

      if (!assignment) {
        continue;
      }

      // 3. Delete from roleAssignments
      await ctx.db.delete(assignment._id);
      revoked++;

      // 4. Delete from effectiveRoles
      const effectiveRole = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user_role_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("role", item.role)
            .eq("scopeKey", scopeKey),
        )
        .unique();

      if (effectiveRole) {
        await ctx.db.delete(effectiveRole._id);
      }

      // 5. For each permission the role grants, update effectivePermissions
      const permissions = args.rolePermissionsMap[item.role] ?? [];
      for (const permission of permissions) {
        const effectivePerm = await ctx.db
          .query("effectivePermissions")
          .withIndex("by_tenant_user_permission_scope", (q) =>
            q
              .eq("tenantId", args.tenantId)
              .eq("userId", args.userId)
              .eq("permission", permission)
              .eq("scopeKey", scopeKey),
          )
          .unique();

        if (!effectivePerm) continue;

        const updatedSources = effectivePerm.sources.filter(
          (s) => s !== item.role,
        );

        if (
          updatedSources.length === 0 &&
          !effectivePerm.directGrant &&
          !effectivePerm.directDeny
        ) {
          // No more sources, no direct grant, no direct deny — delete the row
          await ctx.db.delete(effectivePerm._id);
        } else if (updatedSources.length !== effectivePerm.sources.length) {
          // Role was in sources; patch with updated array
          await ctx.db.patch(effectivePerm._id, {
            sources: updatedSources,
            updatedAt: now,
          });
        }
      }

      // 6. Audit log if enableAudit
      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: now,
          action: "role_revoked",
          userId: args.userId,
          actorId: args.revokedBy,
          details: {
            role: item.role,
            scope: item.scope,
          },
        });
      }
    }

    return { revoked };
  },
});

/**
 * Unified Revoke All Roles
 *
 * Revokes all roles from a user (optionally scoped), removing from BOTH source tables
 * (roleAssignments) AND effective tables (effectiveRoles, effectivePermissions) in a single transaction.
 */
export const revokeAllRolesUnified = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    scope: scopeValidator,
    rolePermissionsMap: v.record(v.string(), v.array(v.string())),
    revokedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.number(), // count of roles revoked
  handler: async (ctx, args) => {
    const now = Date.now();

    // 1. Find all roleAssignments for user
    const assignments = await ctx.db
      .query("roleAssignments")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId),
      )
      .take(4000);

    let revokedCount = 0;

    for (const assignment of assignments) {
      // Skip expired assignments
      if (isExpired(assignment.expiresAt)) continue;

      // Filter by scope if provided
      if (args.scope) {
        if (!assignment.scope) continue;
        if (
          assignment.scope.type !== args.scope.type ||
          assignment.scope.id !== args.scope.id
        ) {
          continue;
        }
      }

      const scopeKey = assignment.scope
        ? `${assignment.scope.type}:${assignment.scope.id}`
        : "global";

      // 2. Delete from roleAssignments
      await ctx.db.delete(assignment._id);
      revokedCount++;

      // 3. Delete from effectiveRoles
      const effectiveRole = await ctx.db
        .query("effectiveRoles")
        .withIndex("by_tenant_user_role_scope", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("role", assignment.role)
            .eq("scopeKey", scopeKey),
        )
        .unique();

      if (effectiveRole) {
        await ctx.db.delete(effectiveRole._id);
      }

      // 4. For each permission the role grants, update effectivePermissions
      const permissions = args.rolePermissionsMap[assignment.role] ?? [];
      for (const permission of permissions) {
        const effectivePerm = await ctx.db
          .query("effectivePermissions")
          .withIndex("by_tenant_user_permission_scope", (q) =>
            q
              .eq("tenantId", args.tenantId)
              .eq("userId", args.userId)
              .eq("permission", permission)
              .eq("scopeKey", scopeKey),
          )
          .unique();

        if (!effectivePerm) continue;

        const updatedSources = effectivePerm.sources.filter(
          (s) => s !== assignment.role,
        );

        if (
          updatedSources.length === 0 &&
          !effectivePerm.directGrant &&
          !effectivePerm.directDeny
        ) {
          await ctx.db.delete(effectivePerm._id);
        } else if (updatedSources.length !== effectivePerm.sources.length) {
          await ctx.db.patch(effectivePerm._id, {
            sources: updatedSources,
            updatedAt: now,
          });
        }
      }

      // 5. Audit log if enableAudit
      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: now,
          action: "role_revoked",
          userId: args.userId,
          actorId: args.revokedBy,
          details: {
            role: assignment.role,
            scope: assignment.scope,
          },
        });
      }
    }

    return revokedCount;
  },
});
