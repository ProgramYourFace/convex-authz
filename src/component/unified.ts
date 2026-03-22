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
          .eq("role", args.role)
      )
      .collect();

    const assignment = assignments.find(
      (row) => matchesScope(row.scope, args.scope) && !isExpired(row.expiresAt)
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
          .eq("scopeKey", scopeKey)
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
            .eq("scopeKey", scopeKey)
        )
        .unique();

      if (!effectivePerm) continue;

      const updatedSources = effectivePerm.sources.filter(
        (s) => s !== args.role
      );

      if (updatedSources.length === 0 && !effectivePerm.directGrant) {
        // No more sources and no direct grant — delete the row
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
          .eq("permission", args.permission)
      )
      .collect();

    const existingOverride = existingOverrides.find((row) =>
      matchesScope(row.scope, args.scope)
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
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (existingPerm) {
      await ctx.db.patch(existingPerm._id, {
        directGrant: true,
        effect: "allow",
        reason: args.reason,
        expiresAt: args.expiresAt,
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
    policyReEvaluations: v.optional(v.record(v.string(), v.union(
      v.literal("allow"),
      v.literal("deny"),
    ))),
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
          .eq("key", args.key)
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
      for (const [permission, newResult] of Object.entries(args.policyReEvaluations)) {
        const effectivePerm = await ctx.db
          .query("effectivePermissions")
          .withIndex("by_tenant_user_permission_scope", (q) =>
            q
              .eq("tenantId", args.tenantId)
              .eq("userId", args.userId)
              .eq("permission", permission)
              .eq("scopeKey", "global")
          )
          .unique();

        if (!effectivePerm || !effectivePerm.policyName) {
          // Only re-evaluate rows that have a policyName (policy-governed permissions)
          continue;
        }

        if (newResult === "deny" && effectivePerm.effect === "allow") {
          if (effectivePerm.directGrant) {
            // Has a direct grant — update policyResult to deny but keep the row
            await ctx.db.patch(effectivePerm._id, {
              policyResult: "deny",
              updatedAt: now,
            });
          } else {
            // No direct grant — mark as denied via policyResult
            await ctx.db.patch(effectivePerm._id, {
              policyResult: "deny",
              updatedAt: now,
            });
          }
        } else if (newResult === "allow" && effectivePerm.policyResult === "deny") {
          // Policy now allows — restore allow state
          await ctx.db.patch(effectivePerm._id, {
            policyResult: "allow",
            effect: "allow",
            updatedAt: now,
          });
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
            value: args.value,
          },
        },
      });
    }

    // 4. Return the attribute ID
    return attributeId;
  },
});

/**
 * Unified Permission Deny
 *
 * Writes a direct permission denial to BOTH permissionOverrides (source of truth)
 * AND effectivePermissions (cache) in a single transaction.
 * Direct deny ALWAYS wins — overrides existing allow.
 */
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
  },
  returns: v.string(), // relation ID
  handler: async (ctx, args) => {
    const now = Date.now();

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
          .eq("objectId", args.objectId)
      )
      .unique();

    if (existing) {
      return existing._id;
    }

    // 2. Insert into relationships (source of truth)
    const relationId = await ctx.db.insert("relationships", {
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

    // 3. Insert into effectiveRelationships (materialized)
    const subjectKey = `${args.subjectType}:${args.subjectId}`;
    const objectKey = `${args.objectType}:${args.objectId}`;

    await ctx.db.insert("effectiveRelationships", {
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
      createdAt: now,
      depth: 0,
    });

    // 4. Audit log
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: now,
        action: "relation_added",
        userId: `${args.subjectType}:${args.subjectId}`,
        actorId: args.createdBy,
        details: {
          scope: undefined,
        },
      });
    }

    // 5. Return relation ID
    return relationId;
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
    enableAudit: v.optional(v.boolean()),
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
          .eq("objectId", args.objectId)
      )
      .unique();

    if (!existing) {
      return false;
    }

    // 2. Delete from relationships
    await ctx.db.delete(existing._id);

    // 3. Find and delete from effectiveRelationships
    const subjectKey = `${args.subjectType}:${args.subjectId}`;
    const objectKey = `${args.objectType}:${args.objectId}`;

    const effectiveRel = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_tenant_subject_relation_object", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("subjectKey", subjectKey)
          .eq("relation", args.relation)
          .eq("objectKey", objectKey)
      )
      .unique();

    if (effectiveRel) {
      await ctx.db.delete(effectiveRel._id);
    }

    // 4. Delete any inherited relationships that point to this one
    const inherited = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_tenant_inherited_from", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("inheritedFrom", existing._id)
      )
      .collect();

    for (const row of inherited) {
      await ctx.db.delete(row._id);
    }

    // 5. Audit log
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: now,
        action: "relation_removed",
        userId: `${args.subjectType}:${args.subjectId}`,
        details: {
          scope: undefined,
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
    policyClassifications: v.optional(v.record(v.string(), v.union(
      v.null(),
      v.literal("allow"),
      v.literal("deny"),
      v.literal("deferred"),
    ))),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const now = Date.now();

    // ── Step 1: Delete all effectiveRoles for this user ──────────────────
    const existingEffectiveRoles = await ctx.db
      .query("effectiveRoles")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId)
      )
      .collect();

    for (const row of existingEffectiveRoles) {
      await ctx.db.delete(row._id);
    }

    // ── Step 2: Delete non-direct effectivePermissions for this user ─────
    const existingEffectivePerms = await ctx.db
      .query("effectivePermissions")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId)
      )
      .collect();

    for (const row of existingEffectivePerms) {
      // Keep direct grants and direct denies — those come from permissionOverrides
      if (row.directGrant === true || row.directDeny === true) {
        continue;
      }
      await ctx.db.delete(row._id);
    }

    // ── Step 3: Read all current roleAssignments for this user ───────────
    const roleAssignments = await ctx.db
      .query("roleAssignments")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId)
      )
      .collect();

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
              .eq("scopeKey", scopeKey)
          )
          .unique();

        if (existingPerm) {
          // Add role to sources if not already present
          const sources = existingPerm.sources.includes(assignment.role)
            ? existingPerm.sources
            : [...existingPerm.sources, assignment.role];
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
            scope: assignment.scope,
            effect: "allow",
            sources: [assignment.role],
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
          .eq("permission", args.permission)
      )
      .collect();

    const existingOverride = existingOverrides.find((row) =>
      matchesScope(row.scope, args.scope)
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
          .eq("scopeKey", scopeKey)
      )
      .unique();

    if (existingPerm) {
      await ctx.db.patch(existingPerm._id, {
        directDeny: true,
        effect: "deny",
        reason: args.reason,
        expiresAt: args.expiresAt,
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
