import { v, ConvexError } from "convex/values";
import { mutation } from "./_generated/server";
import { isExpired } from "./helpers";
import { scopeValidator } from "./validators";

const MAX_BULK_ROLES = 100;

/**
 * Assign a role to a user
 */
export const assignRole = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    role: v.string(),
    scope: scopeValidator,
    metadata: v.optional(v.any()),
    assignedBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    // Check if this exact role assignment already exists
    const existingAssignments = await ctx.db
      .query("roleAssignments")
      .withIndex("by_tenant_user_and_role", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("role", args.role),
      )
      .collect();

    // Check for duplicate (same role + same scope)
    const duplicate = existingAssignments.find((a) => {
      if (isExpired(a.expiresAt)) return false;

      // Compare scopes
      if (!a.scope && !args.scope) return true;
      if (!a.scope || !args.scope) return false;
      return a.scope.type === args.scope.type && a.scope.id === args.scope.id;
    });

    if (duplicate) {
      throw new ConvexError({
        code: "ALREADY_EXISTS",
        message: `User already has role "${args.role}" with the same scope`,
      });
    }

    // Create the role assignment
    const assignmentId = await ctx.db.insert("roleAssignments", {
      tenantId: args.tenantId,
      userId: args.userId,
      role: args.role,
      scope: args.scope,
      metadata: args.metadata,
      assignedBy: args.assignedBy,
      expiresAt: args.expiresAt,
    });

    // Log audit entry if enabled
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: Date.now(),
        action: "role_assigned",
        userId: args.userId,
        actorId: args.assignedBy,
        details: {
          role: args.role,
          scope: args.scope,
        },
      });
    }

    return assignmentId as string;
  },
});

/**
 * Revoke a role from a user
 */
export const revokeRole = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    role: v.string(),
    scope: scopeValidator,
    revokedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const assignments = await ctx.db
      .query("roleAssignments")
      .withIndex("by_tenant_user_and_role", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("role", args.role),
      )
      .collect();

    // Find matching assignment (same scope)
    const toRevoke = assignments.find((a) => {
      if (!a.scope && !args.scope) return true;
      if (!a.scope || !args.scope) return false;
      return a.scope.type === args.scope.type && a.scope.id === args.scope.id;
    });

    if (!toRevoke) {
      return false;
    }

    await ctx.db.delete(toRevoke._id);

    // Log audit entry if enabled
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: Date.now(),
        action: "role_revoked",
        userId: args.userId,
        actorId: args.revokedBy,
        details: {
          role: args.role,
          scope: args.scope,
        },
      });
    }

    return true;
  },
});

/**
 * Revoke all roles from a user
 */
export const revokeAllRoles = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    scope: scopeValidator,
    revokedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.number(),
  handler: async (ctx, args) => {
    const assignments = await ctx.db
      .query("roleAssignments")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId),
      )
      .collect();

    let revokedCount = 0;

    for (const assignment of assignments) {
      // If scope is specified, only revoke matching scope
      if (args.scope) {
        if (!assignment.scope) continue;
        if (
          assignment.scope.type !== args.scope.type ||
          assignment.scope.id !== args.scope.id
        ) {
          continue;
        }
      }

      await ctx.db.delete(assignment._id);
      revokedCount++;

      // Log audit entry if enabled
      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: Date.now(),
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

/**
 * Assign multiple roles to a user in a single transaction.
 */
export const assignRoles = mutation({
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
    assignedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
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

    const assignmentIds: string[] = [];
    let assigned = 0;

    for (const item of args.roles) {
      const existingAssignments = await ctx.db
        .query("roleAssignments")
        .withIndex("by_tenant_user_and_role", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("role", item.role),
        )
        .collect();

      const duplicate = existingAssignments.find((a) => {
        if (isExpired(a.expiresAt)) return false;
        if (!a.scope && !item.scope) return true;
        if (!a.scope || !item.scope) return false;
        return a.scope.type === item.scope.type && a.scope.id === item.scope.id;
      });

      if (duplicate) {
        throw new ConvexError({
          code: "ALREADY_EXISTS",
          message: `User already has role "${item.role}" with the same scope`,
        });
      }

      const assignmentId = await ctx.db.insert("roleAssignments", {
        tenantId: args.tenantId,
        userId: args.userId,
        role: item.role,
        scope: item.scope,
        metadata: item.metadata,
        assignedBy: args.assignedBy,
        expiresAt: item.expiresAt,
      });
      assignmentIds.push(assignmentId as string);
      assigned++;

      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: Date.now(),
          action: "role_assigned",
          userId: args.userId,
          actorId: args.assignedBy,
          details: { role: item.role, scope: item.scope },
        });
      }
    }

    return { assigned, assignmentIds };
  },
});

/**
 * Revoke multiple roles from a user in a single transaction.
 */
export const revokeRoles = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    roles: v.array(
      v.object({
        role: v.string(),
        scope: scopeValidator,
      }),
    ),
    revokedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
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
        `roles must not exceed ${MAX_BULK_ROLES} items (got ${args.roles.length})`,
      );
    }

    let revoked = 0;

    for (const item of args.roles) {
      const assignments = await ctx.db
        .query("roleAssignments")
        .withIndex("by_tenant_user_and_role", (q) =>
          q
            .eq("tenantId", args.tenantId)
            .eq("userId", args.userId)
            .eq("role", item.role),
        )
        .collect();

      const toRevoke = assignments.find((a) => {
        if (!a.scope && !item.scope) return true;
        if (!a.scope || !item.scope) return false;
        return a.scope.type === item.scope.type && a.scope.id === item.scope.id;
      });

      if (!toRevoke) continue;

      await ctx.db.delete(toRevoke._id);
      revoked++;

      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: Date.now(),
          action: "role_revoked",
          userId: args.userId,
          actorId: args.revokedBy,
          details: { role: item.role, scope: item.scope },
        });
      }
    }

    return { revoked };
  },
});

type OffboardUserArgs = {
  tenantId: string;
  userId: string;
  scope?: { type: string; id: string };
  revokedBy?: string;
  removeAttributes?: boolean;
  removeOverrides?: boolean;
  removeRelationships?: boolean;
  enableAudit?: boolean;
};

async function offboardUserImpl(
  ctx: {
    db: import("convex/server").GenericMutationCtx<
      import("./_generated/dataModel").DataModel
    >["db"];
  },
  args: OffboardUserArgs,
): Promise<{
  rolesRevoked: number;
  overridesRemoved: number;
  attributesRemoved: number;
  relationshipsRemoved: number;
  effectiveRolesRemoved: number;
  effectivePermissionsRemoved: number;
  effectiveRelationshipsRemoved: number;
}> {
  const removeAttrs = args.removeAttributes !== false;
  const removeOverridesFlag = args.removeOverrides !== false;
  const removeRels = args.removeRelationships !== false;
  const scopeKey = args.scope ? `${args.scope.type}:${args.scope.id}` : null;
  const fullDeprovision = args.scope === undefined;

  let rolesRevoked = 0;
  let overridesRemoved = 0;
  let attributesRemoved = 0;
  let relationshipsRemoved = 0;
  let effectiveRolesRemoved = 0;
  let effectivePermissionsRemoved = 0;
  let effectiveRelationshipsRemoved = 0;

  // 1. Role assignments (source table)
  const assignments = await ctx.db
    .query("roleAssignments")
    .withIndex("by_tenant_user", (q) =>
      q.eq("tenantId", args.tenantId).eq("userId", args.userId),
    )
    .collect();

  for (const a of assignments) {
    if (args.scope) {
      if (!a.scope) continue;
      if (a.scope.type !== args.scope.type || a.scope.id !== args.scope.id)
        continue;
    }
    await ctx.db.delete(a._id);
    rolesRevoked++;
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: Date.now(),
        action: "role_revoked",
        userId: args.userId,
        actorId: args.revokedBy,
        details: { role: a.role, scope: a.scope },
      });
    }
  }

  // 2. Permission overrides
  if (removeOverridesFlag) {
    const overrides = await ctx.db
      .query("permissionOverrides")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId),
      )
      .collect();

    for (const o of overrides) {
      if (args.scope) {
        if (!o.scope) continue;
        if (o.scope.type !== args.scope.type || o.scope.id !== args.scope.id)
          continue;
      }
      await ctx.db.delete(o._id);
      overridesRemoved++;
    }
  }

  // 3. User attributes (no scope)
  if (removeAttrs) {
    const attributes = await ctx.db
      .query("userAttributes")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId),
      )
      .collect();

    for (const a of attributes) {
      await ctx.db.delete(a._id);
      attributesRemoved++;
      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: Date.now(),
          action: "attribute_removed",
          userId: args.userId,
          actorId: args.revokedBy,
          details: { attribute: { key: a.key } },
        });
      }
    }
  }

  // 4. ReBAC relationships (only on full deprovision, no scope)
  if (fullDeprovision && removeRels) {
    const relationships = await ctx.db
      .query("relationships")
      .withIndex("by_tenant_subject", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("subjectType", "user")
          .eq("subjectId", args.userId),
      )
      .collect();

    for (const r of relationships) {
      await ctx.db.delete(r._id);
      relationshipsRemoved++;
    }

    const userSubjectKey = `user:${args.userId}`;
    const effectiveRels = await ctx.db
      .query("effectiveRelationships")
      .withIndex("by_tenant_subject", (q) =>
        q.eq("tenantId", args.tenantId).eq("subjectKey", userSubjectKey),
      )
      .collect();

    for (const er of effectiveRels) {
      await ctx.db.delete(er._id);
      effectiveRelationshipsRemoved++;
    }
  }

  // 5. Indexed tables: effectiveRoles, effectivePermissions
  const effectiveRoles = await ctx.db
    .query("effectiveRoles")
    .withIndex("by_tenant_user", (q) =>
      q.eq("tenantId", args.tenantId).eq("userId", args.userId),
    )
    .collect();

  for (const r of effectiveRoles) {
    if (scopeKey !== null && r.scopeKey !== scopeKey) continue;
    await ctx.db.delete(r._id);
    effectiveRolesRemoved++;
  }

  const effectivePerms = await ctx.db
    .query("effectivePermissions")
    .withIndex("by_tenant_user", (q) =>
      q.eq("tenantId", args.tenantId).eq("userId", args.userId),
    )
    .collect();

  for (const p of effectivePerms) {
    if (scopeKey !== null && p.scopeKey !== scopeKey) continue;
    await ctx.db.delete(p._id);
    effectivePermissionsRemoved++;
  }

  return {
    rolesRevoked,
    overridesRemoved,
    attributesRemoved,
    relationshipsRemoved,
    effectiveRolesRemoved,
    effectivePermissionsRemoved,
    effectiveRelationshipsRemoved,
  };
}

/**
 * Full user offboarding: remove all roles, optional permission overrides and attributes,
 * ReBAC relationships (when no scope), and clear indexed effectiveRoles/effectivePermissions
 * and effectiveRelationships for this user (and optional scope).
 *
 * When scope is omitted, performs a full deprovision: roles, overrides, attributes,
 * and all relationships where the user is the subject are removed. Use for
 * security incident response, enterprise offboarding, or single-button deactivation.
 */
export const offboardUser = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    scope: scopeValidator,
    revokedBy: v.optional(v.string()),
    removeAttributes: v.optional(v.boolean()),
    removeOverrides: v.optional(v.boolean()),
    removeRelationships: v.optional(v.boolean()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.object({
    rolesRevoked: v.number(),
    overridesRemoved: v.number(),
    attributesRemoved: v.number(),
    relationshipsRemoved: v.number(),
    effectiveRolesRemoved: v.number(),
    effectivePermissionsRemoved: v.number(),
    effectiveRelationshipsRemoved: v.number(),
  }),
  handler: async (ctx, args) => offboardUserImpl(ctx, args),
});

/**
 * Full user deprovisioning: wipes all roles, attributes, relationships, and
 * permission overrides for a given userId in one atomic call. Convenience
 * wrapper around offboardUser with no scope and all removal options enabled.
 * Use for security incident response, enterprise offboarding, or single-button
 * deactivation.
 */
export const deprovisionUser = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    revokedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.object({
    rolesRevoked: v.number(),
    overridesRemoved: v.number(),
    attributesRemoved: v.number(),
    relationshipsRemoved: v.number(),
    effectiveRolesRemoved: v.number(),
    effectivePermissionsRemoved: v.number(),
    effectiveRelationshipsRemoved: v.number(),
  }),
  handler: async (ctx, args) =>
    offboardUserImpl(ctx, {
      tenantId: args.tenantId,
      userId: args.userId,
      revokedBy: args.revokedBy,
      removeAttributes: true,
      removeOverrides: true,
      removeRelationships: true,
      enableAudit: args.enableAudit,
    }),
});

/**
 * Set a user attribute
 */
export const setAttribute = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    key: v.string(),
    value: v.any(),
    setBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    // Check if attribute already exists
    const existing = await ctx.db
      .query("userAttributes")
      .withIndex("by_tenant_user_and_key", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("key", args.key),
      )
      .unique();

    if (existing) {
      // Update existing attribute
      await ctx.db.patch(existing._id, { value: args.value });

      // Log audit entry if enabled
      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: Date.now(),
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

      return existing._id as string;
    }

    // Create new attribute
    const attributeId = await ctx.db.insert("userAttributes", {
      tenantId: args.tenantId,
      userId: args.userId,
      key: args.key,
      value: args.value,
    });

    // Log audit entry if enabled
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: Date.now(),
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

    return attributeId as string;
  },
});

/**
 * Remove a user attribute
 */
export const removeAttribute = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    key: v.string(),
    removedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("userAttributes")
      .withIndex("by_tenant_user_and_key", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("key", args.key),
      )
      .unique();

    if (!existing) {
      return false;
    }

    await ctx.db.delete(existing._id);

    // Log audit entry if enabled
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: Date.now(),
        action: "attribute_removed",
        userId: args.userId,
        actorId: args.removedBy,
        details: {
          attribute: {
            key: args.key,
          },
        },
      });
    }

    return true;
  },
});

/**
 * Remove all user attributes
 */
export const removeAllAttributes = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    removedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.number(),
  handler: async (ctx, args) => {
    const attributes = await ctx.db
      .query("userAttributes")
      .withIndex("by_tenant_user", (q) =>
        q.eq("tenantId", args.tenantId).eq("userId", args.userId),
      )
      .collect();

    for (const attribute of attributes) {
      await ctx.db.delete(attribute._id);

      // Log audit entry if enabled
      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: Date.now(),
          action: "attribute_removed",
          userId: args.userId,
          actorId: args.removedBy,
          details: {
            attribute: {
              key: attribute.key,
            },
          },
        });
      }
    }

    return attributes.length;
  },
});

/**
 * Grant a permission override
 */
export const grantPermission = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    scope: scopeValidator,
    reason: v.optional(v.string()),
    createdBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    // Check for existing override with same permission and scope
    const existing = await ctx.db
      .query("permissionOverrides")
      .withIndex("by_tenant_user_and_permission", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("permission", args.permission),
      )
      .collect();

    const duplicate = existing.find((o) => {
      if (isExpired(o.expiresAt)) return false;
      if (!o.scope && !args.scope) return true;
      if (!o.scope || !args.scope) return false;
      return o.scope.type === args.scope.type && o.scope.id === args.scope.id;
    });

    if (duplicate) {
      // Update existing override
      await ctx.db.patch(duplicate._id, {
        effect: "allow",
        reason: args.reason,
        createdBy: args.createdBy,
        expiresAt: args.expiresAt,
      });

      // Log audit entry if enabled
      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: Date.now(),
          action: "permission_granted",
          userId: args.userId,
          actorId: args.createdBy,
          details: {
            permission: args.permission,
            scope: args.scope,
            reason: args.reason,
          },
        });
      }

      return duplicate._id as string;
    }

    // Create new override
    const overrideId = await ctx.db.insert("permissionOverrides", {
      tenantId: args.tenantId,
      userId: args.userId,
      permission: args.permission,
      effect: "allow",
      scope: args.scope,
      reason: args.reason,
      createdBy: args.createdBy,
      expiresAt: args.expiresAt,
    });

    // Log audit entry if enabled
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: Date.now(),
        action: "permission_granted",
        userId: args.userId,
        actorId: args.createdBy,
        details: {
          permission: args.permission,
          scope: args.scope,
          reason: args.reason,
        },
      });
    }

    return overrideId as string;
  },
});

/**
 * Deny a permission (create deny override)
 */
export const denyPermission = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    scope: scopeValidator,
    reason: v.optional(v.string()),
    createdBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    // Check for existing override with same permission and scope
    const existing = await ctx.db
      .query("permissionOverrides")
      .withIndex("by_tenant_user_and_permission", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("permission", args.permission),
      )
      .collect();

    const duplicate = existing.find((o) => {
      if (isExpired(o.expiresAt)) return false;
      if (!o.scope && !args.scope) return true;
      if (!o.scope || !args.scope) return false;
      return o.scope.type === args.scope.type && o.scope.id === args.scope.id;
    });

    if (duplicate) {
      // Update existing override
      await ctx.db.patch(duplicate._id, {
        effect: "deny",
        reason: args.reason,
        createdBy: args.createdBy,
        expiresAt: args.expiresAt,
      });

      // Log audit entry if enabled
      if (args.enableAudit) {
        await ctx.db.insert("auditLog", {
          tenantId: args.tenantId,
          timestamp: Date.now(),
          action: "permission_denied",
          userId: args.userId,
          actorId: args.createdBy,
          details: {
            permission: args.permission,
            scope: args.scope,
            reason: args.reason,
          },
        });
      }

      return duplicate._id as string;
    }

    // Create new override
    const overrideId = await ctx.db.insert("permissionOverrides", {
      tenantId: args.tenantId,
      userId: args.userId,
      permission: args.permission,
      effect: "deny",
      scope: args.scope,
      reason: args.reason,
      createdBy: args.createdBy,
      expiresAt: args.expiresAt,
    });

    // Log audit entry if enabled
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: Date.now(),
        action: "permission_denied",
        userId: args.userId,
        actorId: args.createdBy,
        details: {
          permission: args.permission,
          scope: args.scope,
          reason: args.reason,
        },
      });
    }

    return overrideId as string;
  },
});

/**
 * Remove a permission override
 */
export const removePermissionOverride = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    scope: scopeValidator,
    removedBy: v.optional(v.string()),
    enableAudit: v.optional(v.boolean()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("permissionOverrides")
      .withIndex("by_tenant_user_and_permission", (q) =>
        q
          .eq("tenantId", args.tenantId)
          .eq("userId", args.userId)
          .eq("permission", args.permission),
      )
      .collect();

    const toRemove = existing.find((o) => {
      if (!o.scope && !args.scope) return true;
      if (!o.scope || !args.scope) return false;
      return o.scope.type === args.scope.type && o.scope.id === args.scope.id;
    });

    if (!toRemove) {
      return false;
    }

    await ctx.db.delete(toRemove._id);

    // Log audit entry if enabled
    if (args.enableAudit) {
      await ctx.db.insert("auditLog", {
        tenantId: args.tenantId,
        timestamp: Date.now(),
        action:
          toRemove.effect === "allow"
            ? "permission_denied"
            : "permission_granted",
        userId: args.userId,
        actorId: args.removedBy,
        details: {
          permission: args.permission,
          scope: args.scope,
          reason: "Override removed",
        },
      });
    }

    return true;
  },
});

/**
 * Log a permission check to the audit log
 */
export const logPermissionCheck = mutation({
  args: {
    tenantId: v.string(),
    userId: v.string(),
    permission: v.string(),
    result: v.boolean(),
    scope: scopeValidator,
    reason: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.insert("auditLog", {
      tenantId: args.tenantId,
      timestamp: Date.now(),
      action: "permission_check",
      userId: args.userId,
      details: {
        permission: args.permission,
        result: args.result,
        scope: args.scope,
        reason: args.reason,
      },
    });

    return null;
  },
});

/**
 * Clean up expired role assignments and permission overrides
 */
export const cleanupExpired = mutation({
  args: {
    tenantId: v.optional(v.string()),
  },
  returns: v.object({
    expiredRoles: v.number(),
    expiredOverrides: v.number(),
  }),
  handler: async (ctx, args) => {
    const now = Date.now();
    let expiredRoles = 0;
    let expiredOverrides = 0;

    const roleAssignments = args.tenantId
      ? await ctx.db
          .query("roleAssignments")
          .withIndex("by_tenant_user", (q) =>
            q.eq("tenantId", args.tenantId!),
          )
          .collect()
      : await ctx.db.query("roleAssignments").collect();
    for (const assignment of roleAssignments) {
      if (assignment.expiresAt && assignment.expiresAt < now) {
        await ctx.db.delete(assignment._id);
        expiredRoles++;
      }
    }

    const overrides = args.tenantId
      ? await ctx.db
          .query("permissionOverrides")
          .withIndex("by_tenant_user", (q) =>
            q.eq("tenantId", args.tenantId!),
          )
          .collect()
      : await ctx.db.query("permissionOverrides").collect();
    for (const override of overrides) {
      if (override.expiresAt && override.expiresAt < now) {
        await ctx.db.delete(override._id);
        expiredOverrides++;
      }
    }

    return { expiredRoles, expiredOverrides };
  },
});

/**
 * Scheduled cleanup job: purges all expired records from roleAssignments,
 * permissionOverrides, effectiveRoles, and effectivePermissions.
 * Intended to be run periodically via Convex crons (e.g. daily).
 *
 * The cleanup cron is auto-registered when you use the component (e.g. assignRole or this mutation).
 * You can also define it manually in your app's convex/crons.ts if you prefer.
 */
export const runScheduledCleanup = mutation({
  args: {
    tenantId: v.optional(v.string()),
  },
  returns: v.object({
    expiredRoleAssignments: v.number(),
    expiredOverrides: v.number(),
    expiredEffectiveRoles: v.number(),
    expiredEffectivePermissions: v.number(),
  }),
  handler: async (ctx, args) => {
    const now = Date.now();
    let expiredRoleAssignments = 0;
    let expiredOverrides = 0;
    let expiredEffectiveRoles = 0;
    let expiredEffectivePermissions = 0;

    // 1. Source tables: roleAssignments, permissionOverrides
    const roleAssignments = args.tenantId
      ? await ctx.db
          .query("roleAssignments")
          .withIndex("by_tenant_user", (q) =>
            q.eq("tenantId", args.tenantId!),
          )
          .collect()
      : await ctx.db.query("roleAssignments").collect();
    for (const assignment of roleAssignments) {
      if (assignment.expiresAt && assignment.expiresAt < now) {
        await ctx.db.delete(assignment._id);
        expiredRoleAssignments++;
      }
    }

    const overrides = args.tenantId
      ? await ctx.db
          .query("permissionOverrides")
          .withIndex("by_tenant_user", (q) =>
            q.eq("tenantId", args.tenantId!),
          )
          .collect()
      : await ctx.db.query("permissionOverrides").collect();
    for (const override of overrides) {
      if (override.expiresAt && override.expiresAt < now) {
        await ctx.db.delete(override._id);
        expiredOverrides++;
      }
    }

    // 2. Indexed tables: effectiveRoles, effectivePermissions
    const effectiveRoles = args.tenantId
      ? await ctx.db
          .query("effectiveRoles")
          .withIndex("by_tenant_user", (q) =>
            q.eq("tenantId", args.tenantId!),
          )
          .collect()
      : await ctx.db.query("effectiveRoles").collect();
    for (const row of effectiveRoles) {
      if (row.expiresAt && row.expiresAt < now) {
        await ctx.db.delete(row._id);
        expiredEffectiveRoles++;
      }
    }

    const effectivePermissions = args.tenantId
      ? await ctx.db
          .query("effectivePermissions")
          .withIndex("by_tenant_user", (q) =>
            q.eq("tenantId", args.tenantId!),
          )
          .collect()
      : await ctx.db.query("effectivePermissions").collect();
    for (const row of effectivePermissions) {
      if (row.expiresAt && row.expiresAt < now) {
        await ctx.db.delete(row._id);
        expiredEffectivePermissions++;
      }
    }

    return {
      expiredRoleAssignments,
      expiredOverrides,
      expiredEffectiveRoles,
      expiredEffectivePermissions,
    };
  },
});

const BATCH_SIZE = 500;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

function getOptionalEnvNumber(name: string): number | undefined {
  try {
    const env = typeof process !== "undefined" ? process.env : undefined;
    const raw = env && (env[name] as string | undefined);
    if (raw === undefined || raw === "") return undefined;
    const n = parseInt(String(raw), 10);
    return Number.isFinite(n) ? n : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Audit log retention cleanup: deletes entries by max age and/or caps total entries.
 * Config from args (when provided) or env AUDIT_RETENTION_DAYS and AUDIT_RETENTION_MAX_ENTRIES.
 * Omit or 0 = skip that policy. Intended to be run daily via cron (e.g. authz-audit-retention).
 */
export const runAuditRetentionCleanup = mutation({
  args: v.object({
    tenantId: v.optional(v.string()),
    maxAgeDays: v.optional(v.number()),
    maxEntries: v.optional(v.number()),
  }),
  returns: v.object({
    deletedByAge: v.number(),
    deletedByCount: v.number(),
  }),
  handler: async (ctx, args) => {
    const maxAgeDays: number | undefined =
      args.maxAgeDays ?? getOptionalEnvNumber("AUDIT_RETENTION_DAYS");
    const maxEntries: number | undefined =
      args.maxEntries ?? getOptionalEnvNumber("AUDIT_RETENTION_MAX_ENTRIES");

    let deletedByAge = 0;
    let deletedByCount = 0;

    if (maxAgeDays !== undefined && maxAgeDays > 0) {
      const cutoff = Date.now() - maxAgeDays * MS_PER_DAY;
      if (args.tenantId) {
        while (true) {
          const batch = await ctx.db
            .query("auditLog")
            .withIndex("by_tenant_timestamp", (q) =>
              q.eq("tenantId", args.tenantId!).lt("timestamp", cutoff),
            )
            .order("asc")
            .take(BATCH_SIZE);
          if (batch.length === 0) break;
          for (const doc of batch) {
            await ctx.db.delete(doc._id);
            deletedByAge++;
          }
        }
      } else {
        const all = await ctx.db.query("auditLog").collect();
        for (const doc of all) {
          if (doc.timestamp < cutoff) {
            await ctx.db.delete(doc._id);
            deletedByAge++;
          }
        }
      }
    }

    if (maxEntries !== undefined && maxEntries > 0) {
      const all = await ctx.db.query("auditLog").collect();
      const filtered = args.tenantId
        ? all.filter((doc) => doc.tenantId === args.tenantId)
        : all;
      const count = filtered.length;
      if (count > maxEntries) {
        const toDelete = count - maxEntries;
        const byTimestamp = filtered.sort((a, b) => a.timestamp - b.timestamp);
        const toRemove = byTimestamp.slice(0, toDelete);
        for (const doc of toRemove) {
          await ctx.db.delete(doc._id);
          deletedByCount++;
        }
      }
    }

    return { deletedByAge, deletedByCount };
  },
});
