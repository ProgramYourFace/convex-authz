/**
 * @djpanda/convex-authz - Authorization Component for Convex
 *
 * A comprehensive RBAC/ABAC/ReBAC authorization component featuring
 * O(1) indexed lookups, inspired by Google Zanzibar.
 *
 * @example
 * ```typescript
 * import { Authz, definePermissions, defineRoles } from "@djpanda/convex-authz";
 * import { components } from "./_generated/api";
 *
 * const permissions = definePermissions({
 *   documents: { create: true, read: true, update: true, delete: true },
 * });
 *
 * const roles = defineRoles(permissions, {
 *   admin: { documents: ["create", "read", "update", "delete"] },
 *   viewer: { documents: ["read"] },
 * });
 *
 * export const authz = new Authz(components.authz, { permissions, roles, tenantId: "my-app" });
 * ```
 */

import type {
  GenericActionCtx,
  GenericDataModel,
  GenericMutationCtx,
  GenericQueryCtx,
} from "convex/server";
import type { ComponentApi } from "../component/_generated/component.js";
import {
  validateTenantId,
  validateUserId,
  validatePermission,
  validateScope,
  validateRole,
  validateOptionalExpiresAt,
  validateAttributeKey,
  validateAuditLimit,
  validateRelationArgs,
  validatePermissions,
  validateRoleAssignItems,
  validateRoles,
  type RoleAssignItem,
  type RoleScopeItem,
} from "./validation.js";

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Permission definition structure
 * Maps resource names to action names
 */
export type PermissionDefinition = Record<string, Record<string, boolean>>;

/** Reserved keys in role definitions; do not use as permission resource names. */
const RESERVED_ROLE_KEYS = ["inherits", "includes"] as const;

/**
 * Role definition structure
 * Maps role names to their granted permissions.
 * Roles may optionally inherit one role (`inherits`) and/or include multiple roles (`includes`).
 * Effective permissions are the union of inherited/included and direct permissions.
 */
export type RoleDefinition<P extends PermissionDefinition> = Record<
  string,
  {
    inherits?: string;
    includes?: readonly string[];
  } & { [K in keyof P]?: ReadonlyArray<keyof P[K]> }
>;

/**
 * Policy definition for ABAC
 * Condition may be sync or async (e.g. for DB or API checks).
 */
export type PolicyDefinition = Record<
  string,
  {
    condition: (ctx: PolicyContext) => boolean | Promise<boolean>;
    message?: string;
  }
>;

/**
 * Policy evaluation context
 */
export interface PolicyContext {
  subject: {
    userId: string;
    roles: string[];
    attributes: Record<string, unknown>;
  };
  resource?: {
    type: string;
    id: string;
    [key: string]: unknown;
  };
  action: string;
}

/**
 * Scope for resource-level permissions
 */
export interface Scope {
  type: string;
  id: string;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Define type-safe permissions.
 *
 * Pass a single object to define permissions from scratch, or pass
 * multiple objects to merge them together. Later entries add new
 * resources and actions; overlapping resources are merged.
 *
 * @example
 * ```ts
 * // Single definition
 * const permissions = definePermissions({
 *   documents: { create: true, read: true, update: true, delete: true },
 * });
 *
 * // Merge component defaults with app-specific resources
 * import { TENANTS_PERMISSIONS } from "@djpanda/convex-tenants";
 * const permissions = definePermissions(TENANTS_PERMISSIONS, {
 *   billing: { manage: true, view: true },
 * });
 * ```
 */
export function definePermissions<P extends PermissionDefinition>(p: P): P;
export function definePermissions<
  P1 extends PermissionDefinition,
  P2 extends PermissionDefinition,
>(p1: P1, p2: P2): P1 & P2;
export function definePermissions<
  P1 extends PermissionDefinition,
  P2 extends PermissionDefinition,
  P3 extends PermissionDefinition,
>(p1: P1, p2: P2, p3: P3): P1 & P2 & P3;
export function definePermissions(
  ...definitions: PermissionDefinition[]
): PermissionDefinition {
  if (definitions.length === 1) return definitions[0];
  const result: Record<string, Record<string, boolean>> = {};
  for (const def of definitions) {
    for (const [resource, actions] of Object.entries(def)) {
      result[resource] = { ...(result[resource] ?? {}), ...actions };
    }
  }
  return result;
}

/**
 * Define type-safe roles based on permissions.
 *
 * The first argument is the permissions definition (for type inference).
 * Pass a single role object, or pass multiple role objects to merge them.
 * For existing roles, permission arrays are concatenated (deduplicated).
 * New roles from later objects are added as-is.
 *
 * @example
 * ```ts
 * // Single definition
 * const roles = defineRoles(permissions, {
 *   admin: { documents: ["create", "read", "update", "delete"] },
 *   viewer: { documents: ["read"] },
 * });
 *
 * // Merge component defaults with app-specific extensions
 * import { TENANTS_ROLES } from "@djpanda/convex-tenants";
 * const roles = defineRoles(permissions, TENANTS_ROLES, {
 *   owner: { billing: ["manage", "view"] },     // extend existing role
 *   billing_admin: { billing: ["manage"] },      // add new role
 * });
 * ```
 */
export function defineRoles<
  P extends PermissionDefinition,
  R extends RoleDefinition<P>,
>(permissions: P, roles: R): R;
export function defineRoles<
  P extends PermissionDefinition,
  R1 extends RoleDefinition<P>,
  R2 extends RoleDefinition<P>,
>(permissions: P, r1: R1, r2: R2): R1 & R2;
export function defineRoles<
  P extends PermissionDefinition,
  R1 extends RoleDefinition<P>,
  R2 extends RoleDefinition<P>,
  R3 extends RoleDefinition<P>,
>(permissions: P, r1: R1, r2: R2, r3: R3): R1 & R2 & R3;
export function defineRoles<P extends PermissionDefinition>(
  _permissions: P,
  ...roleDefs: RoleDefinition<P>[]
): RoleDefinition<P> {
  if (roleDefs.length === 1) return roleDefs[0];
  const result: Record<string, Record<string, unknown>> = {};
  for (const def of roleDefs) {
    for (const [roleName, rolePerms] of Object.entries(def)) {
      const r = rolePerms as Record<string, unknown>;
      if (!result[roleName]) {
        result[roleName] = { ...r };
      } else {
        const existing = result[roleName] as Record<string, unknown>;
        if (r.inherits !== undefined) existing.inherits = r.inherits;
        if (Array.isArray(r.includes)) {
          const prev = (existing.includes as string[] | undefined) ?? [];
          existing.includes = [...new Set([...prev, ...r.includes])];
        }
        for (const [key, value] of Object.entries(r)) {
          if (RESERVED_ROLE_KEYS.includes(key as (typeof RESERVED_ROLE_KEYS)[number]))
            continue;
          const existingArr = (existing[key] ?? []) as string[];
          const incomingArr = Array.isArray(value) ? (value as string[]) : [];
          existing[key] = [...new Set([...existingArr, ...incomingArr])];
        }
      }
    }
  }
  return result as RoleDefinition<P>;
}

/**
 * Define ABAC policies
 */
export function definePolicies<Policy extends PolicyDefinition>(
  policies: Policy
): Policy {
  return policies;
}

/**
 * Evaluate a policy condition (sync or async). Always returns a Promise so callers can await uniformly.
 */
export function evaluatePolicyCondition(
  condition: (ctx: PolicyContext) => boolean | Promise<boolean>,
  ctx: PolicyContext
): Promise<boolean> {
  return Promise.resolve(condition(ctx));
}

/**
 * Resolve effective permissions for a role, following inherits and includes with cycle detection.
 * @internal
 */
function resolveRolePermissions(
  roles: Record<string, Record<string, unknown>>,
  roleName: string,
  visited: Set<string>
): string[] {
  if (!Object.prototype.hasOwnProperty.call(roles, roleName)) return [];
  if (visited.has(roleName)) {
    throw new Error(
      `Role inheritance cycle detected involving role "${roleName}"`
    );
  }
  visited.add(roleName);
  const rolePerms = roles[roleName];
  const perms = new Set<string>();

  try {
    const inherits = rolePerms.inherits;
    if (inherits !== undefined && inherits !== null) {
      const ref = String(inherits);
      if (!Object.prototype.hasOwnProperty.call(roles, ref)) {
        throw new Error(
          `Role "${roleName}" inherits unknown role "${ref}"`
        );
      }
      for (const p of resolveRolePermissions(roles, ref, visited)) perms.add(p);
    }
    const includes = rolePerms.includes;
    if (Array.isArray(includes)) {
      for (const ref of includes) {
        const r = String(ref);
        if (!Object.prototype.hasOwnProperty.call(roles, r)) {
          throw new Error(
            `Role "${roleName}" includes unknown role "${r}"`
          );
        }
        for (const p of resolveRolePermissions(roles, r, visited)) perms.add(p);
      }
    }
    for (const [resource, actions] of Object.entries(rolePerms)) {
      if (
        RESERVED_ROLE_KEYS.includes(resource as (typeof RESERVED_ROLE_KEYS)[number])
      )
        continue;
      if (Array.isArray(actions)) {
        for (const action of actions) perms.add(`${resource}:${String(action)}`);
      }
    }
    return [...perms];
  } finally {
    visited.delete(roleName);
  }
}

/**
 * Flatten role permissions into an array of permission strings.
 * Resolves inheritance (`inherits`) and composition (`includes`) so that
 * effective permissions include those from inherited/included roles.
 */
export function flattenRolePermissions(
  roles: Record<string, Record<string, unknown>>,
  roleName: string
): string[] {
  const visited = new Set<string>();
  return resolveRolePermissions(roles, roleName, visited);
}

// ============================================================================
// Context Types for Client Methods
// ============================================================================

type QueryCtx = Pick<GenericQueryCtx<GenericDataModel>, "runQuery">;
type MutationCtx = Pick<GenericMutationCtx<GenericDataModel>, "runMutation">;
type ActionCtx = Pick<
  GenericActionCtx<GenericDataModel>,
  "runQuery" | "runMutation" | "runAction"
>;

// ============================================================================
// Authz Client Class (Standard)
// ============================================================================

/**
 * Standard Authz client for RBAC/ABAC operations
 *
 * @example
 * ```typescript
 * const authz = new Authz(components.authz, { permissions, roles, tenantId: "my-app" });
 *
 * // In a mutation or query
 * const canEdit = await authz.can(ctx, userId, "documents:update");
 * await authz.require(ctx, userId, "documents:update");
 * ```
 */
export class Authz<
  P extends PermissionDefinition,
  R extends RoleDefinition<P>,
  Policy extends PolicyDefinition = Record<string, never>,
> {
  constructor(
    public component: ComponentApi,
    private options: {
      permissions: P;
      roles: R;
      policies?: Policy;
      defaultActorId?: string;
      tenantId: string;
    }
  ) {
    validateTenantId(options.tenantId);
  }

  withTenant(tenantId: string): Authz<P, R, Policy> {
    validateTenantId(tenantId);
    return new Authz(this.component, { ...this.options, tenantId });
  }

  /**
   * Build role permissions map for queries
   */
  private buildRolePermissionsMap(): Record<string, string[]> {
    const map: Record<string, string[]> = {};
    const roles = this.options.roles as unknown as Record<string, Record<string, string[]>>;

    for (const roleName of Object.keys(roles)) {
      map[roleName] = flattenRolePermissions(roles, roleName);
    }

    return map;
  }

  /**
   * Check if user has permission.
   * Permission checks support wildcard matching: if the user has a role or override with a pattern
   * (e.g. "documents:*", "*:read", or "*"), it is treated as granting that permission when the
   * pattern matches the requested permission.
   * @param permission - Concrete permission "resource:action" (e.g. "documents:read")
   */
  async can(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope
  ): Promise<boolean> {
    validateUserId(userId);
    validatePermission(permission);
    validateScope(scope);
    const result = await ctx.runQuery(this.component.queries.checkPermission, {
      userId,
      permission,
      scope,
      rolePermissions: this.buildRolePermissionsMap(),
      tenantId: this.options.tenantId,
    });

    return result.allowed;
  }

  /**
   * Require permission or throw error.
   * Supports the same wildcard matching as {@link Authz.can}.
   * @param permission - Concrete permission "resource:action" (e.g. "documents:read")
   */
  async require(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope
  ): Promise<void> {
    validateUserId(userId);
    validatePermission(permission);
    validateScope(scope);
    const result = await ctx.runQuery(this.component.queries.checkPermission, {
      userId,
      permission,
      scope,
      rolePermissions: this.buildRolePermissionsMap(),
      tenantId: this.options.tenantId,
    });

    if (!result.allowed) {
      throw new Error(
        `Permission denied: ${permission}${scope ? ` on ${scope.type}:${scope.id}` : ""} - ${result.reason}`
      );
    }
  }

  /**
   * Check if user has any of the given permissions (canAny).
   * Returns true if the user is allowed at least one of the permissions in the given scope.
   * @param permissions - Array of permission strings (e.g. ["documents:read", "documents:update"]). Max length 100.
   */
  async canAny(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permissions: string[],
    scope?: Scope
  ): Promise<boolean> {
    validateUserId(userId);
    validatePermissions(permissions);
    validateScope(scope);
    const result = await ctx.runQuery(this.component.queries.checkPermissions, {
      userId,
      permissions,
      scope,
      rolePermissions: this.buildRolePermissionsMap(),
      tenantId: this.options.tenantId,
    });
    return result.allowed;
  }

  /**
   * Check if user has a role
   */
  async hasRole(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    role: keyof R & string,
    scope?: Scope
  ): Promise<boolean> {
    validateUserId(userId);
    validateRole(role, this.options.roles);
    validateScope(scope);
    return await ctx.runQuery(this.component.queries.hasRole, {
      userId,
      role,
      scope,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Get all roles for a user
   */
  async getUserRoles(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope) {
    validateUserId(userId);
    validateScope(scope);
    return await ctx.runQuery(this.component.queries.getUserRoles, {
      userId,
      scope,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Get all effective permissions for a user
   */
  async getUserPermissions(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    scope?: Scope
  ) {
    validateUserId(userId);
    validateScope(scope);
    return await ctx.runQuery(this.component.queries.getEffectivePermissions, {
      userId,
      rolePermissions: this.buildRolePermissionsMap(),
      scope,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Get all attributes for a user
   */
  async getUserAttributes(ctx: QueryCtx | ActionCtx, userId: string) {
    validateUserId(userId);
    return await ctx.runQuery(this.component.queries.getUserAttributes, {
      userId,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Assign a role to a user
   */
  async assignRole(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: keyof R & string,
    scope?: Scope,
    expiresAt?: number,
    actorId?: string
  ): Promise<string> {
    validateUserId(userId);
    validateRole(role, this.options.roles);
    validateScope(scope);
    validateOptionalExpiresAt(expiresAt);
    return await ctx.runMutation(this.component.mutations.assignRole, {
      userId,
      role,
      scope,
      expiresAt,
      assignedBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Revoke a role from a user
   */
  async revokeRole(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: keyof R & string,
    scope?: Scope,
    actorId?: string
  ): Promise<boolean> {
    validateUserId(userId);
    validateRole(role, this.options.roles);
    validateScope(scope);
    return await ctx.runMutation(this.component.mutations.revokeRole, {
      userId,
      role,
      scope,
      revokedBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Assign multiple roles to a user in a single transaction.
   * @param roles - Array of { role, scope?, expiresAt?, metadata? }. Max length 100.
   */
  async assignRoles(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    roles: RoleAssignItem[],
    actorId?: string
  ): Promise<{ assigned: number; assignmentIds: string[] }> {
    validateUserId(userId);
    validateRoleAssignItems(roles, this.options.roles);
    const assignedBy = actorId ?? this.options.defaultActorId;
    return await ctx.runMutation(this.component.mutations.assignRoles, {
      userId,
      roles: roles.map((r) => ({
        role: r.role,
        scope: r.scope,
        expiresAt: r.expiresAt,
        metadata: r.metadata,
      })),
      assignedBy,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Revoke multiple roles from a user in a single transaction.
   * @param roles - Array of { role, scope? }. Max length 100.
   */
  async revokeRoles(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    roles: RoleScopeItem[],
    actorId?: string
  ): Promise<{ revoked: number }> {
    validateUserId(userId);
    validateRoles(roles, this.options.roles);
    return await ctx.runMutation(this.component.mutations.revokeRoles, {
      userId,
      roles: roles.map((r) => ({ role: r.role, scope: r.scope })),
      revokedBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Revoke all roles from a user (optionally only in a given scope).
   * Use for bulk cleanup or partial offboarding.
   */
  async revokeAllRoles(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    scope?: Scope,
    actorId?: string
  ): Promise<number> {
    validateUserId(userId);
    validateScope(scope);
    return await ctx.runMutation(this.component.mutations.revokeAllRoles, {
      userId,
      scope,
      revokedBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Full user offboarding: remove all roles, permission overrides, attributes, and optionally
   * ReBAC relationships for the user (optionally scoped). Also clears indexed
   * effectiveRoles/effectivePermissions/effectiveRelationships when present.
   */
  async offboardUser(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    options?: {
      scope?: Scope;
      actorId?: string;
      removeAttributes?: boolean;
      removeOverrides?: boolean;
      removeRelationships?: boolean;
    }
  ): Promise<{
    rolesRevoked: number;
    overridesRemoved: number;
    attributesRemoved: number;
    relationshipsRemoved: number;
    effectiveRolesRemoved: number;
    effectivePermissionsRemoved: number;
    effectiveRelationshipsRemoved: number;
  }> {
    validateUserId(userId);
    if (options?.scope) validateScope(options.scope);
    return await ctx.runMutation(this.component.mutations.offboardUser, {
      userId,
      scope: options?.scope,
      revokedBy: options?.actorId ?? this.options.defaultActorId,
      removeAttributes: options?.removeAttributes,
      removeOverrides: options?.removeOverrides,
      removeRelationships: options?.removeRelationships,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Full user deprovisioning: wipes all roles, attributes, relationships, and permission
   * overrides for a given userId in one atomic call. Use for security incident response,
   * enterprise offboarding, or single-button deactivation.
   */
  async deprovisionUser(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    options?: { actorId?: string; enableAudit?: boolean }
  ): Promise<{
    rolesRevoked: number;
    overridesRemoved: number;
    attributesRemoved: number;
    relationshipsRemoved: number;
    effectiveRolesRemoved: number;
    effectivePermissionsRemoved: number;
    effectiveRelationshipsRemoved: number;
  }> {
    validateUserId(userId);
    return await ctx.runMutation(this.component.mutations.deprovisionUser, {
      userId,
      revokedBy: options?.actorId ?? this.options.defaultActorId,
      enableAudit: options?.enableAudit ?? true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Set a user attribute
   */
  async setAttribute(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    key: string,
    value: unknown,
    actorId?: string
  ): Promise<string> {
    validateUserId(userId);
    validateAttributeKey(key);
    return await ctx.runMutation(this.component.mutations.setAttribute, {
      userId,
      key,
      value,
      setBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Remove a user attribute
   */
  async removeAttribute(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    key: string,
    actorId?: string
  ): Promise<boolean> {
    validateUserId(userId);
    validateAttributeKey(key);
    return await ctx.runMutation(this.component.mutations.removeAttribute, {
      userId,
      key,
      removedBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Grant a direct permission override.
   * Permission can be a concrete permission ("documents:read") or a wildcard pattern
   * ("documents:*", "*:read", "*:*", or "*") to allow all matching permissions.
   * @param permission - Permission or pattern (e.g. "documents:read", "documents:*", "*:read", "*")
   */
  async grantPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    actorId?: string
  ): Promise<string> {
    validateUserId(userId);
    validatePermission(permission);
    validateScope(scope);
    validateOptionalExpiresAt(expiresAt);
    return await ctx.runMutation(this.component.mutations.grantPermission, {
      userId,
      permission,
      scope,
      reason,
      expiresAt,
      createdBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Deny a permission (explicit deny override).
   * Permission can be a concrete permission or a wildcard pattern (e.g. "documents:*", "*:read", "*").
   * @param permission - Permission or pattern to deny
   */
  async denyPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    actorId?: string
  ): Promise<string> {
    validateUserId(userId);
    validatePermission(permission);
    validateScope(scope);
    validateOptionalExpiresAt(expiresAt);
    return await ctx.runMutation(this.component.mutations.denyPermission, {
      userId,
      permission,
      scope,
      reason,
      expiresAt,
      createdBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Get audit log entries.
   * Pass cursor and numItems for cursor-based pagination (returns { page, isDone, continueCursor }).
   * Omit both for legacy behavior (returns array, optional limit).
   */
  async getAuditLog(
    ctx: QueryCtx | ActionCtx,
    options?: {
      userId?: string;
      action?: string;
      limit?: number;
      /** Page size when using pagination (1–1000). Use with cursor for next page. */
      numItems?: number;
      /** Cursor from previous page to fetch next page. */
      cursor?: string | null;
    }
  ): Promise<
    | Array<{
        _id: string;
        timestamp: number;
        action: string;
        userId: string;
        actorId?: string;
        details: unknown;
      }>
    | {
        page: Array<{
          _id: string;
          timestamp: number;
          action: string;
          userId: string;
          actorId?: string;
          details: unknown;
        }>;
        isDone: boolean;
        continueCursor: string;
      }
  > {
    if (options?.userId !== undefined) validateUserId(options.userId);
    if (options?.limit !== undefined) validateAuditLimit(options.limit);
    if (options?.numItems !== undefined) validateAuditLimit(options.numItems);

    const usePagination =
      options?.numItems !== undefined || options?.cursor !== undefined;

    const paginationOpts = usePagination
      ? {
          numItems: options?.numItems ?? 100,
          cursor: options?.cursor ?? null,
        }
      : undefined;

    return await ctx.runQuery(this.component.queries.getAuditLog, {
      userId: options?.userId,
      action: options?.action as
        | "permission_check"
        | "role_assigned"
        | "role_revoked"
        | "permission_granted"
        | "permission_denied"
        | "attribute_set"
        | "attribute_removed"
        | undefined,
      limit: options?.limit,
      paginationOpts,
      tenantId: this.options.tenantId,
    });
  }
}

// ============================================================================
// IndexedAuthz Client Class (O(1) Lookups)
// ============================================================================

/**
 * O(1) Indexed Authz client with pre-computed permissions
 *
 * Use this for production workloads with many permission checks.
 * Writes are slower but reads are instant via indexed lookups.
 *
 * @example
 * ```typescript
 * const authz = new IndexedAuthz(components.authz, { permissions, roles, tenantId: "my-app" });
 *
 * // O(1) permission check
 * const canEdit = await authz.can(ctx, userId, "documents:update");
 * ```
 */
export class IndexedAuthz<
  P extends PermissionDefinition,
  R extends RoleDefinition<P>,
> {
  constructor(
    public component: ComponentApi,
    private options: {
      permissions: P;
      roles: R;
      defaultActorId?: string;
      tenantId: string;
    }
  ) {
    validateTenantId(options.tenantId);
  }

  withTenant(tenantId: string): IndexedAuthz<P, R> {
    validateTenantId(tenantId);
    return new IndexedAuthz(this.component, { ...this.options, tenantId });
  }

  /**
   * Check permission - O(1) indexed lookup.
   * Supports wildcard matching: stored patterns (e.g. "documents:*", "*:read") match concrete
   * permissions when the pattern matches the requested permission.
   * @param permission - Concrete permission "resource:action" (e.g. "documents:read")
   */
  async can(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope
  ): Promise<boolean> {
    validateUserId(userId);
    validatePermission(permission);
    validateScope(scope);
    return await ctx.runQuery(this.component.indexed.checkPermissionFast, {
      userId,
      permission,
      objectType: scope?.type,
      objectId: scope?.id,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Require permission or throw - O(1).
   * Supports the same wildcard matching as {@link IndexedAuthz.can}.
   * @param permission - Concrete permission "resource:action" (e.g. "documents:read")
   */
  async require(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope
  ): Promise<void> {
    validateUserId(userId);
    validatePermission(permission);
    validateScope(scope);
    const allowed = await this.can(ctx, userId, permission, scope);
    if (!allowed) {
      throw new Error(
        `Permission denied: ${permission}${scope ? ` on ${scope.type}:${scope.id}` : ""}`
      );
    }
  }

  /**
   * Check if user has any of the given permissions (canAny) - batch O(1) lookups.
   * @param permissions - Array of permission strings. Max length 100.
   */
  async canAny(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permissions: string[],
    scope?: Scope
  ): Promise<boolean> {
    validateUserId(userId);
    validatePermissions(permissions);
    validateScope(scope);
    return await ctx.runQuery(this.component.indexed.checkPermissionsFast, {
      userId,
      permissions,
      objectType: scope?.type,
      objectId: scope?.id,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Check role - O(1) indexed lookup
   */
  async hasRole(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    role: keyof R & string,
    scope?: Scope
  ): Promise<boolean> {
    validateUserId(userId);
    validateRole(role, this.options.roles);
    validateScope(scope);
    return await ctx.runQuery(this.component.indexed.hasRoleFast, {
      userId,
      role,
      objectType: scope?.type,
      objectId: scope?.id,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Check relationship - O(1) indexed lookup
   */
  async hasRelation(
    ctx: QueryCtx | ActionCtx,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string
  ): Promise<boolean> {
    validateRelationArgs(subjectType, subjectId, relation, objectType, objectId);
    return await ctx.runQuery(this.component.indexed.hasRelationFast, {
      subjectType,
      subjectId,
      relation,
      objectType,
      objectId,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Get all permissions for a user
   */
  async getUserPermissions(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    scope?: Scope
  ) {
    validateUserId(userId);
    validateScope(scope);
    const scopeKey = scope ? `${scope.type}:${scope.id}` : undefined;
    return await ctx.runQuery(this.component.indexed.getUserPermissionsFast, {
      userId,
      scopeKey,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Get all roles for a user
   */
  async getUserRoles(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope) {
    validateUserId(userId);
    validateScope(scope);
    const scopeKey = scope ? `${scope.type}:${scope.id}` : undefined;
    return await ctx.runQuery(this.component.indexed.getUserRolesFast, {
      userId,
      scopeKey,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Assign a role and pre-compute permissions
   */
  async assignRole(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    roleName: keyof R & string,
    scope?: Scope,
    expiresAt?: number,
    assignedBy?: string
  ): Promise<string> {
    validateUserId(userId);
    validateRole(roleName, this.options.roles);
    validateScope(scope);
    validateOptionalExpiresAt(expiresAt);
    const rolePermissions = flattenRolePermissions(
      this.options.roles as unknown as Record<string, Record<string, string[]>>,
      roleName
    );

    return await ctx.runMutation(this.component.indexed.assignRoleWithCompute, {
      userId,
      role: roleName,
      rolePermissions,
      scope,
      expiresAt,
      assignedBy: assignedBy ?? this.options.defaultActorId,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Revoke a role and recompute permissions
   */
  async revokeRole(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    roleName: keyof R & string,
    scope?: Scope
  ): Promise<boolean> {
    validateUserId(userId);
    validateRole(roleName, this.options.roles);
    validateScope(scope);
    const rolePermissions = flattenRolePermissions(
      this.options.roles as unknown as Record<string, Record<string, string[]>>,
      roleName
    );

    return await ctx.runMutation(this.component.indexed.revokeRoleWithCompute, {
      userId,
      role: roleName,
      rolePermissions,
      scope,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Assign multiple roles and pre-compute permissions in a single transaction.
   * @param roles - Array of { role, scope?, expiresAt?, metadata? }. Max length 100.
   */
  async assignRoles(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    roles: RoleAssignItem[],
    actorId?: string
  ): Promise<{ assigned: number; assignmentIds: string[] }> {
    validateUserId(userId);
    validateRoleAssignItems(roles, this.options.roles);
    const rolesMap = this.options.roles as unknown as Record<
      string,
      Record<string, string[]>
    >;
    const rolePermissionsMap: Record<string, string[]> = {};
    for (const roleName of Object.keys(rolesMap)) {
      rolePermissionsMap[roleName] = flattenRolePermissions(rolesMap, roleName);
    }
    return await ctx.runMutation(
      this.component.indexed.assignRolesWithCompute,
      {
        userId,
        roles: roles.map((r) => ({
          role: r.role,
          scope: r.scope,
          expiresAt: r.expiresAt,
          metadata: r.metadata,
        })),
        rolePermissionsMap,
        assignedBy: actorId ?? this.options.defaultActorId,
        tenantId: this.options.tenantId,
      }
    );
  }

  /**
   * Revoke multiple roles and recompute permissions in a single transaction.
   * @param roles - Array of { role, scope? }. Max length 100.
   */
  async revokeRoles(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    roles: RoleScopeItem[],
    _actorId?: string
  ): Promise<{ revoked: number }> {
    validateUserId(userId);
    validateRoles(roles, this.options.roles);
    const rolesMap = this.options.roles as unknown as Record<
      string,
      Record<string, string[]>
    >;
    const rolePermissionsMap: Record<string, string[]> = {};
    for (const roleName of Object.keys(rolesMap)) {
      rolePermissionsMap[roleName] = flattenRolePermissions(rolesMap, roleName);
    }
    return await ctx.runMutation(
      this.component.indexed.revokeRolesWithCompute,
      {
        userId,
        roles: roles.map((r) => ({ role: r.role, scope: r.scope })),
        rolePermissionsMap,
        tenantId: this.options.tenantId,
      }
    );
  }

  /**
   * Revoke all roles from a user (optionally only in a given scope).
   * Clears both roleAssignments and indexed effectiveRoles/effectivePermissions.
   */
  async revokeAllRoles(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    scope?: Scope,
    actorId?: string
  ): Promise<number> {
    validateUserId(userId);
    validateScope(scope);
    const result = await ctx.runMutation(
      this.component.mutations.offboardUser,
      {
        userId,
        scope,
        revokedBy: actorId ?? this.options.defaultActorId,
        removeAttributes: false,
        removeOverrides: false,
        enableAudit: true,
        tenantId: this.options.tenantId,
      }
    );
    return result.rolesRevoked + result.effectiveRolesRemoved;
  }

  /**
   * Full user offboarding: remove all roles, overrides, attributes, and optionally
   * relationships (optionally scoped). Clears indexed effectiveRoles/effectivePermissions/
   * effectiveRelationships.
   */
  async offboardUser(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    options?: {
      scope?: Scope;
      actorId?: string;
      removeAttributes?: boolean;
      removeOverrides?: boolean;
      removeRelationships?: boolean;
    }
  ): Promise<{
    rolesRevoked: number;
    overridesRemoved: number;
    attributesRemoved: number;
    relationshipsRemoved: number;
    effectiveRolesRemoved: number;
    effectivePermissionsRemoved: number;
    effectiveRelationshipsRemoved: number;
  }> {
    validateUserId(userId);
    if (options?.scope) validateScope(options.scope);
    return await ctx.runMutation(this.component.mutations.offboardUser, {
      userId,
      scope: options?.scope,
      revokedBy: options?.actorId ?? this.options.defaultActorId,
      removeAttributes: options?.removeAttributes,
      removeOverrides: options?.removeOverrides,
      removeRelationships: options?.removeRelationships,
      enableAudit: true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Full user deprovisioning: wipes all roles, attributes, relationships, and permission
   * overrides for a given userId in one atomic call.
   */
  async deprovisionUser(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    options?: { actorId?: string; enableAudit?: boolean }
  ): Promise<{
    rolesRevoked: number;
    overridesRemoved: number;
    attributesRemoved: number;
    relationshipsRemoved: number;
    effectiveRolesRemoved: number;
    effectivePermissionsRemoved: number;
    effectiveRelationshipsRemoved: number;
  }> {
    validateUserId(userId);
    return await ctx.runMutation(this.component.mutations.deprovisionUser, {
      userId,
      revokedBy: options?.actorId ?? this.options.defaultActorId,
      enableAudit: options?.enableAudit ?? true,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Grant a direct permission.
   * Permission can be concrete ("documents:read") or a wildcard pattern
   * ("documents:*", "*:read", "*:*", or "*") to allow all matching permissions.
   * @param permission - Permission or pattern (e.g. "documents:read", "documents:*", "*:read", "*")
   */
  async grantPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    grantedBy?: string
  ): Promise<string> {
    validateUserId(userId);
    validatePermission(permission);
    validateScope(scope);
    validateOptionalExpiresAt(expiresAt);
    return await ctx.runMutation(this.component.indexed.grantPermissionDirect, {
      userId,
      permission,
      scope,
      reason,
      grantedBy: grantedBy ?? this.options.defaultActorId,
      expiresAt,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Deny a permission (explicit deny override).
   * Permission can be a concrete permission or a wildcard pattern (e.g. "documents:*", "*:read", "*").
   * @param permission - Permission or pattern to deny
   */
  async denyPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    deniedBy?: string
  ): Promise<string> {
    validateUserId(userId);
    validatePermission(permission);
    validateScope(scope);
    validateOptionalExpiresAt(expiresAt);
    return await ctx.runMutation(this.component.indexed.denyPermissionDirect, {
      userId,
      permission,
      scope,
      reason,
      deniedBy: deniedBy ?? this.options.defaultActorId,
      expiresAt,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Add a relationship with computed transitive relations
   */
  async addRelation(
    ctx: MutationCtx | ActionCtx,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string,
    inheritedRelations?: Array<{
      relation: string;
      fromObjectType: string;
      fromRelation: string;
    }>,
    createdBy?: string
  ): Promise<string> {
    validateRelationArgs(subjectType, subjectId, relation, objectType, objectId);
    return await ctx.runMutation(this.component.indexed.addRelationWithCompute, {
      subjectType,
      subjectId,
      relation,
      objectType,
      objectId,
      inheritedRelations,
      createdBy: createdBy ?? this.options.defaultActorId,
      tenantId: this.options.tenantId,
    });
  }

  /**
   * Remove a relationship
   */
  async removeRelation(
    ctx: MutationCtx | ActionCtx,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string
  ): Promise<boolean> {
    validateRelationArgs(subjectType, subjectId, relation, objectType, objectId);
    return await ctx.runMutation(
      this.component.indexed.removeRelationWithCompute,
      {
        subjectType,
        subjectId,
        relation,
        objectType,
        objectId,
        tenantId: this.options.tenantId,
      }
    );
  }
}

// ============================================================================
// Re-exports
// ============================================================================

export type { ComponentApi } from "../component/_generated/component.js";
export type { RoleAssignItem, RoleScopeItem } from "./validation.js";

/**
 * Check if a concrete permission matches a permission pattern (supports wildcards).
 * Use this for client-side logic when you need to test whether a stored pattern
 * would grant a given permission.
 *
 * Patterns:
 * - `"*"` matches every permission
 * - `"resource:*"` matches all actions on that resource (e.g. `"documents:*"` matches `documents:read`, `documents:write`)
 * - `"*:action"` matches that action on any resource (e.g. `"*:read"` matches `documents:read`, `settings:read`)
 * - `"*:*"` matches every permission
 *
 * @example
 * ```ts
 * import { matchesPermissionPattern } from "@djpanda/convex-authz";
 * matchesPermissionPattern("documents:read", "documents:*"); // true
 * matchesPermissionPattern("documents:read", "*:read");     // true
 * matchesPermissionPattern("documents:write", "*:read");   // false
 * ```
 */
export {
  matchesPermissionPattern,
  parsePermission,
  buildPermission,
} from "../component/helpers.js";
