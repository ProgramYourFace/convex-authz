/**
 * Consumer integration test helpers.
 *
 * These Convex functions exercise the Authz client class through real DB calls,
 * covering RBAC with inheritance, scoped permissions, policies, ReBAC, and
 * tenant isolation.
 */
import { mutation, query } from "./_generated/server.js";
import { components } from "./_generated/api.js";
import {
  Authz,
  definePermissions,
  defineRoles,
  definePolicies,
  defineRelationPermissions,
} from "@djpanda/convex-authz";
import { v } from "convex/values";

// ---------------------------------------------------------------------------
// Complex permission / role setup for testing
// ---------------------------------------------------------------------------

const permissions = definePermissions({
  documents: { create: true, read: true, update: true, delete: true },
  settings: { view: true, manage: true },
  billing: { view: true, manage: true },
});

// Roles with inheritance chain: admin → editor → base
const roles = defineRoles(permissions, {
  base: {
    documents: ["read"],
    settings: ["view"],
  },
  editor: {
    inherits: "base",
    documents: ["create", "update"],
  },
  admin: {
    inherits: "editor",
    documents: ["delete"],
    settings: ["manage"],
    billing: ["view", "manage"],
  },
  viewer: {
    documents: ["read"],
  },
});

// Deferred policy — billing:manage requires "verified" attribute
const policies = definePolicies({
  "billing:manage": {
    type: "deferred",
    condition: (ctx) => {
      return ctx.getAttribute("verified") === true;
    },
    message: "Only verified users can manage billing",
  },
});

// Tenant A (default)
const authz = new Authz(components.authz, {
  permissions,
  roles,
  policies,
  tenantId: "consumer-test",
});

// Tenant B (for isolation tests) — no policies so billing:manage is just RBAC
const authzB = new Authz(components.authz, {
  permissions,
  roles,
  tenantId: "consumer-test-b",
});

// Tenant C (for ReBAC -> permission bridge tests)
const relationPermissions = defineRelationPermissions({
  "document:viewer": ["documents:read"],
  "document:editor": ["documents:read", "documents:update"],
  "document:owner": ["documents:read", "documents:update", "documents:delete"],
  "team:member": ["documents:read"],
});

const authzWithRelPerms = new Authz(components.authz, {
  permissions,
  roles,
  tenantId: "consumer-test-rebac",
  relationPermissions,
});

// ---------------------------------------------------------------------------
// Helper mutations
// ---------------------------------------------------------------------------

export const createUser = mutation({
  args: { name: v.string() },
  returns: v.string(),
  handler: async (ctx, args) => {
    const id = await ctx.db.insert("users", {
      name: args.name,
      email: `${args.name}-${Date.now()}@test.com`,
    });
    return String(id);
  },
});

// ---------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------

export const assignRole = mutation({
  args: {
    userId: v.string(),
    role: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
    expiresAt: v.optional(v.number()),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authz.assignRole(
      ctx,
      args.userId,
      args.role as keyof typeof roles,
      args.scope,
      args.expiresAt,
    );
  },
});

export const revokeRole = mutation({
  args: {
    userId: v.string(),
    role: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authz.revokeRole(
      ctx,
      args.userId,
      args.role as keyof typeof roles,
      args.scope,
    );
  },
});

export const can = query({
  args: {
    userId: v.string(),
    permission: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authz.can(ctx, args.userId, args.permission, args.scope);
  },
});

export const canWithContext = query({
  args: {
    userId: v.string(),
    permission: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
    requestContext: v.optional(v.any()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authz.canWithContext(
      ctx,
      args.userId,
      args.permission,
      args.scope,
      args.requestContext,
    );
  },
});

export const hasRole = query({
  args: {
    userId: v.string(),
    role: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authz.hasRole(
      ctx,
      args.userId,
      args.role as keyof typeof roles,
      args.scope,
    );
  },
});

export const getUserRoles = query({
  args: { userId: v.string() },
  returns: v.array(
    v.object({
      role: v.string(),
      scopeKey: v.string(),
      scope: v.optional(v.object({ type: v.string(), id: v.string() })),
    }),
  ),
  handler: async (ctx, args) => {
    return await authz.getUserRoles(ctx, args.userId);
  },
});

export const getUserPermissions = query({
  args: { userId: v.string() },
  returns: v.any(),
  handler: async (ctx, args) => {
    return await authz.getUserPermissions(ctx, args.userId);
  },
});

export const requirePerm = query({
  args: { userId: v.string(), permission: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    await authz.require(ctx, args.userId, args.permission);
    return null;
  },
});

// ---------------------------------------------------------------------------
// Direct grant / deny
// ---------------------------------------------------------------------------

export const grantPermission = mutation({
  args: {
    userId: v.string(),
    permission: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authz.grantPermission(
      ctx,
      args.userId,
      args.permission,
      args.scope,
    );
  },
});

export const denyPermission = mutation({
  args: {
    userId: v.string(),
    permission: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authz.denyPermission(
      ctx,
      args.userId,
      args.permission,
      args.scope,
    );
  },
});

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

export const setAttribute = mutation({
  args: { userId: v.string(), key: v.string(), value: v.any() },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authz.setAttribute(ctx, args.userId, args.key, args.value);
  },
});

export const removeAttribute = mutation({
  args: { userId: v.string(), key: v.string() },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authz.removeAttribute(ctx, args.userId, args.key);
  },
});

// ---------------------------------------------------------------------------
// ReBAC
// ---------------------------------------------------------------------------

export const addRelation = mutation({
  args: {
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authz.addRelation(
      ctx,
      { type: args.subjectType, id: args.subjectId },
      args.relation,
      { type: args.objectType, id: args.objectId },
    );
  },
});

export const hasRelation = query({
  args: {
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authz.hasRelation(
      ctx,
      { type: args.subjectType, id: args.subjectId },
      args.relation,
      { type: args.objectType, id: args.objectId },
    );
  },
});

export const removeRelation = mutation({
  args: {
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authz.removeRelation(
      ctx,
      { type: args.subjectType, id: args.subjectId },
      args.relation,
      { type: args.objectType, id: args.objectId },
    );
  },
});

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

export const deprovision = mutation({
  args: { userId: v.string() },
  returns: v.any(),
  handler: async (ctx, args) => {
    return await authz.deprovisionUser(ctx, args.userId);
  },
});

export const recompute = mutation({
  args: { userId: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    await authz.recomputeUser(ctx, args.userId);
    return null;
  },
});

// ---------------------------------------------------------------------------
// Bulk operations
// ---------------------------------------------------------------------------

export const assignRoles = mutation({
  args: {
    userId: v.string(),
    roles: v.array(
      v.object({
        role: v.string(),
        scope: v.optional(v.object({ type: v.string(), id: v.string() })),
      }),
    ),
  },
  returns: v.object({
    assigned: v.number(),
    assignmentIds: v.array(v.string()),
  }),
  handler: async (ctx, args) => {
    return await authz.assignRoles(
      ctx,
      args.userId,
      args.roles.map((r) => ({
        role: r.role as keyof typeof roles,
        scope: r.scope,
      })),
    );
  },
});

export const revokeRoles = mutation({
  args: {
    userId: v.string(),
    roles: v.array(
      v.object({
        role: v.string(),
        scope: v.optional(v.object({ type: v.string(), id: v.string() })),
      }),
    ),
  },
  returns: v.object({ revoked: v.number() }),
  handler: async (ctx, args) => {
    return await authz.revokeRoles(
      ctx,
      args.userId,
      args.roles.map((r) => ({ role: r.role, scope: r.scope })),
    );
  },
});

export const revokeAllRoles = mutation({
  args: {
    userId: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
  },
  returns: v.number(),
  handler: async (ctx, args) => {
    return await authz.revokeAllRoles(ctx, args.userId, args.scope);
  },
});

// ---------------------------------------------------------------------------
// canAny
// ---------------------------------------------------------------------------

export const canAny = query({
  args: {
    userId: v.string(),
    permissions: v.array(v.string()),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authz.canAny(
      ctx,
      args.userId,
      args.permissions,
      args.scope,
    );
  },
});

// ---------------------------------------------------------------------------
// Offboard
// ---------------------------------------------------------------------------

export const offboardUser = mutation({
  args: {
    userId: v.string(),
    removeOverrides: v.optional(v.boolean()),
    removeAttributes: v.optional(v.boolean()),
    removeRelationships: v.optional(v.boolean()),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
  },
  returns: v.any(),
  handler: async (ctx, args) => {
    return await authz.offboardUser(ctx, args.userId, {
      scope: args.scope,
      removeOverrides: args.removeOverrides,
      removeAttributes: args.removeAttributes,
      removeRelationships: args.removeRelationships,
    });
  },
});

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

export const getAuditLog = query({
  args: { userId: v.optional(v.string()), limit: v.optional(v.number()) },
  returns: v.any(),
  handler: async (ctx, args) => {
    return await authz.getAuditLog(ctx, {
      userId: args.userId,
      limit: args.limit,
    });
  },
});

// ---------------------------------------------------------------------------
// User attributes query
// ---------------------------------------------------------------------------

export const getUserAttributes = query({
  args: { userId: v.string() },
  returns: v.any(),
  handler: async (ctx, args) => {
    return await authz.getUserAttributes(ctx, args.userId);
  },
});

// ---------------------------------------------------------------------------
// Tenant B (for isolation tests)
// ---------------------------------------------------------------------------

export const assignRoleB = mutation({
  args: { userId: v.string(), role: v.string() },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authzB.assignRole(
      ctx,
      args.userId,
      args.role as keyof typeof roles,
    );
  },
});

export const canB = query({
  args: { userId: v.string(), permission: v.string() },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authzB.can(ctx, args.userId, args.permission);
  },
});

// ---------------------------------------------------------------------------
// withTenant()
// ---------------------------------------------------------------------------

export const canWithTenant = query({
  args: {
    userId: v.string(),
    permission: v.string(),
    tenantId: v.string(),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authz
      .withTenant(args.tenantId)
      .can(ctx, args.userId, args.permission);
  },
});

// ---------------------------------------------------------------------------
// ReBAC with permissions bridge
// ---------------------------------------------------------------------------

export const addRelationWithPerms = mutation({
  args: {
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authzWithRelPerms.addRelation(
      ctx,
      { type: args.subjectType, id: args.subjectId },
      args.relation,
      { type: args.objectType, id: args.objectId },
    );
  },
});

export const removeRelationWithPerms = mutation({
  args: {
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authzWithRelPerms.removeRelation(
      ctx,
      { type: args.subjectType, id: args.subjectId },
      args.relation,
      { type: args.objectType, id: args.objectId },
    );
  },
});

export const canWithRelPerms = query({
  args: {
    userId: v.string(),
    permission: v.string(),
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authzWithRelPerms.can(
      ctx,
      args.userId,
      args.permission,
      args.scope,
    );
  },
});

export const hasRelationWithPerms = query({
  args: {
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectType: v.string(),
    objectId: v.string(),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    return await authzWithRelPerms.hasRelation(
      ctx,
      { type: args.subjectType, id: args.subjectId },
      args.relation,
      { type: args.objectType, id: args.objectId },
    );
  },
});

export const assignRoleInRebacTenant = mutation({
  args: { userId: v.string(), role: v.string() },
  returns: v.string(),
  handler: async (ctx, args) => {
    return await authzWithRelPerms.assignRole(
      ctx,
      args.userId,
      args.role as keyof typeof roles,
    );
  },
});

export const deprovisionInRebacTenant = mutation({
  args: { userId: v.string() },
  returns: v.any(),
  handler: async (ctx, args) => {
    return await authzWithRelPerms.deprovisionUser(ctx, args.userId);
  },
});
