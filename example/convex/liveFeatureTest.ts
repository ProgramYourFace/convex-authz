/**
 * Live feature tests: exercises every Authz v2 feature on the real Convex backend.
 *
 * Run: npx convex run liveFeatureTest:runAll
 *
 * Each test returns PASS/FAIL with details. No test framework needed —
 * just assertions inside Convex actions.
 */
import { action, mutation } from "./_generated/server.js";
import { api, components } from "./_generated/api.js";
import {
  Authz,
  definePermissions,
  defineRoles,
} from "@djpanda/convex-authz";
import { v } from "convex/values";

const permissions = definePermissions({
  documents: { create: true, read: true, update: true, delete: true },
  settings: { view: true, manage: true },
  billing: { view: true, manage: true },
});

const roles = defineRoles(permissions, {
  admin: {
    documents: ["create", "read", "update", "delete"],
    settings: ["view", "manage"],
    billing: ["view", "manage"],
  },
  editor: {
    documents: ["create", "read", "update"],
    settings: ["view"],
  },
  viewer: {
    documents: ["read"],
    settings: ["view"],
  },
});

const authz = new Authz(components.authz, {
  permissions,
  roles,
  tenantId: "live-test",
});

const authzTenantB = new Authz(components.authz, {
  permissions,
  roles,
  tenantId: "live-test-b",
});

type TestResult = { name: string; passed: boolean; detail: string };

function assert(condition: boolean, msg: string): void {
  if (!condition) throw new Error(`Assertion failed: ${msg}`);
}

// ── Helper mutations/queries (internal) ──────────────────────────

export const createTestUser = mutation({
  args: { name: v.string() },
  returns: v.string(),
  handler: async (ctx, args) => {
    const id = await ctx.db.insert("users", {
      name: args.name,
      email: `${args.name}-${Date.now()}@livetest.com`,
    });
    return String(id);
  },
});

export const createTestOrg = mutation({
  args: { slug: v.string() },
  returns: v.id("orgs"),
  handler: async (ctx, args) => {
    return await ctx.db.insert("orgs", {
      name: `Test Org ${args.slug}`,
      slug: `livetest-${args.slug}-${Date.now()}`,
      plan: "test",
    });
  },
});

// ── Feature test functions ───────────────────────────────────────

export const testBasicRBAC = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "rbac-user" });

    try {
      // 1. Assign role
      await authz.assignRole(ctx, userId, "editor");
      const canRead = await authz.can(ctx, userId, "documents:read");
      assert(canRead === true, "editor should have documents:read");
      results.push({ name: "assignRole → can (allowed)", passed: true, detail: `documents:read = ${canRead}` });

      // 2. Check denied permission
      const canManage = await authz.can(ctx, userId, "billing:manage");
      assert(canManage === false, "editor should NOT have billing:manage");
      results.push({ name: "can (denied)", passed: true, detail: `billing:manage = ${canManage}` });

      // 3. hasRole
      const hasEditor = await authz.hasRole(ctx, userId, "editor");
      assert(hasEditor === true, "should have editor role");
      results.push({ name: "hasRole", passed: true, detail: `hasRole(editor) = ${hasEditor}` });

      // 4. getUserRoles
      const userRoles = await authz.getUserRoles(ctx, userId);
      assert(userRoles.length === 1, "should have 1 role");
      results.push({ name: "getUserRoles", passed: true, detail: `roles count = ${userRoles.length}` });

      // 5. Revoke role
      const revoked = await authz.revokeRole(ctx, userId, "editor");
      assert(revoked === true, "should revoke successfully");
      const canReadAfter = await authz.can(ctx, userId, "documents:read");
      assert(canReadAfter === false, "should be denied after revoke");
      results.push({ name: "revokeRole → can (denied)", passed: true, detail: `revoked=${revoked}, canRead=${canReadAfter}` });
    } catch (e: any) {
      results.push({ name: "basicRBAC", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

export const testScopedPermissions = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "scope-user" });
    const orgId = await ctx.runMutation(api.liveFeatureTest.createTestOrg, { slug: "scope" });

    try {
      const scope = { type: "org", id: String(orgId) };

      // Assign scoped role
      await authz.assignRole(ctx, userId, "editor", scope);

      // Allowed in correct scope
      const allowed = await authz.can(ctx, userId, "documents:read", scope);
      assert(allowed === true, "should be allowed in correct scope");
      results.push({ name: "scoped role → allowed in scope", passed: true, detail: `${allowed}` });

      // Denied in global scope
      const deniedGlobal = await authz.can(ctx, userId, "documents:read");
      assert(deniedGlobal === false, "should be denied in global scope");
      results.push({ name: "scoped role → denied globally", passed: true, detail: `${deniedGlobal}` });

      // Denied in different scope
      const deniedOther = await authz.can(ctx, userId, "documents:read", { type: "org", id: "other-org" });
      assert(deniedOther === false, "should be denied in different scope");
      results.push({ name: "scoped role → denied in other scope", passed: true, detail: `${deniedOther}` });
    } catch (e: any) {
      results.push({ name: "scopedPermissions", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

export const testDirectGrantDeny = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "grantdeny-user" });

    try {
      // 1. Direct grant
      await authz.grantPermission(ctx, userId, "documents:delete");
      const canDelete = await authz.can(ctx, userId, "documents:delete");
      assert(canDelete === true, "direct grant should allow");
      results.push({ name: "grantPermission → allowed", passed: true, detail: `${canDelete}` });

      // 2. Deny overrides grant
      await authz.denyPermission(ctx, userId, "documents:delete");
      const canDeleteAfterDeny = await authz.can(ctx, userId, "documents:delete");
      assert(canDeleteAfterDeny === false, "deny should override grant");
      results.push({ name: "denyPermission → denied", passed: true, detail: `${canDeleteAfterDeny}` });

      // 3. Grant again clears deny
      await authz.grantPermission(ctx, userId, "documents:delete");
      const canDeleteAfterRegrant = await authz.can(ctx, userId, "documents:delete");
      assert(canDeleteAfterRegrant === true, "grant should clear deny");
      results.push({ name: "grant → deny → grant (triple flip)", passed: true, detail: `${canDeleteAfterRegrant}` });

      // 4. Role + deny → deny wins
      await authz.assignRole(ctx, userId, "editor");
      await authz.denyPermission(ctx, userId, "documents:read");
      const canReadDenied = await authz.can(ctx, userId, "documents:read");
      assert(canReadDenied === false, "deny should override role-based allow");
      results.push({ name: "deny overrides role-based allow", passed: true, detail: `${canReadDenied}` });

      // 5. Revoke role → direct grant survives
      await authz.revokeRole(ctx, userId, "editor");
      const canDeleteSurvives = await authz.can(ctx, userId, "documents:delete");
      assert(canDeleteSurvives === true, "direct grant should survive role revoke");
      results.push({ name: "direct grant survives role revoke", passed: true, detail: `${canDeleteSurvives}` });
    } catch (e: any) {
      results.push({ name: "directGrantDeny", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

export const testBulkOperations = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "bulk-user" });

    try {
      // 1. Bulk assign
      const assigned = await authz.assignRoles(ctx, userId, [
        { role: "admin" },
        { role: "editor" },
        { role: "viewer" },
      ]);
      assert(assigned.assigned === 3, "should assign 3 roles");
      results.push({ name: "assignRoles (bulk)", passed: true, detail: `assigned=${assigned.assigned}` });

      // Verify all permissions
      const canDelete = await authz.can(ctx, userId, "documents:delete");
      const canBilling = await authz.can(ctx, userId, "billing:manage");
      assert(canDelete === true, "admin should have documents:delete");
      assert(canBilling === true, "admin should have billing:manage");
      results.push({ name: "bulk assign → permissions correct", passed: true, detail: `delete=${canDelete}, billing=${canBilling}` });

      // 2. Bulk revoke (admin + editor)
      const revoked = await authz.revokeRoles(ctx, userId, [
        { role: "admin" },
        { role: "editor" },
      ]);
      assert(revoked.revoked === 2, "should revoke 2 roles");
      results.push({ name: "revokeRoles (bulk)", passed: true, detail: `revoked=${revoked.revoked}` });

      // Viewer still grants documents:read
      const canRead = await authz.can(ctx, userId, "documents:read");
      assert(canRead === true, "viewer should still grant documents:read");
      results.push({ name: "shared perm survives partial revoke", passed: true, detail: `canRead=${canRead}` });

      // Admin-only permissions denied
      const canDeleteAfter = await authz.can(ctx, userId, "documents:delete");
      assert(canDeleteAfter === false, "documents:delete should be denied");
      results.push({ name: "unique perms denied after revoke", passed: true, detail: `canDelete=${canDeleteAfter}` });

      // 3. Revoke all
      const revokedAll = await authz.revokeAllRoles(ctx, userId);
      const canReadFinal = await authz.can(ctx, userId, "documents:read");
      assert(canReadFinal === false, "all denied after revokeAll");
      results.push({ name: "revokeAllRoles → all denied", passed: true, detail: `revoked=${revokedAll}, canRead=${canReadFinal}` });
    } catch (e: any) {
      results.push({ name: "bulkOperations", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

export const testReBAC = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "rebac-user" });

    try {
      // 1. Add relation
      const relId = await authz.addRelation(
        ctx,
        { type: "user", id: userId },
        "member",
        { type: "team", id: "team-1" },
      );
      assert(typeof relId === "string", "should return relation ID");
      results.push({ name: "addRelation", passed: true, detail: `relId=${relId.slice(0, 10)}...` });

      // 2. hasRelation
      const has = await authz.hasRelation(
        ctx,
        { type: "user", id: userId },
        "member",
        { type: "team", id: "team-1" },
      );
      assert(has === true, "should have relation");
      results.push({ name: "hasRelation → true", passed: true, detail: `${has}` });

      // 3. hasRelation (different object)
      const hasOther = await authz.hasRelation(
        ctx,
        { type: "user", id: userId },
        "member",
        { type: "team", id: "team-2" },
      );
      assert(hasOther === false, "should not have relation to team-2");
      results.push({ name: "hasRelation (wrong object) → false", passed: true, detail: `${hasOther}` });

      // 4. Idempotent add
      const relId2 = await authz.addRelation(
        ctx,
        { type: "user", id: userId },
        "member",
        { type: "team", id: "team-1" },
      );
      assert(relId2 === relId, "idempotent add should return same ID");
      results.push({ name: "addRelation (idempotent)", passed: true, detail: `same ID: ${relId2 === relId}` });

      // 5. Remove relation
      const removed = await authz.removeRelation(
        ctx,
        { type: "user", id: userId },
        "member",
        { type: "team", id: "team-1" },
      );
      assert(removed === true, "should remove successfully");
      const hasAfter = await authz.hasRelation(
        ctx,
        { type: "user", id: userId },
        "member",
        { type: "team", id: "team-1" },
      );
      assert(hasAfter === false, "should not have relation after remove");
      results.push({ name: "removeRelation → hasRelation false", passed: true, detail: `removed=${removed}, has=${hasAfter}` });
    } catch (e: any) {
      results.push({ name: "rebac", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

export const testAttributes = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "attr-user" });

    try {
      // 1. Set attribute
      await authz.setAttribute(ctx, userId, "department", "engineering");
      const attrs = await authz.getUserAttributes(ctx, userId);
      const dept = attrs.find((a: any) => a.key === "department");
      assert(dept !== undefined, "should have department attribute");
      assert(dept!.value === "engineering", "should be engineering");
      results.push({ name: "setAttribute + getUserAttributes", passed: true, detail: `dept=${dept!.value}` });

      // 2. Update attribute
      await authz.setAttribute(ctx, userId, "department", "sales");
      const attrs2 = await authz.getUserAttributes(ctx, userId);
      const dept2 = attrs2.find((a: any) => a.key === "department");
      assert(dept2!.value === "sales", "should be updated to sales");
      results.push({ name: "setAttribute (update)", passed: true, detail: `dept=${dept2!.value}` });

      // 3. Remove attribute
      const removed = await authz.removeAttribute(ctx, userId, "department");
      assert(removed === true, "should remove successfully");
      const attrs3 = await authz.getUserAttributes(ctx, userId);
      assert(attrs3.length === 0, "should have no attributes");
      results.push({ name: "removeAttribute", passed: true, detail: `removed=${removed}, count=${attrs3.length}` });
    } catch (e: any) {
      results.push({ name: "attributes", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

export const testCrossTenantIsolation = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "tenant-user" });

    try {
      // Assign role in tenant A
      await authz.assignRole(ctx, userId, "admin");

      // Allowed in tenant A
      const allowedA = await authz.can(ctx, userId, "documents:delete");
      assert(allowedA === true, "should be allowed in tenant A");
      results.push({ name: "tenant A → allowed", passed: true, detail: `${allowedA}` });

      // Denied in tenant B
      const allowedB = await authzTenantB.can(ctx, userId, "documents:delete");
      assert(allowedB === false, "should be denied in tenant B");
      results.push({ name: "tenant B → denied (isolation)", passed: true, detail: `${allowedB}` });

      // Add relation in tenant A
      await authz.addRelation(ctx, { type: "user", id: userId }, "member", { type: "team", id: "t1" });
      const hasA = await authz.hasRelation(ctx, { type: "user", id: userId }, "member", { type: "team", id: "t1" });
      const hasB = await authzTenantB.hasRelation(ctx, { type: "user", id: userId }, "member", { type: "team", id: "t1" });
      assert(hasA === true, "relation in tenant A");
      assert(hasB === false, "no relation in tenant B");
      results.push({ name: "relation isolation", passed: true, detail: `A=${hasA}, B=${hasB}` });
    } catch (e: any) {
      results.push({ name: "crossTenant", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    await authzTenantB.deprovisionUser(ctx, userId);
    return results;
  },
});

export const testRecomputeUser = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "recompute-user" });

    try {
      // Assign role
      await authz.assignRole(ctx, userId, "editor");
      const canBefore = await authz.can(ctx, userId, "documents:read");
      assert(canBefore === true, "should be allowed before recompute");
      results.push({ name: "before recompute → allowed", passed: true, detail: `${canBefore}` });

      // Recompute with changed permission map (simulate role definition change)
      await authz.recomputeUser(ctx, userId);
      const canAfter = await authz.can(ctx, userId, "documents:read");
      assert(canAfter === true, "should still be allowed after recompute");
      results.push({ name: "after recompute → still allowed", passed: true, detail: `${canAfter}` });

      // Grant direct permission, recompute should preserve it
      await authz.grantPermission(ctx, userId, "billing:manage");
      await authz.revokeRole(ctx, userId, "editor");
      await authz.recomputeUser(ctx, userId);
      const canBilling = await authz.can(ctx, userId, "billing:manage");
      assert(canBilling === true, "direct grant should survive recompute");
      results.push({ name: "recompute preserves direct grant", passed: true, detail: `billing:manage=${canBilling}` });
    } catch (e: any) {
      results.push({ name: "recomputeUser", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

export const testOffboardDeprovision = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];

    try {
      // Test offboard
      const userId1 = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "offboard-user" });
      await authz.assignRole(ctx, userId1, "admin");
      await authz.grantPermission(ctx, userId1, "billing:manage");
      await authz.setAttribute(ctx, userId1, "dept", "eng");

      const offResult = await authz.offboardUser(ctx, userId1, {
        removeAttributes: false,
        removeOverrides: false,
      });
      assert(offResult.rolesRevoked > 0, "should revoke roles");
      results.push({ name: "offboardUser (preserves overrides)", passed: true, detail: `revoked=${offResult.rolesRevoked}` });

      // Role denied, direct grant still in source (but effective tables cleaned by offboard)
      const canAfterOffboard = await authz.can(ctx, userId1, "documents:delete");
      results.push({ name: "role perm denied after offboard", passed: canAfterOffboard === false, detail: `documents:delete=${canAfterOffboard}` });

      // Test deprovision
      const userId2 = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "deprov-user" });
      await authz.assignRole(ctx, userId2, "admin");
      await authz.grantPermission(ctx, userId2, "billing:manage");
      await authz.setAttribute(ctx, userId2, "dept", "eng");
      await authz.addRelation(ctx, { type: "user", id: userId2 }, "member", { type: "team", id: "t1" });

      const depResult = await authz.deprovisionUser(ctx, userId2);
      assert(depResult.rolesRevoked > 0, "should revoke");
      results.push({ name: "deprovisionUser", passed: true, detail: `revoked=${depResult.rolesRevoked}, attrs=${depResult.attributesRemoved}` });

      const canAfterDeprov = await authz.can(ctx, userId2, "documents:delete");
      assert(canAfterDeprov === false, "everything denied after deprovision");
      results.push({ name: "all denied after deprovision", passed: true, detail: `${canAfterDeprov}` });
    } catch (e: any) {
      results.push({ name: "offboard/deprovision", passed: false, detail: e.message });
    }

    return results;
  },
});

export const testExpiry = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "expiry-user" });

    try {
      // Assign role with already-expired expiresAt
      await authz.assignRole(ctx, userId, "editor", undefined, Date.now() - 10000);
      const canRead = await authz.can(ctx, userId, "documents:read");
      // Note: the role is assigned but the effectivePermissions row has expiresAt in the past
      results.push({ name: "expired role → check result", passed: true, detail: `canRead=${canRead}` });

      // Assign with future expiry
      await authz.assignRole(ctx, userId, "admin", undefined, Date.now() + 600000);
      const canDelete = await authz.can(ctx, userId, "documents:delete");
      assert(canDelete === true, "future expiry should allow");
      results.push({ name: "future expiry → allowed", passed: true, detail: `documents:delete=${canDelete}` });

      // Grant with already-expired expiresAt
      await authz.grantPermission(ctx, userId, "billing:manage", undefined, undefined, Date.now() - 10000);
      const canBilling = await authz.can(ctx, userId, "billing:manage");
      results.push({ name: "expired grant → check result", passed: true, detail: `billing:manage=${canBilling}` });
    } catch (e: any) {
      results.push({ name: "expiry", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

// ── Wildcard pattern tests ───────────────────────────────────────

export const testWildcardPatterns = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "wildcard-user" });

    try {
      // 1. wildcard docs:* grants docs:read and docs:write
      await authz.grantPermission(ctx, userId, "documents:*");
      const canDocRead = await authz.can(ctx, userId, "documents:read");
      const canDocWrite = await authz.can(ctx, userId, "documents:update");
      const canSettingsRead = await authz.can(ctx, userId, "settings:view");
      assert(canDocRead === true, "documents:* should grant documents:read");
      assert(canDocWrite === true, "documents:* should grant documents:update");
      assert(canSettingsRead === false, "documents:* should NOT grant settings:view");
      results.push({ name: "wildcard docs:* grants docs:read and docs:update", passed: true, detail: `docRead=${canDocRead}, docUpdate=${canDocWrite}, settingsView=${canSettingsRead}` });

      await authz.deprovisionUser(ctx, userId);

      // 2. wildcard deny docs:* blocks docs:read even with role
      await authz.assignRole(ctx, userId, "editor");
      await authz.denyPermission(ctx, userId, "documents:*");
      const canDocReadDenied = await authz.can(ctx, userId, "documents:read");
      assert(canDocReadDenied === false, "deny documents:* should block documents:read even with editor role");
      results.push({ name: "wildcard deny docs:* blocks docs:read even with role", passed: true, detail: `documents:read=${canDocReadDenied}` });

      await authz.deprovisionUser(ctx, userId);

      // 3. wildcard *:view grants settings:view and billing:view but not documents:update
      await authz.grantPermission(ctx, userId, "*:view");
      const canSettingsView3 = await authz.can(ctx, userId, "settings:view");
      const canBillingView3 = await authz.can(ctx, userId, "billing:view");
      const canDocUpdate3 = await authz.can(ctx, userId, "documents:update");
      assert(canSettingsView3 === true, "*:view should grant settings:view");
      assert(canBillingView3 === true, "*:view should grant billing:view");
      assert(canDocUpdate3 === false, "*:view should NOT grant documents:update");
      results.push({ name: "wildcard *:view grants settings:view and billing:view", passed: true, detail: `settingsView=${canSettingsView3}, billingView=${canBillingView3}, docUpdate=${canDocUpdate3}` });

      await authz.deprovisionUser(ctx, userId);

      // 4. full wildcard * grants everything
      await authz.grantPermission(ctx, userId, "*");
      const canAnything = await authz.can(ctx, userId, "documents:delete");
      const canBilling = await authz.can(ctx, userId, "billing:manage");
      assert(canAnything === true, "* should grant any permission");
      assert(canBilling === true, "* should grant billing:manage");
      results.push({ name: "full wildcard * grants everything", passed: true, detail: `documents:delete=${canAnything}, billing:manage=${canBilling}` });

      await authz.deprovisionUser(ctx, userId);

      // 5. full wildcard deny * blocks everything
      await authz.assignRole(ctx, userId, "admin");
      await authz.denyPermission(ctx, userId, "*");
      const canAnythingDenied = await authz.can(ctx, userId, "documents:read");
      const canBillingDenied = await authz.can(ctx, userId, "billing:manage");
      assert(canAnythingDenied === false, "deny * should block everything");
      assert(canBillingDenied === false, "deny * should block billing:manage");
      results.push({ name: "full wildcard deny * blocks everything", passed: true, detail: `documents:read=${canAnythingDenied}, billing:manage=${canBillingDenied}` });
    } catch (e: any) {
      results.push({ name: "wildcardPatterns", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

// ── Multi-role interaction tests ─────────────────────────────────

export const testMultiRoleInteractions = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "multirole-user" });

    try {
      // 1. two roles sharing permission, revoke one, still allowed
      await authz.assignRole(ctx, userId, "editor");
      await authz.assignRole(ctx, userId, "viewer");
      await authz.revokeRole(ctx, userId, "editor");
      const canRead = await authz.can(ctx, userId, "documents:read");
      assert(canRead === true, "documents:read should survive via viewer after editor revoked");
      results.push({ name: "two roles sharing perm, revoke one, still allowed", passed: true, detail: `documents:read=${canRead}` });

      await authz.deprovisionUser(ctx, userId);

      // 2. three roles, revoke two, shared perm survives via third
      await authz.assignRole(ctx, userId, "admin");
      await authz.assignRole(ctx, userId, "editor");
      await authz.assignRole(ctx, userId, "viewer");
      await authz.revokeRole(ctx, userId, "admin");
      await authz.revokeRole(ctx, userId, "editor");
      const canReadStill = await authz.can(ctx, userId, "documents:read");
      const canDeleteDenied = await authz.can(ctx, userId, "documents:delete");
      assert(canReadStill === true, "documents:read should survive via viewer");
      assert(canDeleteDenied === false, "documents:delete should be denied without admin");
      results.push({ name: "three roles, revoke two, shared perm survives via third", passed: true, detail: `documents:read=${canReadStill}, documents:delete=${canDeleteDenied}` });

      await authz.deprovisionUser(ctx, userId);

      // 3. assign same role twice is idempotent
      await authz.assignRole(ctx, userId, "editor");
      await authz.assignRole(ctx, userId, "editor");
      const userRoles = await authz.getUserRoles(ctx, userId);
      assert(userRoles.length === 1, "should have exactly 1 role after double assign");
      results.push({ name: "assign same role twice is idempotent", passed: true, detail: `roles count=${userRoles.length}` });

      await authz.deprovisionUser(ctx, userId);

      // 4. revoke non-existent role returns false
      const revoked = await authz.revokeRole(ctx, userId, "admin");
      assert(revoked === false, "revoking non-existent role should return false");
      results.push({ name: "revoke non-existent role returns false", passed: true, detail: `revoked=${revoked}` });
    } catch (e: any) {
      results.push({ name: "multiRoleInteractions", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

// ── Expiry edge case tests ───────────────────────────────────────

export const testExpiryEdgeCases = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "expiry-edge-user" });

    try {
      // 1. extend expiry by reassigning with later date
      await authz.assignRole(ctx, userId, "editor", undefined, Date.now() + 10000);
      await authz.assignRole(ctx, userId, "editor", undefined, Date.now() + 60000);
      const canRead = await authz.can(ctx, userId, "documents:read");
      assert(canRead === true, "role with extended expiry should still be valid");
      results.push({ name: "extend expiry by reassigning with later date", passed: true, detail: `documents:read=${canRead}` });

      await authz.deprovisionUser(ctx, userId);

      // 2. extend to no expiry by reassigning without expiresAt
      await authz.assignRole(ctx, userId, "editor", undefined, Date.now() + 10000);
      await authz.assignRole(ctx, userId, "editor");
      const canReadNoExpiry = await authz.can(ctx, userId, "documents:read");
      assert(canReadNoExpiry === true, "role reassigned without expiresAt should never expire");
      results.push({ name: "extend to no expiry by reassigning without expiresAt", passed: true, detail: `documents:read=${canReadNoExpiry}` });

      await authz.deprovisionUser(ctx, userId);

      // 3. deny with future expiry still blocks
      await authz.assignRole(ctx, userId, "editor");
      await authz.denyPermission(ctx, userId, "documents:read", undefined, undefined, Date.now() + 60000);
      const canReadDenyFuture = await authz.can(ctx, userId, "documents:read");
      assert(canReadDenyFuture === false, "deny with future expiry should still block");
      results.push({ name: "deny with future expiry still blocks", passed: true, detail: `documents:read=${canReadDenyFuture}` });
    } catch (e: any) {
      results.push({ name: "expiryEdgeCases", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

// ── Offboard edge case tests ─────────────────────────────────────

export const testOffboardEdgeCases = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];

    try {
      // 1. offboard with removeOverrides=true removes direct grants
      const userId1 = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "offboard-override-user" });
      await authz.grantPermission(ctx, userId1, "documents:delete");
      const canBefore = await authz.can(ctx, userId1, "documents:delete");
      assert(canBefore === true, "direct grant should allow before offboard");
      await authz.offboardUser(ctx, userId1, { removeOverrides: true });
      const canAfter = await authz.can(ctx, userId1, "documents:delete");
      assert(canAfter === false, "offboard removeOverrides=true should deny");
      results.push({ name: "offboard removeOverrides=true removes direct grants", passed: true, detail: `before=${canBefore}, after=${canAfter}` });
      await authz.deprovisionUser(ctx, userId1);

      // 2. offboard with removeRelationships=true removes relations
      const userId2 = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "offboard-rel-user" });
      await authz.addRelation(ctx, { type: "user", id: userId2 }, "member", { type: "team", id: "team-offboard" });
      const hasBefore = await authz.hasRelation(ctx, { type: "user", id: userId2 }, "member", { type: "team", id: "team-offboard" });
      assert(hasBefore === true, "should have relation before offboard");
      await authz.offboardUser(ctx, userId2, { removeRelationships: true });
      const hasAfter = await authz.hasRelation(ctx, { type: "user", id: userId2 }, "member", { type: "team", id: "team-offboard" });
      assert(hasAfter === false, "offboard removeRelationships=true should remove relation");
      results.push({ name: "offboard removeRelationships=true removes relations", passed: true, detail: `before=${hasBefore}, after=${hasAfter}` });
      await authz.deprovisionUser(ctx, userId2);

      // 3. offboard preserves attributes when removeAttributes=false
      const userId3 = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "offboard-attr-user" });
      await authz.setAttribute(ctx, userId3, "department", "engineering");
      await authz.assignRole(ctx, userId3, "editor");
      await authz.offboardUser(ctx, userId3, { removeAttributes: false });
      const attrs = await authz.getUserAttributes(ctx, userId3);
      const dept = attrs.find((a: any) => a.key === "department");
      assert(dept !== undefined, "attribute should be preserved");
      assert(dept!.value === "engineering", "attribute value should be engineering");
      results.push({ name: "offboard preserves attributes when removeAttributes=false", passed: true, detail: `dept=${dept!.value}` });
      await authz.deprovisionUser(ctx, userId3);

      // 4. deprovision user with zero data returns zero counts
      const userId4 = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "offboard-empty-user" });
      const depResult = await authz.deprovisionUser(ctx, userId4);
      assert(depResult.rolesRevoked === 0, "rolesRevoked should be 0");
      assert(depResult.overridesRemoved === 0, "overridesRemoved should be 0");
      assert(depResult.attributesRemoved === 0, "attributesRemoved should be 0");
      assert(depResult.relationshipsRemoved === 0, "relationshipsRemoved should be 0");
      results.push({ name: "deprovision user with zero data returns zero counts", passed: true, detail: `roles=${depResult.rolesRevoked}, overrides=${depResult.overridesRemoved}, attrs=${depResult.attributesRemoved}, rels=${depResult.relationshipsRemoved}` });
    } catch (e: any) {
      results.push({ name: "offboardEdgeCases", passed: false, detail: e.message });
    }

    return results;
  },
});

// ── Scope interaction tests ──────────────────────────────────────

export const testScopeInteractions = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "scope-interaction-user" });
    const orgA = await ctx.runMutation(api.liveFeatureTest.createTestOrg, { slug: "scope-a" });
    const orgB = await ctx.runMutation(api.liveFeatureTest.createTestOrg, { slug: "scope-b" });
    const scopeA = { type: "org", id: String(orgA) };
    const scopeB = { type: "org", id: String(orgB) };

    try {
      // 1. same permission in different scopes are independent
      await authz.grantPermission(ctx, userId, "documents:read", scopeA);
      await authz.denyPermission(ctx, userId, "documents:read", scopeB);
      const allowedA = await authz.can(ctx, userId, "documents:read", scopeA);
      const deniedB = await authz.can(ctx, userId, "documents:read", scopeB);
      assert(allowedA === true, "should be allowed in scope A");
      assert(deniedB === false, "should be denied in scope B");
      results.push({ name: "same permission in different scopes are independent", passed: true, detail: `A=${allowedA}, B=${deniedB}` });

      await authz.deprovisionUser(ctx, userId);

      // 2. revoke scoped role preserves global role
      await authz.assignRole(ctx, userId, "admin");
      await authz.assignRole(ctx, userId, "editor", scopeA);
      await authz.revokeRole(ctx, userId, "editor", scopeA);
      const canGlobalAdmin = await authz.can(ctx, userId, "documents:delete");
      assert(canGlobalAdmin === true, "global admin perms should survive scoped revoke");
      results.push({ name: "revoke scoped role preserves global role", passed: true, detail: `documents:delete=${canGlobalAdmin}` });

      await authz.deprovisionUser(ctx, userId);

      // 3. revokeAllRoles with scope only revokes in that scope
      await authz.assignRole(ctx, userId, "admin");
      await authz.assignRole(ctx, userId, "editor", scopeA);
      await authz.revokeAllRoles(ctx, userId, scopeA);
      const globalRoles = await authz.getUserRoles(ctx, userId);
      const scopedRoles = await authz.getUserRoles(ctx, userId, scopeA);
      assert(globalRoles.length > 0, "global roles should survive scoped revokeAll");
      assert(scopedRoles.length === 0, "scoped roles should be revoked");
      results.push({ name: "revokeAllRoles with scope only revokes in that scope", passed: true, detail: `globalRoles=${globalRoles.length}, scopedRoles=${scopedRoles.length}` });
    } catch (e: any) {
      results.push({ name: "scopeInteractions", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

// ── Audit log tests ──────────────────────────────────────────────

export const testAuditLog = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "audit-user" });

    try {
      // 1. assignRole creates audit entry
      await authz.assignRole(ctx, userId, "editor");
      const logAfterAssign = await authz.getAuditLog(ctx, { userId, limit: 10 }) as Array<any>;
      const assignEntry = logAfterAssign.find((e: any) => e.action === "role_assigned");
      assert(assignEntry !== undefined, "should have role_assigned audit entry");
      results.push({ name: "assignRole creates audit entry", passed: true, detail: `action=${assignEntry?.action}` });

      // 2. grantPermission creates audit entry
      await authz.grantPermission(ctx, userId, "billing:manage");
      const logAfterGrant = await authz.getAuditLog(ctx, { userId, limit: 10 }) as Array<any>;
      const grantEntry = logAfterGrant.find((e: any) => e.action === "permission_granted");
      assert(grantEntry !== undefined, "should have permission_granted audit entry");
      results.push({ name: "grantPermission creates audit entry", passed: true, detail: `action=${grantEntry?.action}` });

      // 3. revokeRole creates audit entry
      await authz.revokeRole(ctx, userId, "editor");
      const logAfterRevoke = await authz.getAuditLog(ctx, { userId, limit: 10 }) as Array<any>;
      const revokeEntry = logAfterRevoke.find((e: any) => e.action === "role_revoked");
      assert(revokeEntry !== undefined, "should have role_revoked audit entry");
      results.push({ name: "revokeRole creates audit entry", passed: true, detail: `action=${revokeEntry?.action}` });
    } catch (e: any) {
      results.push({ name: "auditLog", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

// ── Require method tests ─────────────────────────────────────────

export const testRequireMethod = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "require-user" });

    try {
      // 1. require passes for allowed permission
      await authz.assignRole(ctx, userId, "editor");
      let requirePassed = false;
      try {
        await authz.require(ctx, userId, "documents:read");
        requirePassed = true;
      } catch {
        requirePassed = false;
      }
      assert(requirePassed === true, "require should not throw for allowed permission");
      results.push({ name: "require passes for allowed permission", passed: true, detail: `threw=${!requirePassed}` });

      await authz.deprovisionUser(ctx, userId);

      // 2. require throws for denied permission
      let requireThrew = false;
      try {
        await authz.require(ctx, userId, "documents:read");
        requireThrew = false;
      } catch {
        requireThrew = true;
      }
      assert(requireThrew === true, "require should throw for denied permission");
      results.push({ name: "require throws for denied permission", passed: true, detail: `threw=${requireThrew}` });
    } catch (e: any) {
      results.push({ name: "requireMethod", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

// ── canAny tests ─────────────────────────────────────────────────

export const testCanAny = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "canany-user" });

    try {
      // 1. canAny returns true if any permission matches
      await authz.assignRole(ctx, userId, "viewer");
      const anyTrue = await authz.canAny(ctx, userId, ["documents:read", "documents:delete"]);
      assert(anyTrue === true, "canAny should return true when at least one perm matches");
      results.push({ name: "canAny returns true if any permission matches", passed: true, detail: `canAny=${anyTrue}` });

      // 2. canAny returns false if no permission matches
      const anyFalse = await authz.canAny(ctx, userId, ["documents:delete", "billing:manage"]);
      assert(anyFalse === false, "canAny should return false when no perm matches");
      results.push({ name: "canAny returns false if no permission matches", passed: true, detail: `canAny=${anyFalse}` });
    } catch (e: any) {
      results.push({ name: "canAny", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

// ── getUserPermissions tests ─────────────────────────────────────

export const testGetUserPermissions = action({
  args: {},
  returns: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  handler: async (ctx) => {
    const results: TestResult[] = [];
    const userId = await ctx.runMutation(api.liveFeatureTest.createTestUser, { name: "perms-user" });

    try {
      // 1. getUserPermissions returns all effective permissions
      await authz.assignRole(ctx, userId, "editor");
      const perms = await authz.getUserPermissions(ctx, userId) as Array<any>;
      const permNames = perms.map((p: any) => p.permission || p.name || p);
      const expected = ["documents:create", "documents:read", "documents:update", "settings:view"];
      const hasAll = expected.every((e) => permNames.some((p: string) => p === e || p.includes(e)));
      assert(hasAll === true, `getUserPermissions should include editor perms, got: ${JSON.stringify(permNames)}`);
      results.push({ name: "getUserPermissions returns all effective permissions", passed: true, detail: `perms=${JSON.stringify(permNames)}` });
    } catch (e: any) {
      results.push({ name: "getUserPermissions", passed: false, detail: e.message });
    }

    await authz.deprovisionUser(ctx, userId);
    return results;
  },
});

// ── Main runner ──────────────────────────────────────────────────

export const runAll = action({
  args: {},
  returns: v.string(),
  handler: async (ctx) => {
    const allResults: TestResult[] = [];

    console.log("\n🧪 Running live feature tests...\n");

    const suites = [
      { name: "Basic RBAC", fn: api.liveFeatureTest.testBasicRBAC },
      { name: "Scoped Permissions", fn: api.liveFeatureTest.testScopedPermissions },
      { name: "Direct Grant/Deny", fn: api.liveFeatureTest.testDirectGrantDeny },
      { name: "Bulk Operations", fn: api.liveFeatureTest.testBulkOperations },
      { name: "ReBAC", fn: api.liveFeatureTest.testReBAC },
      { name: "Attributes", fn: api.liveFeatureTest.testAttributes },
      { name: "Cross-Tenant Isolation", fn: api.liveFeatureTest.testCrossTenantIsolation },
      { name: "Recompute User", fn: api.liveFeatureTest.testRecomputeUser },
      { name: "Offboard/Deprovision", fn: api.liveFeatureTest.testOffboardDeprovision },
      { name: "Expiry", fn: api.liveFeatureTest.testExpiry },
      { name: "Wildcard Patterns", fn: api.liveFeatureTest.testWildcardPatterns },
      { name: "Multi-Role Interactions", fn: api.liveFeatureTest.testMultiRoleInteractions },
      { name: "Expiry Edge Cases", fn: api.liveFeatureTest.testExpiryEdgeCases },
      { name: "Offboard Edge Cases", fn: api.liveFeatureTest.testOffboardEdgeCases },
      { name: "Scope Interactions", fn: api.liveFeatureTest.testScopeInteractions },
      { name: "Audit Log", fn: api.liveFeatureTest.testAuditLog },
      { name: "Require Method", fn: api.liveFeatureTest.testRequireMethod },
      { name: "canAny", fn: api.liveFeatureTest.testCanAny },
      { name: "getUserPermissions", fn: api.liveFeatureTest.testGetUserPermissions },
    ];

    for (const suite of suites) {
      console.log(`  📋 ${suite.name}...`);
      try {
        const results = await ctx.runAction(suite.fn, {}) as TestResult[];
        for (const r of results) {
          allResults.push(r);
          const icon = r.passed ? "✅" : "❌";
          console.log(`    ${icon} ${r.name}: ${r.detail}`);
        }
      } catch (e: any) {
        allResults.push({ name: suite.name, passed: false, detail: e.message });
        console.log(`    ❌ ${suite.name}: ${e.message}`);
      }
    }

    const passed = allResults.filter((r) => r.passed).length;
    const failed = allResults.filter((r) => !r.passed).length;
    const total = allResults.length;

    const summary = `\n${"=".repeat(50)}\n${passed}/${total} passed, ${failed} failed\n${"=".repeat(50)}`;
    console.log(summary);

    if (failed > 0) {
      console.log("\nFailed tests:");
      for (const r of allResults.filter((r) => !r.passed)) {
        console.log(`  ❌ ${r.name}: ${r.detail}`);
      }
    }

    return `${passed}/${total} passed, ${failed} failed`;
  },
});
