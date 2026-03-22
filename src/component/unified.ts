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
import { query } from "./_generated/server.js";
import { scopeValidator } from "./validators.js";
import { isExpired, matchesPermissionPattern } from "./helpers.js";

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
