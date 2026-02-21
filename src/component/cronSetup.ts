/**
 * Registers the authz cleanup cron with the embedded @convex-dev/crons component.
 * Called lazily so that when a developer installs the component, the cleanup job
 * is auto-registered on first use (no manual crons.ts or init required).
 */

import { v } from "convex/values";
import { mutation } from "./_generated/server";
import { api, components } from "./_generated/api";
import { Crons } from "@convex-dev/crons";

const CRON_NAME = "authz-cleanup-expired";
const INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Idempotently register the scheduled cleanup cron with the crons component.
 * Safe to call on every deploy or from any mutation; only registers if not already present.
 * When the authz component is used (e.g. assignRole, runScheduledCleanup), schedule this
 * once so the cron is auto-set without the app defining crons.ts.
 * No-ops when the crons component is not available (e.g. in convex-test without registering crons).
 */
export const ensureCleanupCronRegistered = mutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    try {
      const crons = new Crons(components.crons);
      const existing = await crons.get(ctx, { name: CRON_NAME });
      if (existing === null) {
        await crons.register(
          ctx,
          { kind: "interval", ms: INTERVAL_MS },
          api.mutations.runScheduledCleanup,
          {},
          CRON_NAME
        );
      }
    } catch (err) {
      // In tests the crons component may not be registered; ignore so tests don't need to set it up
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes("is not registered")) throw err;
    }
    return null;
  },
});
