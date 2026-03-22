import { v } from "convex/values";

export const scopeValidator = v.optional(
  v.object({ type: v.string(), id: v.string() })
);
