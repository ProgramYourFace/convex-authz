// Helper types and utilities for authorization checks

/**
 * Check if a role assignment has expired
 */
export function isExpired(expiresAt: number | undefined | null): boolean {
  if (expiresAt === undefined || expiresAt === null) return false;
  return Date.now() > expiresAt;
}

/**
 * Parse a permission string into resource and action parts
 * e.g., "documents:read" -> { resource: "documents", action: "read" }
 */
export function parsePermission(permission: string): {
  resource: string;
  action: string;
} {
  const parts = permission.split(":");
  if (parts.length !== 2) {
    throw new Error(
      `Invalid permission format: "${permission}". Expected "resource:action"`
    );
  }
  return { resource: parts[0], action: parts[1] };
}

/**
 * Build a permission string from resource and action
 */
export function buildPermission(resource: string, action: string): string {
  return `${resource}:${action}`;
}

/**
 * Check if a permission matches a pattern (supports wildcards)
 * Patterns:
 * - "*" matches everything
 * - "documents:*" matches all document actions
 * - "*:read" matches read action on all resources
 */
export function matchesPermissionPattern(
  permission: string,
  pattern: string
): boolean {
  if (pattern === "*") return true;

  const { resource: permResource, action: permAction } = parsePermission(permission);
  const { resource: patResource, action: patAction } = parsePermission(pattern);

  const resourceMatch = patResource === "*" || patResource === permResource;
  const actionMatch = patAction === "*" || patAction === permAction;

  return resourceMatch && actionMatch;
}

/**
 * Scope matching for resource-level permissions.
 * A global scope (undefined) matches any target scope — use for
 * permission override lookups where a global override covers all scopes.
 * For exact scope equality (e.g., duplicate detection), use scopeEquals in unified.ts instead.
 */
export function matchesScope(
  scope: { type: string; id: string } | undefined,
  targetScope: { type: string; id: string } | undefined
): boolean {
  // No scope = global permission (matches everything)
  if (!scope) return true;
  // Target has no scope but permission is scoped = no match
  if (!targetScope) return false;
  // Both have scope, must match exactly
  return scope.type === targetScope.type && scope.id === targetScope.id;
}
