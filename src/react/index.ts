"use client";

import React, {
  createContext,
  useContext,
  useMemo,
  type ReactNode,
} from "react";
import { useQuery } from "convex/react";

// ============================================================================
// Types
// ============================================================================

/**
 * Scope for resource-level permissions (e.g. org, team).
 */
export interface Scope {
  type: string;
  id: string;
}

/**
 * Query refs the app must provide (Convex queries that wrap Authz).
 * Pass these from your API, e.g. queryRefs={{ checkPermission: api.app.checkPermission, getUserRoles: api.app.getUserWithRoles }}.
 * checkPermission should accept { userId, permission, scope? } and return boolean.
 * getUserRoles should accept { userId, scope? } and return an array of role objects.
 */
export interface AuthzQueryRefs {
  checkPermission: Parameters<typeof useQuery>[0];
  getUserRoles: Parameters<typeof useQuery>[0];
}

export interface AuthzProviderValue {
  queryRefs: AuthzQueryRefs;
  defaultUserId: string | undefined;
}

const AuthzContext = createContext<AuthzProviderValue | null>(null);

// ============================================================================
// Provider
// ============================================================================

export interface AuthzProviderProps {
  queryRefs: AuthzQueryRefs;
  defaultUserId?: string;
  children: ReactNode;
}

/**
 * Provides authz query refs and optional default userId to hooks.
 * Wrap your app (or the subtree that uses authz hooks) with this provider.
 */
export function AuthzProvider({
  queryRefs,
  defaultUserId,
  children,
}: AuthzProviderProps) {
  const value = useMemo<AuthzProviderValue>(
    () => ({ queryRefs, defaultUserId }),
    [queryRefs, defaultUserId]
  );
  return React.createElement(AuthzContext.Provider, { value }, children);
}

/**
 * Returns the authz context value. Throws if used outside AuthzProvider.
 */
export function useAuthz(): AuthzProviderValue {
  const ctx = useContext(AuthzContext);
  if (ctx === null) {
    throw new Error("useAuthz must be used within an AuthzProvider");
  }
  return ctx;
}

// ============================================================================
// Hook options
// ============================================================================

export interface UseCanUserOptions {
  userId?: string;
  scope?: Scope;
}

export interface UseUserRolesOptions {
  userId?: string;
  scope?: Scope;
}

// ============================================================================
// useCanUser
// ============================================================================

export interface UseCanUserResult {
  allowed: boolean | undefined;
  isLoading: boolean;
  error: Error | undefined;
}

/**
 * Reactive permission check. Uses Convex useQuery under the hood so the UI updates when permissions change.
 * @param permission - Permission string (e.g. "documents:read")
 * @param options - Optional userId and scope; userId defaults to provider's defaultUserId
 */
export function useCanUser(
  permission: string,
  options?: UseCanUserOptions
): UseCanUserResult {
  const { queryRefs, defaultUserId } = useAuthz();
  const userId = options?.userId ?? defaultUserId;
  const scope = options?.scope;

  const allowed = useQuery(
    queryRefs.checkPermission,
    userId !== undefined && userId !== ""
      ? { userId, permission, scope }
      : "skip"
  );

  if (userId === undefined || userId === "") {
    return {
      allowed: false,
      isLoading: false,
      error: new Error("userId is required for useCanUser (pass options.userId or AuthzProvider defaultUserId)"),
    };
  }

  return {
    allowed: allowed === undefined ? undefined : allowed,
    isLoading: allowed === undefined,
    error: undefined,
  };
}

// ============================================================================
// useUserRoles
// ============================================================================

export interface UseUserRolesResult {
  roles: unknown[];
  isLoading: boolean;
  error: Error | undefined;
}

/**
 * Observe a user's roles. Uses Convex useQuery for reactive updates.
 */
export function useUserRoles(options?: UseUserRolesOptions): UseUserRolesResult {
  const { queryRefs, defaultUserId } = useAuthz();
  const userId = options?.userId ?? defaultUserId;
  const scope = options?.scope;

  const roles = useQuery(
    queryRefs.getUserRoles,
    userId !== undefined && userId !== ""
      ? { userId, scope }
      : "skip"
  );

  if (userId === undefined || userId === "") {
    return {
      roles: [],
      isLoading: false,
      error: new Error("userId is required for useUserRoles (pass options.userId or AuthzProvider defaultUserId)"),
    };
  }

  return {
    roles: roles ?? [],
    isLoading: roles === undefined,
    error: undefined,
  };
}

// ============================================================================
// useRequirePermission
// ============================================================================

/**
 * Like useCanUser but throws when the user does not have the permission (after loading).
 * Use an error boundary to catch the error and show an access-denied UI.
 */
export function useRequirePermission(
  permission: string,
  options?: UseCanUserOptions
): void {
  const { allowed, isLoading, error } = useCanUser(permission, options);

  if (error !== undefined) {
    throw error;
  }

  if (!isLoading && allowed === false) {
    throw new Error(
      `Permission denied: ${permission}${options?.scope ? ` on ${options.scope.type}:${options.scope.id}` : ""}`
    );
  }
}

// ============================================================================
// PermissionGate
// ============================================================================

export interface PermissionGateProps {
  permission: string;
  userId?: string;
  scope?: Scope;
  fallback?: ReactNode;
  loadingFallback?: ReactNode;
  children: ReactNode;
}

/**
 * Declarative gate: renders children only when the user has the permission; otherwise renders fallback.
 * Shows loadingFallback while the permission check is loading.
 */
export function PermissionGate({
  permission,
  userId,
  scope,
  fallback = null,
  loadingFallback = null,
  children,
}: PermissionGateProps): ReactNode {
  const { allowed, isLoading } = useCanUser(permission, { userId, scope });

  if (isLoading) {
    return loadingFallback;
  }

  if (allowed !== true) {
    return fallback;
  }

  return children;
}
