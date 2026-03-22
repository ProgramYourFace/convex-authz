/* eslint-disable */
/**
 * Generated `ComponentApi` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type { FunctionReference } from "convex/server";

/**
 * A utility for referencing a Convex component's exposed API.
 *
 * Useful when expecting a parameter like `components.myComponent`.
 * Usage:
 * ```ts
 * async function myFunction(ctx: QueryCtx, component: ComponentApi) {
 *   return ctx.runQuery(component.someFile.someQuery, { ...args });
 * }
 * ```
 */
export type ComponentApi<Name extends string | undefined = string | undefined> =
  {
    cronSetup: {
      ensureCleanupCronRegistered: FunctionReference<
        "mutation",
        "internal",
        {},
        null,
        Name
      >;
    };
    indexed: {
      addRelationWithCompute: FunctionReference<
        "mutation",
        "internal",
        {
          createdBy?: string;
          inheritedRelations?: Array<{
            fromObjectType: string;
            fromRelation: string;
            relation: string;
          }>;
          objectId: string;
          objectType: string;
          relation: string;
          subjectId: string;
          subjectType: string;
          tenantId: string;
        },
        string,
        Name
      >;
      assignRolesWithCompute: FunctionReference<
        "mutation",
        "internal",
        {
          assignedBy?: string;
          rolePermissionsMap: Record<string, Array<string>>;
          roles: Array<{
            expiresAt?: number;
            metadata?: any;
            role: string;
            scope?: { id: string; type: string };
          }>;
          tenantId: string;
          userId: string;
        },
        { assigned: number; assignmentIds: Array<string> },
        Name
      >;
      assignRoleWithCompute: FunctionReference<
        "mutation",
        "internal",
        {
          assignedBy?: string;
          expiresAt?: number;
          role: string;
          rolePermissions: Array<string>;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        string,
        Name
      >;
      checkPermissionFast: FunctionReference<
        "query",
        "internal",
        {
          objectId?: string;
          objectType?: string;
          permission: string;
          tenantId: string;
          userId: string;
        },
        boolean,
        Name
      >;
      checkPermissionsFast: FunctionReference<
        "query",
        "internal",
        {
          objectId?: string;
          objectType?: string;
          permissions: Array<string>;
          tenantId: string;
          userId: string;
        },
        boolean,
        Name
      >;
      cleanupExpired: FunctionReference<
        "mutation",
        "internal",
        { tenantId: string },
        { expiredPermissions: number; expiredRoles: number },
        Name
      >;
      denyPermissionDirect: FunctionReference<
        "mutation",
        "internal",
        {
          deniedBy?: string;
          expiresAt?: number;
          permission: string;
          reason?: string;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        string,
        Name
      >;
      getUserPermissionsFast: FunctionReference<
        "query",
        "internal",
        { scopeKey?: string; tenantId: string; userId: string },
        Array<{
          effect: string;
          permission: string;
          scopeKey: string;
          sources: Array<string>;
        }>,
        Name
      >;
      getUserRolesFast: FunctionReference<
        "query",
        "internal",
        { scopeKey?: string; tenantId: string; userId: string },
        Array<{
          role: string;
          scope?: { id: string; type: string };
          scopeKey: string;
        }>,
        Name
      >;
      grantPermissionDirect: FunctionReference<
        "mutation",
        "internal",
        {
          expiresAt?: number;
          grantedBy?: string;
          permission: string;
          reason?: string;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        string,
        Name
      >;
      hasRelationFast: FunctionReference<
        "query",
        "internal",
        {
          objectId: string;
          objectType: string;
          relation: string;
          subjectId: string;
          subjectType: string;
          tenantId: string;
        },
        boolean,
        Name
      >;
      hasRoleFast: FunctionReference<
        "query",
        "internal",
        {
          objectId?: string;
          objectType?: string;
          role: string;
          tenantId: string;
          userId: string;
        },
        boolean,
        Name
      >;
      removeRelationWithCompute: FunctionReference<
        "mutation",
        "internal",
        {
          objectId: string;
          objectType: string;
          relation: string;
          subjectId: string;
          subjectType: string;
          tenantId: string;
        },
        boolean,
        Name
      >;
      revokeRolesWithCompute: FunctionReference<
        "mutation",
        "internal",
        {
          rolePermissionsMap: Record<string, Array<string>>;
          roles: Array<{ role: string; scope?: { id: string; type: string } }>;
          tenantId: string;
          userId: string;
        },
        { revoked: number },
        Name
      >;
      revokeRoleWithCompute: FunctionReference<
        "mutation",
        "internal",
        {
          role: string;
          rolePermissions: Array<string>;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        boolean,
        Name
      >;
    };
    mutations: {
      assignRole: FunctionReference<
        "mutation",
        "internal",
        {
          assignedBy?: string;
          enableAudit?: boolean;
          expiresAt?: number;
          metadata?: any;
          role: string;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        string,
        Name
      >;
      assignRoles: FunctionReference<
        "mutation",
        "internal",
        {
          assignedBy?: string;
          enableAudit?: boolean;
          roles: Array<{
            expiresAt?: number;
            metadata?: any;
            role: string;
            scope?: { id: string; type: string };
          }>;
          tenantId: string;
          userId: string;
        },
        { assigned: number; assignmentIds: Array<string> },
        Name
      >;
      cleanupExpired: FunctionReference<
        "mutation",
        "internal",
        { tenantId?: string },
        { expiredOverrides: number; expiredRoles: number },
        Name
      >;
      denyPermission: FunctionReference<
        "mutation",
        "internal",
        {
          createdBy?: string;
          enableAudit?: boolean;
          expiresAt?: number;
          permission: string;
          reason?: string;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        string,
        Name
      >;
      deprovisionUser: FunctionReference<
        "mutation",
        "internal",
        {
          enableAudit?: boolean;
          revokedBy?: string;
          tenantId: string;
          userId: string;
        },
        {
          attributesRemoved: number;
          effectivePermissionsRemoved: number;
          effectiveRelationshipsRemoved: number;
          effectiveRolesRemoved: number;
          overridesRemoved: number;
          relationshipsRemoved: number;
          rolesRevoked: number;
        },
        Name
      >;
      grantPermission: FunctionReference<
        "mutation",
        "internal",
        {
          createdBy?: string;
          enableAudit?: boolean;
          expiresAt?: number;
          permission: string;
          reason?: string;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        string,
        Name
      >;
      logPermissionCheck: FunctionReference<
        "mutation",
        "internal",
        {
          permission: string;
          reason?: string;
          result: boolean;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        null,
        Name
      >;
      offboardUser: FunctionReference<
        "mutation",
        "internal",
        {
          enableAudit?: boolean;
          removeAttributes?: boolean;
          removeOverrides?: boolean;
          removeRelationships?: boolean;
          revokedBy?: string;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        {
          attributesRemoved: number;
          effectivePermissionsRemoved: number;
          effectiveRelationshipsRemoved: number;
          effectiveRolesRemoved: number;
          overridesRemoved: number;
          relationshipsRemoved: number;
          rolesRevoked: number;
        },
        Name
      >;
      removeAllAttributes: FunctionReference<
        "mutation",
        "internal",
        {
          enableAudit?: boolean;
          removedBy?: string;
          tenantId: string;
          userId: string;
        },
        number,
        Name
      >;
      removeAttribute: FunctionReference<
        "mutation",
        "internal",
        {
          enableAudit?: boolean;
          key: string;
          removedBy?: string;
          tenantId: string;
          userId: string;
        },
        boolean,
        Name
      >;
      removePermissionOverride: FunctionReference<
        "mutation",
        "internal",
        {
          enableAudit?: boolean;
          permission: string;
          removedBy?: string;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        boolean,
        Name
      >;
      revokeAllRoles: FunctionReference<
        "mutation",
        "internal",
        {
          enableAudit?: boolean;
          revokedBy?: string;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        number,
        Name
      >;
      revokeRole: FunctionReference<
        "mutation",
        "internal",
        {
          enableAudit?: boolean;
          revokedBy?: string;
          role: string;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        boolean,
        Name
      >;
      revokeRoles: FunctionReference<
        "mutation",
        "internal",
        {
          enableAudit?: boolean;
          revokedBy?: string;
          roles: Array<{ role: string; scope?: { id: string; type: string } }>;
          tenantId: string;
          userId: string;
        },
        { revoked: number },
        Name
      >;
      runAuditRetentionCleanup: FunctionReference<
        "mutation",
        "internal",
        { maxAgeDays?: number; maxEntries?: number; tenantId?: string },
        { deletedByAge: number; deletedByCount: number },
        Name
      >;
      runScheduledCleanup: FunctionReference<
        "mutation",
        "internal",
        { tenantId?: string },
        {
          expiredEffectivePermissions: number;
          expiredEffectiveRoles: number;
          expiredOverrides: number;
          expiredRoleAssignments: number;
        },
        Name
      >;
      setAttribute: FunctionReference<
        "mutation",
        "internal",
        {
          enableAudit?: boolean;
          key: string;
          setBy?: string;
          tenantId: string;
          userId: string;
          value: any;
        },
        string,
        Name
      >;
    };
    queries: {
      checkPermission: FunctionReference<
        "query",
        "internal",
        {
          permission: string;
          rolePermissions: Record<string, Array<string>>;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        {
          allowed: boolean;
          matchedOverride?: string;
          matchedRole?: string;
          reason: string;
        },
        Name
      >;
      checkPermissions: FunctionReference<
        "query",
        "internal",
        {
          permissions: Array<string>;
          rolePermissions: Record<string, Array<string>>;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        { allowed: boolean; matchedPermission?: string },
        Name
      >;
      getAuditLog: FunctionReference<
        "query",
        "internal",
        {
          action?:
            | "permission_check"
            | "role_assigned"
            | "role_revoked"
            | "permission_granted"
            | "permission_denied"
            | "attribute_set"
            | "attribute_removed";
          limit?: number;
          paginationOpts?: {
            cursor: string | null;
            endCursor?: string | null;
            id?: number;
            maximumBytesRead?: number;
            maximumRowsRead?: number;
            numItems: number;
          };
          tenantId: string;
          userId?: string;
        },
        | Array<{
            _id: string;
            action: string;
            actorId?: string;
            details: any;
            timestamp: number;
            userId: string;
          }>
        | {
            continueCursor: string;
            isDone: boolean;
            page: Array<{
              _id: string;
              action: string;
              actorId?: string;
              details: any;
              timestamp: number;
              userId: string;
            }>;
          },
        Name
      >;
      getEffectivePermissions: FunctionReference<
        "query",
        "internal",
        {
          rolePermissions: Record<string, Array<string>>;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        {
          deniedPermissions: Array<string>;
          permissions: Array<string>;
          roles: Array<string>;
        },
        Name
      >;
      getPermissionOverrides: FunctionReference<
        "query",
        "internal",
        { permission?: string; tenantId: string; userId: string },
        Array<{
          _id: string;
          effect: "allow" | "deny";
          expiresAt?: number;
          permission: string;
          reason?: string;
          scope?: { id: string; type: string };
        }>,
        Name
      >;
      getUserAttribute: FunctionReference<
        "query",
        "internal",
        { key: string; tenantId: string; userId: string },
        null | any,
        Name
      >;
      getUserAttributes: FunctionReference<
        "query",
        "internal",
        { tenantId: string; userId: string },
        Array<{ _id: string; key: string; value: any }>,
        Name
      >;
      getUserRoles: FunctionReference<
        "query",
        "internal",
        {
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        Array<{
          _id: string;
          expiresAt?: number;
          metadata?: any;
          role: string;
          scope?: { id: string; type: string };
        }>,
        Name
      >;
      getUsersWithRole: FunctionReference<
        "query",
        "internal",
        {
          role: string;
          scope?: { id: string; type: string };
          tenantId: string;
        },
        Array<{ assignedAt: number; expiresAt?: number; userId: string }>,
        Name
      >;
      hasRole: FunctionReference<
        "query",
        "internal",
        {
          role: string;
          scope?: { id: string; type: string };
          tenantId: string;
          userId: string;
        },
        boolean,
        Name
      >;
    };
    rebac: {
      addRelation: FunctionReference<
        "mutation",
        "internal",
        {
          createdBy?: string;
          objectId: string;
          objectType: string;
          relation: string;
          subjectId: string;
          subjectType: string;
          tenantId: string;
        },
        string,
        Name
      >;
      checkRelationWithTraversal: FunctionReference<
        "query",
        "internal",
        {
          maxDepth?: number;
          objectId: string;
          objectType: string;
          relation: string;
          subjectId: string;
          subjectType: string;
          tenantId: string;
          traversalRules?: any;
        },
        { allowed: boolean; path: Array<string>; reason: string },
        Name
      >;
      getObjectRelations: FunctionReference<
        "query",
        "internal",
        {
          objectId: string;
          objectType: string;
          relation?: string;
          tenantId: string;
        },
        Array<{
          _id: string;
          relation: string;
          subjectId: string;
          subjectType: string;
        }>,
        Name
      >;
      getSubjectRelations: FunctionReference<
        "query",
        "internal",
        {
          objectType?: string;
          subjectId: string;
          subjectType: string;
          tenantId: string;
        },
        Array<{
          _id: string;
          objectId: string;
          objectType: string;
          relation: string;
        }>,
        Name
      >;
      hasDirectRelation: FunctionReference<
        "query",
        "internal",
        {
          objectId: string;
          objectType: string;
          relation: string;
          subjectId: string;
          subjectType: string;
          tenantId: string;
        },
        boolean,
        Name
      >;
      listAccessibleObjects: FunctionReference<
        "query",
        "internal",
        {
          objectType: string;
          relation: string;
          subjectId: string;
          subjectType: string;
          tenantId: string;
          traversalRules?: any;
        },
        Array<{ objectId: string; via: string }>,
        Name
      >;
      listUsersWithAccess: FunctionReference<
        "query",
        "internal",
        {
          objectId: string;
          objectType: string;
          relation: string;
          tenantId: string;
        },
        Array<{ userId: string; via: string }>,
        Name
      >;
      removeRelation: FunctionReference<
        "mutation",
        "internal",
        {
          objectId: string;
          objectType: string;
          relation: string;
          subjectId: string;
          subjectType: string;
          tenantId: string;
        },
        boolean,
        Name
      >;
    };
  };
