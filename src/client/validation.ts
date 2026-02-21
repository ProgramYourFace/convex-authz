/**
 * Input validation for Authz and IndexedAuthz public APIs.
 * All validators throw Error with clear messages for invalid arguments.
 */

import { parsePermission } from "../component/helpers.js";

const MAX_USER_ID_LENGTH = 512;
const MAX_AUDIT_LIMIT = 1000;

export interface ScopeLike {
  type: string;
  id: string;
}

/**
 * Validate userId: non-empty string (after trim), max length 512.
 */
export function validateUserId(userId: string): void {
  if (typeof userId !== "string") {
    throw new Error("userId must be a string");
  }
  const trimmed = userId.trim();
  if (trimmed.length === 0) {
    throw new Error("userId must be a non-empty string");
  }
  if (userId.length > MAX_USER_ID_LENGTH) {
    throw new Error(`userId must not exceed ${MAX_USER_ID_LENGTH} characters`);
  }
}

/**
 * Validate permission format: "resource:action". Uses parsePermission from helpers.
 */
export function validatePermission(permission: string): void {
  if (typeof permission !== "string") {
    throw new Error("permission must be a string");
  }
  parsePermission(permission);
}

/**
 * Validate scope when provided: type and id must be non-empty strings.
 */
export function validateScope(scope: ScopeLike | undefined): void {
  if (scope === undefined || scope === null) return;
  if (typeof scope !== "object" || Array.isArray(scope)) {
    throw new Error("scope must be an object with type and id when provided");
  }
  if (typeof scope.type !== "string" || scope.type.trim().length === 0) {
    throw new Error("scope must have non-empty type when provided");
  }
  if (typeof scope.id !== "string" || scope.id.trim().length === 0) {
    throw new Error("scope must have non-empty id when provided");
  }
}

/**
 * Validate role: non-empty string. If knownRoles provided, role must be one of them.
 */
export function validateRole(
  role: string,
  knownRoles?: Set<string> | Record<string, unknown>
): void {
  if (typeof role !== "string") {
    throw new Error("role must be a string");
  }
  if (role.trim().length === 0) {
    throw new Error("role must be a non-empty string");
  }
  if (knownRoles !== undefined) {
    const set =
      knownRoles instanceof Set
        ? knownRoles
        : new Set(Object.keys(knownRoles));
    if (!set.has(role)) {
      throw new Error(`Unknown role: "${role}"`);
    }
  }
}

/**
 * Validate optional expiresAt: if provided, must be a finite number (timestamp).
 * Past timestamps are allowed (e.g. for tests or backdating).
 */
export function validateOptionalExpiresAt(expiresAt: number | undefined): void {
  if (expiresAt === undefined) return;
  if (typeof expiresAt !== "number") {
    throw new Error("expiresAt must be a number when provided");
  }
  if (!Number.isFinite(expiresAt)) {
    throw new Error("expiresAt must be a finite number");
  }
}

/**
 * Validate attribute key: non-empty string.
 */
export function validateAttributeKey(key: string): void {
  if (typeof key !== "string") {
    throw new Error("Attribute key must be a string");
  }
  if (key.trim().length === 0) {
    throw new Error("Attribute key must be a non-empty string");
  }
}

/**
 * Validate audit log limit: if provided, must be a positive integer in [1, 1000].
 */
export function validateAuditLimit(limit: number | undefined): void {
  if (limit === undefined) return;
  if (typeof limit !== "number") {
    throw new Error("limit must be a number when provided");
  }
  if (!Number.isInteger(limit) || limit < 1) {
    throw new Error("limit must be a positive integer when provided");
  }
  if (limit > MAX_AUDIT_LIMIT) {
    throw new Error(`limit must not exceed ${MAX_AUDIT_LIMIT}`);
  }
}

/**
 * Validate relation args for hasRelation, addRelation, removeRelation: all non-empty strings.
 */
export function validateRelationArgs(
  subjectType: string,
  subjectId: string,
  relation: string,
  objectType: string,
  objectId: string
): void {
  const check = (name: string, value: string) => {
    if (typeof value !== "string") {
      throw new Error(`${name} must be a string`);
    }
    if (value.trim().length === 0) {
      throw new Error(`${name} must be a non-empty string`);
    }
  };
  check("subjectType", subjectType);
  check("subjectId", subjectId);
  check("relation", relation);
  check("objectType", objectType);
  check("objectId", objectId);
}
