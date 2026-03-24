# Changelog

## v2.1.1

- Fix merge conflict markers in README badge section

## v2.1.0

### New features

- **Type-safe permission strings**: `can()`, `require()`, `canAny()`,
  `grantPermission()`, and `denyPermission()` now accept `PermissionArg<P>`
  instead of `string`. TypeScript catches typos like `"documets:read"` or
  `"documents:archive"` at compile time. Wildcards (`"documents:*"`, `"*:read"`,
  `"*"`) are also type-checked against defined resources and actions. New
  exported types: `PermissionString<P>`, `PermissionArg<P>`.

### Tests

- 7 new audit log consumer tests covering every action type: `role_revoked`,
  `permission_denied`, `attribute_set`, `relation_added`, `relation_removed`,
  action filtering, and entry detail verification. 663 total tests.

---

## v2.0.0

### BREAKING CHANGES

- **`IndexedAuthz` removed**: Use `Authz` instead. All IndexedAuthz
  functionality (O(1) reads, ReBAC, pre-computed permissions) is now built into
  the unified `Authz` class. `IndexedAuthz` is no longer exported.

- **`Authz.can()` now reads from effectivePermissions**: Permission checks are
  always O(1) via pre-computed effective tables. Existing `Authz` users must run
  `recomputeUser()` for each user to backfill effective tables after upgrading.

- **`tenantId` required in constructor**:
  `new Authz(component, { ..., tenantId: "my-app" })`. Single-tenant apps pass
  any constant string. Multi-tenant apps pass their org/tenant identifier.

- **All component function args require `tenantId`**: Every mutation, query, and
  ReBAC function now requires `tenantId`. Cleanup/cron mutations accept it as
  optional for global cleanup.

- **All indexes renamed to tenant-prefixed**: `by_user` → `by_tenant_user`,
  `by_role` → `by_tenant_role`, etc. Requires fresh deployment or data
  migration.

- **ReBAC methods use structured objects**: `hasRelation`, `addRelation`,
  `removeRelation` now take `{ type, id }` objects instead of positional string
  arguments.

- **Legacy component functions removed**: Source-only mutations
  (`mutations.assignRole`, `mutations.revokeRole`, `mutations.grantPermission`,
  `mutations.denyPermission`, etc.), old indexed write mutations
  (`indexed.assignRoleWithCompute`, etc.), old ReBAC mutations
  (`rebac.addRelation`, `rebac.removeRelation`), and old query-time permission
  evaluation (`queries.checkPermission`, `queries.checkPermissions`,
  `queries.getEffectivePermissions`) have all been deleted. Use the unified
  Authz client class instead.

- **`MAX_BULK_ROLES` reduced from 100 to 20**: Prevents Convex transaction limit
  overflow (20 roles × ~100 permission lookups = 2,000 db.query calls, safely
  within the 4,096 limit).

### New features

#### Unified Authz class

- Single `Authz` class replaces both `Authz` (scan-based) and `IndexedAuthz`
  (O(1)). All reads are O(1) by default via pre-computed `effectivePermissions`
  table. All writes dual-write to source and effective tables atomically.

#### Tiered permission resolution

- `can()` uses a three-step tiered resolution: (1) O(1) exact lookup in
  effectivePermissions, (2) global wildcard deny check, (3) wildcard pattern
  fallback. Deny always wins.

#### ReBAC → Permission bridge

- `defineRelationPermissions()` maps relationship types to permissions. When
  `addRelation` creates a relationship, it automatically writes scoped
  permissions to `effectivePermissions`. When `removeRelation` deletes a
  relationship, it revokes those permissions. This enables SpiceDB-style
  "relationships grant permissions" without separate `hasRelation()` calls.

#### ABAC deferred policies

- `canWithContext(ctx, userId, permission, scope?, requestContext?)` evaluates
  policies that depend on runtime context (IP address, time of day, request
  headers).
- `definePolicies()` accepts a `type` field (`"static"` or `"deferred"`). Both
  types are evaluated at read time when `can()` is called.
- `PolicyContext` includes `hasRole()`, `hasAttribute()`, `getAttribute()`, and
  `environment` helpers.
- `evaluatePolicyCondition()` now catches errors and returns `false`
  (fail-closed) instead of throwing.

#### Post-deploy rebuild

- `recomputeUser(ctx, userId)` rebuilds a user's effective tables from source
  tables. Use after role definition changes or schema migrations.

#### Cross-tenant operations

- `withTenant(tenantId)` returns a new Authz instance scoped to a different
  tenant for admin operations.

#### Transactional bulk mutations

- `assignRoles()`, `revokeRoles()`, `revokeAllRoles()` now use unified mutations
  that dual-write in a single Convex transaction (previously used two separate
  transactions).

#### Schema additions

- `effectivePermissions`: `policyResult` (`"allow"` | `"deny"` | `"deferred"`),
  `policyName`
- `effectiveRelationships`: `depth`
- `relationships`: `caveat`, `caveatContext`
- `auditLog` actions: `relation_added`, `relation_removed`, `policy_evaluated`
- `auditLog` details: `relation`, `subject`, `object` fields
- `effectivePermissions.effect`: tightened from `v.string()` to
  `v.union(v.literal("allow"), v.literal("deny"))`

#### Definition helpers

- `defineRelationPermissions()` — type-safe relation-to-permission mapping
- `defineTraversalRules()` — type-safe traversal rules for
  `checkRelationWithTraversal`
- `defineCaveats()` — type-safe caveat function definitions

### Bug fixes

- **Cleanup mutations use batched deletion**: `cleanupExpired`,
  `runScheduledCleanup`, `runAuditRetentionCleanup` no longer do full table
  scans. Use `.take(500)` batches to stay within Convex's 16,384 document scan
  limit.
- **ReBAC traversal has `maxBranching` limit**: `checkRelationWithTraversal`
  accepts `maxBranching` (default 50) to prevent exceeding the 4,096 db.query
  call limit on wide graphs.
- **All `.collect()` calls bounded**: Every database query uses `.take(N)` to
  prevent scan limit overflow. 46 unbounded collects fixed across 5 files.
- **Wildcard deny overrides exact allow**: A deny pattern like `"documents:*"`
  now correctly blocks `"documents:read"` even when an exact allow exists.
  Previously the exact match short-circuited before checking deny patterns.
- **`expiresAt` propagated to effectivePermissions**: Role assignments now
  correctly propagate expiry to effective permission rows. Previously, expired
  roles appeared as valid permissions.
- **`expiresAt` merge uses max/undefined-wins**: When two roles grant the same
  permission with different expiries, the effective row uses the later expiry
  (or no expiry if either source has none).
- **Expiry extension updates all tables**: Re-assigning a role with a later
  `expiresAt` now updates `roleAssignments`, `effectiveRoles`, AND
  `effectivePermissions` (previously only updated the source table).
- **`denyPermission` clears `directGrant` flag**: Prevents inconsistent state
  where a row has both `directGrant: true` and `directDeny: true`.
- **`grantPermission` clears `directDeny` and `policyResult`**: Explicit grant
  overrides any deny or policy result.
- **`revokeRole` preserves `directDeny` rows**: Revoking a role no longer
  accidentally deletes explicit deny overrides on shared permissions.
- **`offboardUser` preserves direct grant/deny effective rows**: When
  `removeOverrides=false`, effective permission rows with `directGrant` or
  `directDeny` survive offboarding (previously all effective rows were deleted).
- **`setAttributeWithRecompute` policy re-evaluation works across scopes**: No
  longer hardcoded to `scopeKey: "global"`.
- **`setAttributeWithRecompute` query hoisted outside loop**: Prevents N ×
  full-scan when re-evaluating multiple policies.
- **Scope equality in duplicate detection**: `assignRole`, `revokeRole`,
  `grantPermission`, `denyPermission` now use exact scope equality
  (`scopeEquals`) for duplicate detection instead of asymmetric `matchesScope`.
- **Global wildcard deny checked for scoped permissions**: A global
  `denyPermission("documents:*")` now correctly blocks scoped permission checks.
- **`removeAttribute` triggers policy re-evaluation**: Previously only
  `setAttribute` re-evaluated policies.
- **Audit log uses proper `userId` for ReBAC**: `addRelation`/`removeRelation`
  audit entries use the subject's ID (not a composite string) when the subject
  is a user.
- **`auditLogActionValidator` includes all action types**: `getAuditLog` now
  accepts `"relation_added"`, `"relation_removed"`, and `"policy_evaluated"` as
  filter values.
- **`getAuditLog` TypeScript cast includes all action types**: IntelliSense now
  shows all valid audit action filter values.

### Code cleanup

- **Dead code removed**: 1,837+ lines of dead functions deleted — 11 source-only
  mutations from `mutations.ts`, 8 indexed write mutations from `indexed.ts`, 2
  ReBAC mutations from `rebac.ts`, 3 internal queries from `queries.ts`, 8
  unused helper functions from `helpers.ts`. `helpers.ts` reduced from 244 to 73
  lines.
- **`IndexedAuthz` export removed**: No longer exported from
  `src/client/index.ts`.
- **Unused constructor options removed**: `traversalRules` and `caveats` removed
  from Authz constructor (were accepted but never used). `defineTraversalRules`
  and `defineCaveats` remain as exported helpers for direct component API usage.
- **Shared `scopeValidator`**: Extracted into `src/component/validators.ts`,
  removing ~30 inline duplicates.
- **Test files organized**: All component tests moved to `src/component/tests/`
  subfolder.

### Testing

- **648 tests** across 21 test files
- **40 consumer integration tests**: Full Authz class → real convexTest DB path,
  covering RBAC, role inheritance, deferred policies, scoped permissions,
  cross-tenant isolation, grant/deny interactions, bulk operations, ReBAC with
  permission bridge, wildcards, expiry, offboarding, audit log, and more
- **67 live feature tests**: All features verified against real Convex backend
  with 10K users
- **126 exhaustive invariant tests**: Every write→read interaction, every
  operation pair, every edge case
- **Real-world benchmarks**: 1ms permission checks at 10K user scale on
  production Convex infrastructure

### Migration guide

1. Replace `IndexedAuthz` with `Authz` — same constructor, just rename the
   import.
2. Add `tenantId` to your constructor:
   ```typescript
   const authz = new Authz(components.authz, {
     permissions,
     roles,
     tenantId: "my-app",
   });
   ```
3. Run `recomputeUser()` for each existing user to backfill effective tables:
   ```typescript
   for (const user of users) {
     await authz.recomputeUser(ctx, String(user._id));
   }
   ```
4. If you access component functions directly, they no longer exist as public
   exports. Use the Authz client methods instead.
5. Update `hasRelation`/`addRelation`/`removeRelation` calls from positional
   args to structured objects:
   ```typescript
   // Before
   await authz.hasRelation(ctx, "user", userId, "member", "team", teamId);
   // After
   await authz.hasRelation(ctx, { type: "user", id: userId }, "member", {
     type: "team",
     id: teamId,
   });
   ```

### Performance

Benchmarked on real Convex backend with 10,000 users:

| Operation                          | Median latency |
| ---------------------------------- | -------------- |
| `can()` (permission check)         | **1ms**        |
| `checkAllPermissions()` (11 perms) | **1ms**        |
| `assignRole()`                     | 48-68ms        |
| `revokeRole()`                     | 49ms           |
| `grantPermission()`                | 36-39ms        |
| `denyPermission()`                 | 37ms           |

Read latency is constant regardless of data size (O(1) indexed lookups).

---

## 0.1.7

- Role inheritance and composition: Roles support `inherits` (single parent) and
  `includes` (multiple roles) with cycle detection
- Permission definition merging: `definePermissions()` and `defineRoles()`
  accept multiple objects
- Coverage reporting with `@vitest/coverage-v8`
- Improved type safety with `ReadonlyArray` in role definitions

## 0.1.4

- Real-world scenario tests (Google Drive, Food Delivery, multi-org)
- Example UI with shadcn/ui components, sidebar navigation, dashboard
- Seed script with demo data
- Permission Tester and Users & Roles management pages
