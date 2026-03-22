# Changelog

## Unreleased

- **BREAKING: Tenant-level data isolation**: All tables now include a required `tenantId` field. All indexes have been replaced with tenant-prefixed versions (`tenantId` as the first column). This is a breaking schema change.

- **BREAKING: tenantId required in constructors**: The `Authz` and `IndexedAuthz` constructors now require a `tenantId: string` option. Single-tenant apps should pass any constant string (e.g. `"my-app"`). Multi-tenant apps should pass their tenant/organization identifier.

- **BREAKING: All component function args require tenantId**: Every mutation, query, indexed function, and ReBAC function now requires `tenantId: v.string()` as the first argument. Cleanup/cron mutations (`cleanupExpired`, `runScheduledCleanup`, `runAuditRetentionCleanup`) accept it as optional for global cleanup.

- **BREAKING: Index names changed**: All database indexes renamed from `by_user`, `by_role`, etc. to `by_tenant_user`, `by_tenant_role`, etc.

- **New: `withTenant()` fluent API**: Both `Authz` and `IndexedAuthz` now have a `withTenant(tenantId)` method that returns a new instance scoped to a different tenant, for rare cross-tenant admin operations.

- Extracted shared `scopeValidator` constant into `src/component/validators.ts`; removed ~30 inline duplicates.

### Migration guide

1. Add `tenantId` to your constructor:
   ```typescript
   // Before
   const authz = new Authz(components.authz, { permissions, roles });
   // After
   const authz = new Authz(components.authz, { permissions, roles, tenantId: "my-app" });
   ```
2. If you call component functions directly, add `tenantId` to every call.
3. Existing data must be migrated: all rows need a `tenantId` value. Run a one-time migration or redeploy with fresh data.

- **Role inheritance and composition**: Roles can be defined with optional `inherits` (single parent) and/or `includes` (multiple roles). Effective permissions are the union of inherited/included and direct permissions. Resolved at client build time with cycle and unknown-role validation. The keys `inherits` and `includes` are reserved in role definitions. Existing permission-only role definitions are unchanged.

## 0.1.7

- Update version to 0.1.4 in package-lock.json
- Refactor permission definitions in index.ts to support merging multiple
  permission and role objects, enhancing type safety and flexibility. Update
  query in convex_rules.mdc to use indexed filtering for improved performance.
- Update package dependencies in package.json and package-lock.json to include
  new libraries for improved functionality and testing. Added
  @vitest/coverage-v8 for coverage reporting, @radix-ui/react-slot for
  slot-based composition, and updated existing dependencies for better
  compatibility.
- Enhance Vitest configuration for coverage reporting and expand tests for
  permission and role definitions. Added coverage settings to vitest.config.js
  and introduced new test cases for merging permissions and roles in
  index.test.ts, along with additional context handling in helpers.test.ts and
  ReBAC tests. Improved indexed authorization tests to cover role updates and
  scoped permissions.
- Refactor role definition types in index.ts to use ReadonlyArray for improved
  immutability and update roles casting for better type safety in
  buildRolePermissionsMap method.
- Update version to 0.1.5 in package.json and package-lock.json for release.

## 0.1.4

- Add comprehensive real-world scenario tests (Google Drive, Food Delivery,
  multi-org)
- Improve example UI with shadcn/ui components, sidebar navigation, and
  dashboard
- Add seed script with demo data (users, orgs, documents, roles)
- Add Permission Tester and Users & Roles management pages
- Move UI dependencies to devDependencies
- Fix linting issues and remove dead code
- Improve scoped permission examples
