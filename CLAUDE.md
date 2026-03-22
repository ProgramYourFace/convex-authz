# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Package

`@djpanda/convex-authz` — a Convex component providing RBAC/ABAC/ReBAC authorization with O(1) indexed lookups (inspired by Google Zanzibar). Published as a Convex component via `defineComponent("authz")`.

## Commands

```bash
npm test                 # Run vitest (run mode + type checking)
npm run test:watch       # Vitest in watch mode
npm run build            # Compile via tsconfig.build.json → dist/
npm run build:clean      # Remove dist + tsbuildinfo, full codegen rebuild
npm run build:codegen    # Generate Convex component code + rebuild
npm run lint             # ESLint on all files
npm run typecheck        # tsc --noEmit across src, example, and example/convex
npm run dev              # Parallel: convex dev + vite (example app) + build watcher
```

Run a single test file: `npx vitest run src/component/queries.test.ts`
Run a single test by name: `npx vitest run -t "test name pattern"`
Debug tests: `npm run test:debug` (enables Node inspector, no file parallelism).

## Architecture

### Dual-Layer Design

The core architectural pattern is **source tables + pre-computed indexed tables**:

- **Source tables** (`roleAssignments`, `userAttributes`, `permissionOverrides`, `relationships`, `auditLog`) store ground-truth authorization data.
- **Indexed tables** (`effectivePermissions`, `effectiveRoles`, `effectiveRelationships`) store denormalized, pre-computed results for O(1) lookups.

On writes, the indexed layer computes all resulting permissions/roles/relationships and stores them. On reads, it does a direct index lookup on `[userId, permission, scopeKey]`.

### Two Client Classes

Both expose the same API but use different component function paths:

| | **Authz** (standard) | **IndexedAuthz** (O(1)) |
|---|---|---|
| Reads | `component.queries.*` — evaluates on the fly from source tables | `component.indexed.*Fast` — direct index lookup on effective tables |
| Writes | `component.mutations.*` — writes only to source tables | `component.indexed.*WithCompute` — writes + pre-computes effective tables |

### Three Authorization Models

| Model | Tables | Component file |
|---|---|---|
| **RBAC** — role → permissions mapping with inheritance/composition | `roleAssignments`, `effectiveRoles` | `mutations.ts`, `queries.ts` |
| **ABAC** — attribute-based policies with sync/async conditions | `userAttributes` | `mutations.ts`, `queries.ts` + policy evaluation in `client/index.ts` |
| **ReBAC** — relationship tuples with transitive traversal | `relationships`, `effectiveRelationships` | `rebac.ts` |

### Scope System

Scope (`{ type: string; id: string }`) enables resource-level permissions. A role/permission can be global (no scope) or scoped to a resource (e.g., `{ type: "team", id: "team_123" }`). Indexed tables use `scopeKey` field: `"global"` or `"type:id"`.

### Key File Map

- `src/component/schema.ts` — 8 tables with all indexes
- `src/component/mutations.ts` — 16 mutations (source table writes + audit logging)
- `src/component/queries.ts` — 10 queries (on-the-fly permission evaluation)
- `src/component/indexed.ts` — 15 functions (O(1) reads + compute-on-write mutations)
- `src/component/rebac.ts` — 8 functions (relationship tuples + traversal)
- `src/component/helpers.ts` — `matchesPermissionPattern`, scope matching, policy context
- `src/client/index.ts` — `Authz`, `IndexedAuthz` classes + `definePermissions`, `defineRoles`, `definePolicies` helpers
- `src/client/validation.ts` — input validation for client methods
- `src/react/index.ts` — `AuthzProvider`, `useCanUser`, `useUserRoles`, `PermissionGate`

### Package Exports

- `.` → `dist/client/index.js` (Authz/IndexedAuthz classes, define* helpers)
- `./react` → `dist/react/index.js` (React hooks/components)
- `./convex.config` → `dist/component/convex.config.js` (component registration)

### Type-Safe Permission/Role Definitions

`definePermissions()` and `defineRoles(permissions, ...)` use generics so that role definitions are type-checked against declared permissions. Roles support `inherits` (single parent) and `includes` (multiple roles) with cycle detection via `flattenRolePermissions()`.

### Wildcard Permissions

Permission strings support patterns: `"*"` (all), `"resource:*"` (all actions on resource), `"*:action"` (action on all resources). Matching happens in `matchesPermissionPattern()`.

## Test Pattern

Tests use `convex-test`:

```typescript
import { convexTest } from "convex-test";
import schema from "./schema.js";
import { api } from "./_generated/api.js";

const t = convexTest(schema, import.meta.glob("./**/*.ts"));
await t.mutation(api.mutations.assignRole, { userId, role, ... });
const result = await t.query(api.queries.hasRole, { userId, role, ... });
```

Each test gets a fresh database. Test files: `authz.test.ts`, `queries.test.ts`, `indexed.test.ts`, `rebac.test.ts`, `scenarios.test.ts`, `helpers.test.ts`, `client/index.test.ts`, `react/index.test.ts`.

## Convex Conventions (from .cursor/rules)

- Always use new function syntax: `export const f = query({ args: {}, returns: v.null(), handler: ... })`
- Always include `args` and `returns` validators on all functions
- Use `v.null()` (not undefined) for functions that don't return a value
- Use `withIndex()` for queries — never use `.filter()`
- Index names must include all fields: `by_field1_and_field2`
- Use `internalQuery`/`internalMutation`/`internalAction` for private functions
- Convex queries don't support `.delete()` — collect results and delete individually
- `v.bigint()` is deprecated — use `v.int64()`

## Code Style

- Prettier: trailing commas (`"all"`), prose wrap (`"always"`)
- ESLint: flat config (v9), TypeScript strict, no floating promises, unused vars prefixed with `_`
- Import `.js` extensions for local imports (ESM)
