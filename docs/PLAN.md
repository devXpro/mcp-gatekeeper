# MCP Gatekeeper — plan, step 1: extract the harness from Family Hub

This plan is for the orchestrator (the main Claude session) and the subagents it launches. Every card in §6 is
self-contained once §2–§5 are read.

## 0. How to use this plan

- Read §1–§5, then your card in §6. Work only inside your card's "Owns".
- The source of every card is Family Hub, a private repo (checked out next to this one as `family-hub`)
  (read-only for every card except G9). Its plan is `family-hub/docs/PLAN.md`; its rules (§5.2 HTTP surface, §5.5
  OAuth rules, §5.6 gateway rules, §5.11 security rules) still hold unless this plan says otherwise.
- Progress goes to `docs/progress/<ID>.md`, test notes to `docs/testing/<ID>.md`, security notes to
  `docs/security/<ID>.md`.

## 1. Goal and non-goals

MCP Gatekeeper is the shared front door of two applications by the same owner:
- **Family Hub** (server, private): families, modules in containers, MongoDB, Gin/Zap/Fx, live on
  its own domain.
- **Homie** (home, public): one household, local plugins, SQLite.

The gatekeeper holds what both need: passkey sign-in and sessions, step-up, setup links, invites, people and
accounts, an OAuth 2.1 authorization server for MCP connectors (ChatGPT, Claude), consent, grants and revocation, the
access check in front of an MCP endpoint, the audit log, HTTP security plumbing, the admin unix socket, the Cloudflare
Tunnel setup, and the admin web UI as a package.

**Step 1 (this plan):** move that code out of Family Hub into this repo and switch Family Hub to it **with no change
anyone outside can see**. Homie adopts the gatekeeper in a later step, after the owner checks Family Hub.

Non-goals of step 1: new features (guests, quick tunnels, the cloudflared supervisor and the single-resource home
come with Homie), a Homie integration, a data migration, any change to Family Hub's modules.

## 2. Locked decisions (the owner, 2026-11-24)

| Topic | Decision |
|---|---|
| Repo | `devXpro/mcp-gatekeeper`, **public**, MIT. Module `github.com/devXpro/mcp-gatekeeper`. |
| Source | Extracted **from Family Hub** (newer, reviewed, proven live with ChatGPT). Homie's own auth is replaced later. |
| Stack | Go 1.26 (toolchain go1.26.11). Plain `net/http` (Go 1.22 mux patterns) and `log/slog`. No Gin, Zap, Fx or caarlos0/env in the gatekeeper. Family Hub keeps them and plugs the gatekeeper in through thin adapters. |
| Storage | Shared interfaces (`store`), two adapters (`store/mongostore`, `store/sqlitestore`), **one** conformance suite (`store/storetest`) both must pass. An application picks the adapter at build time by importing it. |
| UI | The admin web UI's shared part is a package in this repo (`ui/`, source TSX), consumed by a git tag/commit — no npm registry. |
| Versions | Tags `v0.x.y`. The orchestrator bumps both applications and merges (the owner steers only). |
| Order | Extract → switch Family Hub → all tests and the full rehearsal green → deploy on the server → the owner checks via Claude (and ChatGPT) that everything works as before → only then Homie. |
| Agents | Up to 8 in parallel; Opus for security-critical work and UI, Sonnet for well-scoped work (§7). |

## 3. Map: Family Hub → gatekeeper

| Family Hub today | Goes to | Stays in Family Hub |
|---|---|---|
| `internal/core` (types, store and service interfaces) | `core`, `store` (frozen, §4.1) | `Module`, `AccountModule`, `LegacyKey`, `ModuleStore`, `LegacyKeyStore`, `ModuleRegistry`, `ModuleCaller`, `Signer`, `Deployer` |
| `internal/store` (MongoDB) | `store/mongostore` + `store/storetest` | the module and legacy-key collections (they join the gatekeeper's transactions and cascades) |
| `internal/auth` | `auth` | — |
| `internal/adminsock` | `adminsock` | Family Hub's own admin commands |
| `internal/oauth` | `oauth` (modules become resources: `core.ResourceCatalog`, `core.ResourcePaths`) | the `ResourceCatalog` over its module registry |
| `internal/gateway` | `mcpguard`: the token check, 401 + `resource_metadata`, header policy, limits, streaming | the module proxy, identity JWT minting (`mint.go`), `caller.go`, the legacy REST door |
| `internal/people`, generic parts of `internal/admin` | `people`: accounts, members, invites, connections, audit API | module endpoints, deploy, allowlist, jobs |
| `internal/httpx` | `httpsec`: security headers, request log, trusted-peer address rules, recovery | the Gin engine and the Zap glue |
| `internal/web` | `webui`: the SPA handler (the app embeds its own built SPA) | its `dist` and route list |
| `cmd/hub/cloudflare` | `tunnel/cloudflare` | the `hub admin cloudflare connect` command wiring |
| `web/src` shared parts | `ui/` package | the superadmin's modules/deploy screens and app routes |
| `internal/identity`, `internal/deployer*`, `internal/modules`, `pkg/contract`, `pkg/conformance`, `cmd/hubctl`, `examples/` | — | all of it |

## 4. Contracts

### 4.1 Frozen files

The orchestrator wrote these; they are the source of truth. Never edit them; put a change request in your report:
- `core/core.go`, `core/services.go`;
- `store/store.go`;
- `httpsec/errors.go`;
- `internal/testlog/testlog.go` (shared test helper; add nothing to it, ask instead).

Rules that go with them:
- Times are UTC. IDs come from `core.NewID(prefix)`.
- Stores return `core.ErrNotFound`, `ErrConflict`, `ErrExpired` or `ErrUsed`, wrapped with `%w`.
- Secrets, tokens, codes and invite tokens are stored only as sha256.
- Transactions travel in the context (`store.Store.Tx`).

### 4.2 Compatibility with the live Family Hub (MUST)

Family Hub runs live with real people, passkeys, sessions and ChatGPT connectors. After the switch nobody may
notice:
1. **MongoDB:** the same collection names, document field names (the `bson` tags of the doc structs, e.g. grants keep
   `module_id`), `_id` forms, indexes (names, keys, options, TTLs) and semantics. No migration. Old documents read
   back unchanged; new documents look exactly like the old code's.
2. **Cookies and headers:** names, attributes and lifetimes come from `core.Brand`; Family Hub passes its current
   values (`__Host-fh_session`, `__Host-fh_txn`, `X-Family-Hub`, product "Family Hub"). Signed-in people stay
   signed in.
3. **URLs:** every route keeps its path, method and status codes (Family Hub plan §5.2).
4. **OAuth:** metadata documents, registration (CIMD and DCR, including the ChatGPT `none` quirk of commit
   `a0acd6e`), authorize, consent, token, refresh rotation and revoke behave byte-for-byte the same toward ChatGPT and
   Claude. Issued tokens and grants keep working.
5. **MCP:** the 401 with `WWW-Authenticate: Bearer resource_metadata="…"`, the header policy (including the MCP
   2026-07-28 routing headers `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*` of commit `b0fc38b`), limits and streaming are
   unchanged.
6. **Audit:** the same action names, targets and detail keys.
7. **The JSON error form** `{"error":"<code>","message":"…"}` and its codes (`httpsec/errors.go`).

The JSON between the admin SPA and its API may change (both ship in one build): e.g. the consent API's `module`
becomes `resource`. Keep such renames few and list them in your report.

### 4.3 Package API conventions

- Every package has an `Options` struct and a constructor `New(o Options) (*T, error)` that validates it; no global
  state; nil `*slog.Logger` means discard.
- HTTP packages implement `core.RouteRegistrar` on a `*http.ServeMux` and export their middlewares as
  `func(http.Handler) http.Handler`.
- Everything takes a `core.Clock` for time and a `core.Site` for URLs and origins.
- No package imports Gin, Zap, Fx or caarlos0/env. No package reads environment variables.

### 4.4 HTTP security rules (from Family Hub §5.2 and §5.11)

- Every mutating `/api/*` call needs the header `Brand.CSRFHeader: 1`, `Origin` equal to the public URL when the
  browser sends it, and `Sec-Fetch-Site: same-origin` when sent.
- Step-up is required where Family Hub requires it (invites, removing a member, deleting a passkey, account create
  and delete, …).
- Pages: a strict CSP without inline script, HSTS, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`. Cookies
  `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict` (the consent binding cookie keeps Family Hub's attributes).
- The request log drops query strings on `/oauth/*` and never logs `Authorization` or cookies. No secrets, tokens,
  codes or application data in logs, audit details or errors. Secrets compare in constant time.

### 4.5 The UI package

- Root `package.json`: `@devxpro/mcp-gatekeeper-ui`, sources in `ui/src` (TSX, not built), an `exports` map, React 19,
  Tailwind 4 and the other runtime libraries as `peerDependencies` at Family Hub's versions.
- Applications depend on it as `github:devXpro/mcp-gatekeeper#<tag or commit>`, compile it with their own Vite, and
  add `@source` for it in their Tailwind CSS.
- It provides the design system and the shared screens (sign-in, setup, join, consent, connect, account and people,
  passkeys, audit, the shell with slots for an application's own tabs and routes), RU/EN strings an app can extend,
  and a small API client that sends `Brand.CSRFHeader`.

## 5. Rules for every agent

1. **Language.** Code, comments and docs in English; UI strings in Russian and English. Match the source's style and
   comment density. Moved code keeps its comments and its tests.
2. **Go.** Go 1.26 (toolchain go1.26.11; the go command fetches it). `golangci-lint` v2.12.2 in `~/go/bin` must be
   clean with `.golangci.yml`. `go test -race` must be green. Read library sources in the Go module cache
   instead of guessing APIs.
3. **Dependencies.** `go.mod` already lists every module (`internal/deps`): go-webauthn, descope/virtualwebauthn,
   testify, mongo-driver v2, golang.org/x/sys, modernc.org/sqlite. Never add one; if you truly need one, stop and
   report. Never run `go mod tidy`.
4. **Frontend.** Node 22+ and npm, only for card G8 (`package.json`, `ui/`).
5. **Tool hygiene on this Mac.** Absolute paths, `git -C`, `go -C`, `make -C`, `npm --prefix`. Never `cd X && …`. No
   `rm -rf` of computed paths. No Perl. Python only as `python3` inside a venv. Downloaded files go in their own empty
   directory.
6. **Ownership.** Edit only your card's "Owns". Frozen files are off limits. Family Hub is read-only (except G9).
7. **A shared tree.** Other agents edit this repo at the same time:
   - never reformat or rewrite files outside your paths; no `gofmt -w ./...`;
   - no git command that changes the tree or the index (checkout, stash, reset, clean, add, commit) — the
     orchestrator commits;
   - lint and test only your packages: `make -C <repo> lint test
     PKGS=./<pkg>/...`.
8. **No live actions:** no commits, pushes, GitHub or ssh actions; no Cloudflare, ChatGPT or Claude calls (use
   fixtures); Docker only in tests tagged `integration`; **never** the browser tools `mcp__playwright__*` or
   `mcp__paseo__browser_*` (they drive the owner's real browser profile — browser tests use the project's own npm
   Playwright with its own Chromium).
9. **Tests are part of the task.** Port the source's tests with the code (Gin test contexts become `httptest`; Zap
   observers become `internal/testlog`). Fakes over mocks, table tests, no sleeps where a channel or deadline will
   do. Docker tests carry the build tag `integration`.
10. **Report**, in this order: a summary in three sentences; files created or changed; how you verified it (exact
    commands and results); deviations from this plan and why; change requests for frozen files; JSON or behavior
    differences from Family Hub (must be none outside §4.2's allowance); open issues; what G9 needs to know to wire
    your package into Family Hub.

## 6. Cards

#### G1 — store conformance suite and MongoDB adapter · Opus / high
**Owns:** `store/storetest/**`, `store/mongostore/**`.
**Source:** Family Hub `internal/store` (everything except the module and legacy-key parts) and its tests.
1. **Write `storetest` first** and note in `docs/progress/G1.md` the moment it compiles (G2 waits for it): `func
   Run(t *testing.T, open func(t *testing.T) store.Store, cascade *Recorder)` (or similar) testing every method of
   `store.Store`, including atomicity (`Consume`, `UseRefresh`, `ConsumeCode` under concurrency), cascades
   (`store.Cascade` called inside the transaction; an error rolls everything back), `Tx` commit, rollback and nesting,
   paging and ordering of audit, expiry rules. Port Family Hub's store tests into it.
2. `mongostore`: the Family Hub code moved, with §4.2.1 compatibility: the same collections, doc structs, `bson` tags,
   indexes and TTLs. Transactions through the session carried in the context; a nested `Tx` joins the outer one.
   Options take either a URI and database name or an existing `*mongo.Database` (Family Hub shares its client),
   plus `[]store.Cascade`. Export what Family Hub needs to put its own collections in the same transaction and to
   create its own indexes.
3. A compatibility test: documents in the exact shape Family Hub writes today (fixtures in testdata) read back
   correctly, and documents the adapter writes match them field for field.
4. Integration tests against a throwaway `mongo:8.0` single-node replica set (as Family Hub's tests do), tag
   `integration`.

#### G2 — SQLite adapter · Sonnet / high
**Owns:** `store/sqlitestore/**`. Starts when `storetest` compiles (G1 says so in its progress file).
- modernc.org/sqlite, WAL, foreign keys on, a busy timeout; schema versioning with migrations in code.
- Transactions in the context; `Conn(ctx)` returns the current transaction or the database, so an application's own
  tables join (Homie's plugin tables later). Nested `Tx` joins the outer one. `store.Cascade` support.
- Atomic `Consume`, `UseRefresh`, `ConsumeCode` (conditional UPDATE … RETURNING or equivalent).
- Audit IDs sort by time like the Mongo adapter's.
- Passes `storetest` with `go test -race` (no Docker).

#### G3 — passkeys, sessions and the admin socket · Opus / high
**Owns:** `auth/**`, `adminsock/**`.
**Source:** Family Hub `internal/auth`, `internal/adminsock`.
- `net/http` on Family Hub's paths (`/api/auth/*`, `/api/me`, `/api/me/passkeys*`, `/api/me/sessions/revoke`),
  implementing `core.Sessions` and `core.RouteRegistrar`. Names from `core.Brand`; TTLs, rate limits, error answers,
  cookie attributes and audit as today.
- `adminsock`: the unix-socket server and client with peer credentials (darwin, linux), and a command registry any
  application can add to. `auth` registers its own commands (setup link and friends) through it.
- All tests ported (virtual authenticator).

#### G4 — OAuth authorization server · Opus / max
**Owns:** `oauth/**`.
**Source:** Family Hub `internal/oauth`.
- `net/http` on Family Hub's paths (`/.well-known/*`, `/oauth/*`, `/api/oauth/txn/*`). Modules become resources:
  `core.ResourceCatalog` replaces the module registry and the manifest; `core.ResourcePaths` builds and parses MCP
  paths (Family Hub will pass `core.PerResource{Prefix: "/mcp/"}`). The binding cookie name from
  `Brand.TxnCookie`. Implements `core.TokenValidator`.
- Every behavior of §4.2.4, every fix Family Hub carries (CIMD `none`, consent-phishing binding, the consent step-up
  option), all tests ported.
- The consent transaction JSON may say `resource` instead of `module`; tell G8 and G9 exactly what changed.

#### G5 — HTTP plumbing, the SPA handler and Cloudflare Tunnel setup · Sonnet / high
**Owns:** `httpsec/**` (except the frozen `errors.go`), `webui/**`, `tunnel/**`.
**Source:** Family Hub `internal/httpx`, `internal/web`, `cmd/hub/cloudflare`.
- `httpsec`: security headers (CSP given by the application), no-store, recovery, the request log of §4.4 on slog,
  and the trusted-peer rule (delete `CF-Connecting-IP` and `X-Forwarded-For` from peers outside a trusted network).
- `webui`: the SPA handler (an `fs.FS` from the application, fallback routes, CSP and cache headers, ETag) as today.
- `tunnel/cloudflare`: the connect flow as a library (login link → tunnel → DNS route → config → the account
  certificate deleted), options instead of Family Hub's config.
- Tests ported.

#### G6 — the MCP access check · Opus / high
**Owns:** `mcpguard/**`.
**Source:** the generic parts of Family Hub `internal/gateway` (`gateway.go` token check, `respond.go`, `limits.go`,
`sse.go`, the header policy of `forward.go`). Not `mint.go`, `module.go`, `caller.go` or the legacy door.
- A middleware that finds the resource of the path (`core.ResourcePaths`), checks the bearer token
  (`core.TokenValidator`), answers 401 with the exact `WWW-Authenticate` of today, and puts `core.AccessInfo` in the
  context.
- Helpers the application's MCP handler or proxy uses: the request/response header policy (strip `Authorization`,
  cookies, hop-by-hop; pass the MCP session and routing headers), body limits, streaming that flushes server-sent
  events, JSON-RPC error answers.
- Tests ported.

#### G7 — accounts, people, invites, connections and audit API · Opus / high
**Owns:** `people/**`.
**Source:** Family Hub `internal/people` and the generic parts of `internal/admin` (`account.go`, `superadmin.go`
accounts part, `respond.go`, `ratelimit.go`, `actorname/`).
- The service and the `net/http` handlers on Family Hub's paths: `/api/account` (get, delete everything),
  `/api/account/invites*`, `/api/account/members/*`, `/api/account/connections*`, `/api/account/audit`, and the
  superadmin's `/api/admin/accounts*` and `/api/admin/audit`.
- Extension points: an application adds fields to `GET /api/account` (Family Hub: its modules) and erases its own
  data before an account is deleted (Family Hub: every module erases the account). Rules as today (step-up, members
  see only their own audit entries, …).
- Tests ported.

#### G8 — the admin UI package · Opus / high
**Owns:** `package.json`, `package-lock.json`, `tsconfig*.json`, `eslint.config.js`, `vitest.config.ts`, `ui/**`.
**Source:** Family Hub `web/` (React 19, Vite, Tailwind 4, shadcn/ui, motion), which copied Homie's design 1:1.
- The package of §4.5 with the shared components and screens; Family Hub's own superadmin screens stay there.
- JSON field names matching G4 and G7 (ask them through your report if unclear; check their packages when done).
- Unit tests (Vitest) moved; `npm run typecheck`, `lint`, `test` pass at the repo root.
- `ui/README.md`: how an application consumes the package (git dependency, Tailwind `@source`, the provider with the
  brand and the extra routes).

#### G9 — Family Hub on the gatekeeper · Opus / max — wave 2
**Owns:** `family-hub/**`. Live actions: none (the orchestrator commits and deploys).
- Replace the moved packages with the gatekeeper: thin adapters (`net/http` handlers mounted in Gin, gatekeeper
  middlewares as Gin middlewares, Zap → slog through `go.uber.org/zap/exp/zapslog` or Zap's own slog bridge, Fx
  modules wrapping the constructors), `core.Brand` with today's names, `core.PerResource{Prefix: "/mcp/"}`, a
  `ResourceCatalog` over the module registry, Family Hub's own module and legacy-key collections on the gatekeeper's
  `mongostore` (same transactions, `store.Cascade`), the SPA on the UI package by git commit.
- The go.mod requires a pushed gatekeeper commit; a local `go.work` is allowed but never committed.
- Acceptance: every Family Hub test (unit, integration, web unit and Playwright smoke), the full rehearsal
  `FH_E2E_REHEARSAL=1`, and CI green; §4.2 holds (no migration, same cookies, paths and OAuth behavior); screenshots of
  the SPA compared before/after with no visible difference.

#### G.R — parity and security review · Opus / high — wave 3
Compare the old and new Family Hub: the HTTP surface, OAuth flows, MCP gate, Mongo documents and indexes, cookies,
audit. Then a security review of the gatekeeper. Findings in `docs/reviews/G.R.md`; fixes become cards.

## 7. Waves

| Wave | Cards | Needs |
|---|---|---|
| 0 | frozen contracts, repo (orchestrator) | — |
| 1 | G1, G3, G4, G5, G6, G7, G8 in parallel; G2 once `storetest` compiles | wave 0 |
| 2 | G9 | wave 1 merged and pushed |
| 3 | G.R → fixes → deploy on the server (orchestrator) → the owner checks via Claude and ChatGPT | wave 2 |

Models: G1, G3, G6, G7, G8, G.R Opus high; G4, G9 Opus max; G2, G5 Sonnet high.

## 8. Orchestrator-only actions

Commits and pushes, tags, `go mod tidy`, merging change requests into frozen files, anything on the server (the deploy
keeps the previous hub image for an instant rollback), GitHub settings, and talking to the owner.
