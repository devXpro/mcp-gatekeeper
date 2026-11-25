# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project follows [Semantic Versioning](https://semver.org/) (while it is below 1.0, a minor version may change an
API).

## [0.2.0] - 2026-11-25

Everything new is optional: with the default options, the answers toward assistants, the cookies, the routes, the
audit names, the Mongo collections and the MCP 401/403 bytes are those of v0.1.0.

### Added

- **Access terms and application permissions.** `core.Person.AccessUntil` and `Person.Permissions`, the same on
  `core.Invite` (copied to the person when the invite is redeemed, in one transaction), `Person.Active(now)`,
  `core.PermissionAll`, `core.PermissionCatalog` and `core.PermissionInfo`, and `store.PersonStore.SetAccess`. A term is
  enforced by the session, the sign-in, the OAuth consent, the code exchange, the refresh and every MCP call. Access
  tokens end no later than the term. A term never revokes a grant, so extending it resumes the connection.
- **`people`:** the `access_until` and `permissions` fields on invites; `PATCH /api/account/members/{id}` (owner only,
  step-up when the change widens access, audited as `account.member.update`); `GET /api/account/permissions`;
  `access_until`, `permissions` and `active` in member listings; `people.AccessInviter`; `Options.Permissions`.
- **Co-owners.** `people.Options.CoOwners`: the superadmin invites another owner into an existing account, and redeeming
  the invite creates a second `RoleOwner` person there (`POST /api/auth/token` answers `co_owner: true`). Only the
  superadmin changes or removes an owner.
- **Single-account applications.** `people.Options.SingleAccount` (account creation and deletion answer 404).
- **`mcpguard`:** `Guard.MiddlewareFor(id)` (GK-1); `Guard.AdmitAccess` and the options `InFlightPerResource`,
  `InFlightKey` (`PerAccount` or `PerPerson`) and `FailuresPerAddress` (GK-4); a one-time warning when a header mode
  sees a refused request without the client address header.
- **`httpsec`:** `LoopbackPeers()` (GK-2), `BodyDeadline` and `BodyReadTimeout` (GK-17), `MountClean` (GK-19).
- **`core`:** `Site.Validate()` (GK-2), and the optional `Brand.ResourceNoun` and `Brand.AppNoun` with
  `ResourceWord()` and `AppWord()` (GK-18).
- **`tunnel/cloudflare`:** `Connector.Start` (the connect flow in the background, reporting `Step`s and surfacing the
  login link), `Supervisor` (one cloudflared child, named or quick tunnel, private `HOME`, minimal environment, no
  secret in arguments, restart backoff, `Status`, `Probe`, `OnURL`), and `ErrDNSRecordExists`.
- **`auth`:** `IssueSetupLink`, `IssueSetupLinkTTL`, `IssueInviteWithAccess`, `SuperadminCanSignIn`, the
  `access_ended` sign-in code (403), `Options.OnAccessReset` and the peer's pid, executable path and ancestry
  (`peer_chain`: up to three parent processes, so a CLI run shows who started it) in the audit details of
  `admin.setup-link` and `admin.reset-access` (GK-5). `adminsock.Invocation.Peer` carries the peer, `Peer.Chain` its
  ancestry.
- **Stores:** migration v2 of `sqlitestore` (the two new columns and an audit index), `store.Purger` and
  `sqlitestore.Purge` (GK-3); `mongostore` gets `omitempty` fields. The conformance suite covers terms, permissions and
  retention.
- **UI package:** the invite pickers (what a person may use, term presets), the member detail (revoke a connection, end
  access now, change, remove), expired people greyed with «Продлить», the co-owner invite and join, a clear message for
  an ended term, `configure({ singleAccount, coOwners, accountDelete })`, and the `usePermissions`, `live`,
  `indexRoute`, `Overlay` and `useInvitesDisabled` props; tabs for owners only (`TabDef.owner`, `TabDef.visible`);
  `ApiError.details` keeps an error body's extra keys; the `/api/me` error screen shows the error's words; sign-in
  without a usable `next` lands on `/`, where the shell's index route decides.
- Documentation: security and testing notes for the v0.2 changes.

### Changed

- `auth.New`, `oauth.New`, `mcpguard.New` and `people.New` fail on a `core.Site` that does not pass `Site.Validate()`
  (GK-2). An empty or unknown client-address mode, a public URL with a path, a trailing slash, an empty query or
  fragment, or a port without a host, plain http on a public host, and an RP ID that is not the host or a parent domain
  of it are refused.
- A person past their term or disabled is refused at consent, code exchange and refresh with `invalid_grant` or 401
  `no_session`; before, only the MCP call refused them (GK-13).
- `oauth`: a scope-only authorize round-trips through `Paths` (with `core.SingleResource`, `mcp:<other>` is
  `invalid_scope`) (GK-7); `ValidateAccess` returns an error that is both `core.ErrInvalidToken` and `core.ErrExpired`
  for a known ended token, so the guard does not charge it to the address (GK-12). The 401 bytes are unchanged.
- `mcpguard` and `httpsec`: a request body must arrive within 30 seconds (GK-17).
- `sqlitestore`: the file, `-wal` and `-shm` are `0600` (GK-8). The directory must be the database's own: `Open`
  tightens it to `0700` when it created it, or when it belongs to the process and holds only the database's files, and
  otherwise refuses with an error that says so (a shared directory is never chmodded). The audit counter is seeded from
  `MAX(id)` (GK-9); `synchronous=FULL` (GK-11).
- `tunnel/cloudflare`: a quick tunnel's host is read only from the child's own output; the metrics port only confirms
  it, so another process on that port cannot redirect the application. The generated `config.yml` quotes the
  credentials path, so a data dir with `: ` or ` #` in its path works.
- The hourly sweep of `auth` calls `store.Purger` when the store has it.

### Security

Review items closed in this version: GK-1, GK-2, GK-3, GK-4, GK-5 (documented boundary, audit of the peer and an alert
hook), GK-7, GK-8, GK-9, GK-11, GK-12, GK-13, GK-17, GK-18, GK-19. GK-14 (choose a stable RP ID before the first
passkey) and GK-16 are documentation. See [docs/security/v0.2.md](docs/security/v0.2.md).

## [0.1.0] - 2026-11-24

The extraction: the front door of an existing multi-module deployment, made into a library that other applications can
use.

### Added

- `auth`: passkey sign-in, sessions and step-up, setup links and invites, the admin socket commands `setup-link` and
  `reset-access`.
- `oauth`: an OAuth 2.1 authorization server for ChatGPT and Claude connectors (client ID metadata documents and
  dynamic client registration, consent, grants, refresh rotation with reuse detection, revocation).
- `mcpguard`: the access check in front of MCP endpoints, with limits and event-stream relaying.
- `people`: accounts, members, invites, connections and the audit.
- `httpsec`: the request chain, trusted peers, security headers, body limits.
- `adminsock`: the admin unix socket with a command registry.
- `webui`: the SPA handler.
- `tunnel/cloudflare`: Cloudflare Tunnel setup with the cloudflared CLI.
- `store` with MongoDB (`mongostore`) and SQLite (`sqlitestore`) adapters and one conformance suite (`storetest`).
- `ui/`: the admin UI package.
- Single-resource and per-resource MCP layouts (`core.SingleResource`, `core.PerResource`).

[0.2.0]: https://github.com/devXpro/mcp-gatekeeper/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/devXpro/mcp-gatekeeper/releases/tag/v0.1.0
