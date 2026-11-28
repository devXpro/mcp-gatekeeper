# MCP Gatekeeper

The front door for self-hosted MCP servers: people sign in with passkeys, connect ChatGPT and Claude as MCP
connectors through a built-in OAuth 2.1 authorization server, and the owner revokes access per person or per
connection.

Extracted from [Family Hub](docs/PLAN.md) and shared with [Homie](https://github.com/devXpro/homie). See the
[changelog](CHANGELOG.md) for what each version added.

- **Go** (`net/http`, `log/slog`): passkeys and sessions (`auth`), the OAuth server and consent (`oauth`), the
  access check in front of an MCP endpoint (`mcpguard`), accounts, people and invites (`people`), HTTP security
  (`httpsec`), the admin unix socket (`adminsock`), the SPA handler (`webui`), Cloudflare Tunnel setup and the
  cloudflared supervisor (`tunnel/cloudflare`).
- **Storage:** interfaces in `store`, adapters for MongoDB (`store/mongostore`) and SQLite (`store/sqlitestore`),
  one conformance suite (`store/storetest`).
- **Admin UI:** a React package in `ui/`, consumed by a git tag (see [ui/README.md](ui/README.md)).

Current version: **v0.2.0**.

## Native apps (unreleased)

An application can let its own programs connect from the person's computer, next to ChatGPT and Claude, with a
loopback redirect (RFC 8252). Without a declared app nothing changes, byte for byte.

```go
oauth.New(oauth.Options{ /* ... */ NativeApps: []oauth.NativeApp{{ID: "desk", Name: "Desk", Ports: []int{8742}}}})
```

- The app registers by DCR as a public client: `redirect_uris` exactly `["http://127.0.0.1/oauth/callback"]` (or
  `http://[::1]/oauth/callback`; never `localhost`, never a port), `software_id` its `ID`,
  `token_endpoint_auth_method` `none`, and a `client_name` such as the computer's name.
- It authorizes with `redirect_uri` `http://127.0.0.1:<port>/oauth/callback` and PKCE S256, then exchanges the
  code with the same `redirect_uri`. Any port, or one of `Ports` when the app declares them. Tokens, refresh and the
  resource are as for everyone.
- Its client's `core.Assistant` is `app:<ID>` (`oauth.NativeAppID` reads it back): `AccessInfo.Assistant`, grants and
  the audit carry it, and the application maps it to its own label.
- The consent screen calls it "Desk on your computer" with the client's name in the App row and the loopback address
  next to Allow. It skips the "not opened from the assistant" warning only when the app opened the system browser
  itself (`Sec-Fetch-Site: none`, no `Referer`: `started_from` is `app`); a link from a web page warns.
- Refresh, for every client: a refresh token spent within the last 60 seconds that its own client presents again
  gets the same new tokens again (a lost answer no longer revokes the connection); later, it is reuse as before.

The rules in full are in [docs/security/G4.md](docs/security/G4.md#clients).

## What v0.2 adds

Everything below is optional. An application that does not use it gets the v0.1 behaviour, byte for byte.

### Access terms and application permissions

A person can have an end date and a list of application-defined permissions.

- `core.Person.AccessUntil` ends the person's access at that instant (nil means no end). `Person.Active(now)` is
  `DisabledAt == nil && (AccessUntil == nil || now.Before(*AccessUntil))`, and every check below uses it.
- `core.Person.Permissions` is a list of opaque ids that the application defines (for example `all` or
  `plugin:tv`). The gatekeeper stores them and checks them against the application's `core.PermissionCatalog`; it
  never interprets them. `core.PermissionAll` (`"all"`) means everything the application offers, now and later. The
  application enforces permissions itself, usually by reading `mcpguard.PersonFrom(ctx).Permissions` in its MCP
  handler.
- An invite carries the same two fields and copies them to the person who redeems it, in the same transaction.
- Where a term is enforced:

  | Place | An ended term means |
  |---|---|
  | session (`auth`) | the session is refused and deleted; sign-in answers 403 `access_ended` after the passkey verified |
  | consent (`oauth`) | 401 `no_session`, nothing is written |
  | code exchange and refresh (`oauth`) | `invalid_grant`, nothing is spent or revoked |
  | access tokens (`oauth`) | a token ends at `AccessUntil` when that comes before its hour; `expires_in` says so |
  | every MCP call (`mcpguard`) | 401 `invalid_token`, the same bytes as a disabled person |

  A term never revokes a grant: when the owner extends it, the connection works again.
- `people` gets the HTTP side when `people.Options.Permissions` (a catalog) is set and the inviter implements
  `people.AccessInviter` (`auth.(*Auth).IssueInviteWithAccess`):
  - `POST /api/account/invites` takes optional `access_until` (RFC 3339, in the future, at most one year away) and
    `permissions`;
  - `PATCH /api/account/members/{id}` changes a member's term and permissions (owner only; a step-up is required when
    the change **widens** access: a later end, no end, or more permissions). Ending access now is
    `{"access_until": <now>}`; extending an ended term is a widening `PATCH`;
  - `GET /api/account/permissions` returns the catalog for pickers;
  - member and invite listings carry `access_until`, `permissions` and `active`. An expired person stays listed until
    the owner removes them. Someone who is not an owner sees these fields on their own row only.
  - Without a catalog, `access_until` and `permissions` are refused (400), never ignored.
- The invite sheet, the term presets and the member detail (end now, extend, change, remove) are in the UI package.

### Co-owners

With `people.Options.CoOwners` the superadmin can invite another **owner** into their own existing account
(`POST /api/account/invites` with `role: "owner"`). Redeeming it creates a `RoleOwner` person in that account: no new
account, not a superadmin, and `account_name` is ignored. Owner invites never carry a term or permissions; an owner
counts as having every permission.

Owners manage members: they can change or remove members and revoke members' connections. Everything that targets an
owner or the superadmin (change, remove, revoke their grant, withdraw an owner invite, delete an account that holds
another owner) is the superadmin's alone and answers 403 `forbidden` to anyone else. Nobody can change their own
access, and a superadmin can neither get a term nor be removed. Without `CoOwners`, `role` is refused.

### Single-account applications

`people.Options.SingleAccount` makes `POST` and `DELETE /api/admin/accounts` answer 404 and lists only the viewer's own
account on `GET /api/admin/accounts`. The UI package hides the families tab with `configure({ singleAccount: true })`.
For such an application, `core.SingleResource{At: "/mcp", ID: "..."}` serves one MCP URL for the whole account.

### The MCP gate

- `mcpguard.Guard.MiddlewareFor(id)`: the application states the resource, and a path that `Paths.FromPath` maps
  elsewhere is a 404. Plain `Middleware` trusts the application to route on the same uncleaned `r.URL.Path`; use
  `MiddlewareFor` when in doubt. `MiddlewareFor` panics at wiring time when the paths cannot serve the id.
- `mcpguard.PersonFrom(ctx)` next to `AccessFrom(ctx)`: the guard has loaded the person anyway.
- `Options.InFlightPerResource` (default 16), `Options.InFlightKey` (`PerAccount`, the default, or `PerPerson`) and
  `Options.FailuresPerAddress` (default 30). Under `PerPerson`, admit every door with `Guard.AdmitAccess`.
- A valid token of a person who is gone, disabled or past their term is refused with the usual 401 bytes but is not
  charged to the per-address failure bucket (an assistant provider's address is shared by every connector).
- `ReadBody` and `httpsec.BodyLimit` give the client 30 seconds to send a request body (408 on a `ReadBody` timeout).

### Client address and the site

- `core.Site.Validate()` is called by `auth.New`, `oauth.New`, `mcpguard.New` and `people.New`. It requires an https
  public URL with a host and nothing else (plain http only for `localhost` or a loopback IP), an RP ID that is the host
  or a parent domain of it, and one of the three client address modes. An empty or unknown mode is refused.
- `httpsec.LoopbackPeers()` is the trusted network `127.0.0.0/8, ::1/128` for `httpsec.PeerGuard`, for a connector on
  the same machine. Pair `ClientIPCloudflare` with a `PeerGuard` that trusts only the connector, and bind the listener
  to loopback. Choose a stable RP ID before the first passkey: a parent domain lets every origin under it ask for the
  passkeys.
- `httpsec.MountClean` is an opt-in middleware that answers 404 for an unclean path (dot or empty segments, an escaped
  `/`).
- `core.Brand` has two optional nouns, `ResourceNoun` (default `"module"`) and `AppNoun` (default `"hub"`), read through
  `Brand.ResourceWord()` and `Brand.AppWord()`. The texts that assistants and people read use them.

### Cloudflare: the quick tunnel and the supervisor

`tunnel/cloudflare` keeps the `Connector` (login link, tunnel, DNS, `config.yml`, certificate deleted). v0.2 adds:

- `Connector.Start(ctx, ConnectOptions, progress)`: the same flow in the background for a web page or a CLI. It reports
  `Step{Name, LoginURL, Done, Err}` and surfaces the login link as soon as cloudflared prints it. `ErrDNSRecordExists`
  is returned (for `errors.Is`) when cloudflared refuses to replace an existing record.
- `Supervisor`: runs one cloudflared child and keeps it up, with restarts on a 1 s to 60 s backoff.
  - **Named** mode runs the tunnel the `Connector` made. **Quick** mode runs a quick tunnel (no account, no domain)
    and reads its random `*.trycloudflare.com` host from cloudflared's metrics endpoint; `OnURL` fires whenever it
    appears or changes.
  - The child gets a private empty `HOME` inside the tunnel directory, a minimal environment (`HOME` and `PATH`), and
    no secret in its arguments: named mode reads a credentials file, quick mode needs none.
  - `Status()` reports `starting`, `probing`, `connected`, `failing` or `stopped`, with the URL, the time and the last
    error. An optional `Probe` checks the public URL end to end before the state becomes `connected`.
  - Quick tunnels are for trying: the host changes at every start, there is no uptime promise and no Server-Sent
    Events, and `trycloudflare.com` is on the Public Suffix List, so every new host needs new passkeys.

### Stores

- Both adapters store `access_until` and `permissions` on people and invites and implement `PersonStore.SetAccess`.
  MongoDB gets two `omitempty` fields (no migration, no index change); `sqlitestore` gets migration v2.
- `store.Purger`: an optional interface for adapters without TTL indexes. `sqlitestore.Purge(now)` deletes expired
  tokens and codes, invites 7 days after they expire, audit entries older than 400 days and DCR clients without a
  grant. `auth`'s hourly sweep calls it when the store has it. `mongostore` keeps its TTL indexes.
- `sqlitestore.Open` makes the file, its `-wal` and `-shm` `0600` and the directory `0700` (tightening looser modes and
  warning), seeds the audit counter from `MAX(id)`, and runs with `synchronous=FULL`.

### Admin socket and sign-in

- `auth.(*Auth).IssueSetupLink` and `IssueSetupLinkTTL` for in-process callers (the same rule as the socket command:
  refused while an enabled superadmin has a usable passkey), and `SuperadminCanSignIn`.
- The socket's only proof is the peer's uid. `admin.setup-link` and `admin.reset-access` now record the peer's pid and
  executable path in the audit and the log, and `auth.Options.OnAccessReset` lets an application alert its owner.

### UI package

`configure({ singleAccount, coOwners })` and the `GatekeeperApp` props `usePermissions` (the catalog) and `live`
(`'sse'` or `'poll'`, for an application's own data hooks behind a tunnel without SSE). With a catalog the invite sheet
asks what a person may use and for how long, and the member detail shows the term and the connections. Without it the
screens are what they were. See [ui/README.md](ui/README.md).

## Development

```sh
make lint test          # Go lint and unit tests
make integration        # tests that need Docker (MongoDB)
make ui                 # the UI package: typecheck, lint, unit tests
make vuln               # govulncheck
```

Notes on each package's security model and tests are in [docs/security](docs/security) and [docs/testing](docs/testing);
the v0.2 changes are in [docs/security/v0.2.md](docs/security/v0.2.md) and
[docs/testing/v0.2.md](docs/testing/v0.2.md). [docs/PLAN.md](docs/PLAN.md) is the historical plan of the extraction.

## License

[MIT](LICENSE)
