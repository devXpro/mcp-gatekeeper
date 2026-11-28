# Native apps (RFC 8252 loopback redirect) — progress

The card is called G1 in its plan; `docs/progress/G1.md` already belongs to the store conformance card of the
first build, so this note has its own name instead of replacing it.

Status: **done**, on branch `native-apps`, not tagged (the release tag is made by whoever releases).

- [x] `oauth.Options.NativeApps []oauth.NativeApp{ID, Name}`, checked by `New` (ID pattern, no repeats, a visible
  name of at most 64 characters)
- [x] DCR: `redirect_uris` only `http://127.0.0.1/oauth/callback` / `http://[::1]/oauth/callback`, `software_id` a
  declared ID, `token_endpoint_auth_method` `none`; the answer carries `software_id`
- [x] authorize: the loopback callback with any port, scheme, host and path exact; PKCE S256 as for everyone
- [x] assistant kind `app:<ID>` (`oauth.AppAssistantPrefix`, `oauth.NativeAppID`)
- [x] consent view `app: {id, name}`, `started_from: "app"`; the UI package's consent screen names the app
- [x] tests: `oauth/native_test.go`, positive and negative, and byte parity for ChatGPT and Claude
- [x] README, docs/security/G4.md, CHANGELOG `[Unreleased]`
- [x] gofmt, go vet, golangci-lint (0 issues), `go test -race ./...` green

## Decisions

- **Where the field lives.** The contract says "`oauth.Config` / Site field". The package has no `Config`; its
  configuration is `oauth.Options`, so the field is `Options.NativeApps`. `core` is frozen (its package comment), so
  `NativeApp` is `oauth.NativeApp` and nothing in `core` changed: `core.Assistant` simply holds `app:<ID>`.
- **Registration is strict.** Only the two port-less loopback URIs, up to 10 of them without repeats (so in practice
  one or both). A URI with a port at registration is refused; RFC 8252 lets the server ignore the port at authorize,
  which is what happens.
- **Assistant callbacks are checked first.** A ChatGPT or Claude registration that sends a `software_id` is an
  assistant's, exactly as in v0.2.0. A set that mixes a loopback and an assistant callback is refused.
- **Without native apps declared**, a loopback registration gets v0.2.0's error bytes. With some declared, the
  refusal of a bad callback set names the loopback callback too (a different `error_description`; same code).
- **`client_name`** goes through the same cleaning as every DCR name; an empty one becomes the app's `Name`.
- **`started_from` is `app`** for a native app's transaction. The red "not opened from the assistant" warning would
  fire on every native connection (a system browser has no `Referer` and sends `Sec-Fetch-Site: none`), and the
  phishing it guards against does not work here: the code can only go to a loopback address of the computer the
  consent is given on, and only the PKCE verifier of whoever started the request redeems it. To be checked by the
  security review card.
- **An app removed from `NativeApps`**: its clients are refused at authorize (`pageBadRedirect`); existing grants and
  tokens keep working until revoked, like `RefuseConnectorCallback`.
- **UI.** `returnable` replaces the https-only check of approve's redirect: http on `127.0.0.1` / `[::1]` is allowed
  only when the transaction has `app`. Titles use `consent.native` ("{{app}} on your computer"); the App row keeps
  `client_name`; the footnote is `consent.only_yours.native`. EN and RU added.

## Open points

- The UI package's typecheck, lint and vitest were **not run**: the worktree has no `node_modules`, and installing
  them needs the network, which this card had to stay off. The change is small (types, one helper, three strings),
  but `make ui` must run before the release.
- No UI unit test was added for the native consent screen, for the same reason.
- An application that embeds the UI package must rebuild its SPA to pick up the native consent screen; the server
  side alone leaves an old screen refusing the http redirect ("no redirect").
- The people/admin connection lists show a native client with `assistant` `app:<ID>` and its `client_name`;
  `assistantName` falls back to `client_name`, so they read fine, but there is no app-specific wording or icon yet
  (the application's admin card owns that).

## Security-review fixes (card GF: review SR M1 and L5)

Status: **done**, on branch `native-apps`, not tagged.

- [x] M1: `started_from` is `app` only for a request with exactly one `Sec-Fetch-Site: none` and no `Referer`; any
  other native request (cross-site, same-site, same-origin, no header, a Referer) is `elsewhere` and warns
  (`TestNativeStartedFrom`, `TestNativeConsentPhishing`)
- [x] M1: `NativeApp.Ports []int`, optional; when set the loopback redirect must use one of them (a port-less redirect
  counts as 80); `New` refuses 0, over 65535 and repeats (`TestNativeAppPorts`, `TestNewRefusesBadNativeApps`)
- [x] M1: the consent screen says "Returns to 127.0.0.1:<port> on this computer" next to Allow for a native app
  (`consent.native.return`, EN and RU), Allow is described by it; component tests in
  `ui/src/features/consent/consent.test.tsx`
- [x] L5: the 60 s refresh grace for every client (`TestRefreshGrace`, `TestRotatedTokens`, `TestRefreshRace` now
  expects every concurrent refresh to get the same answer); the conformance group `RefreshGrace` runs on SQLite and on
  MongoDB (Docker, tag `integration`)
- [x] CHANGELOG `[Unreleased]` (Added and Changed), docs/security/G4.md, README
- [x] gofmt, go vet, golangci-lint (0 issues, also with `--build-tags integration` on `./store/...`),
  `go test -race ./...`, the Mongo conformance under `-tags integration`; `npm run typecheck && npm run lint &&
  npm test` (78 tests)

### Decisions

- **`Sec-Fetch-Site: none` strictly**, as the plan's decision says, not the review's wider variant (also accept a
  cross-site navigation without Referer when the port is declared). An app that opens the authorize URL by
  navigating its own loopback admin page therefore gets the red warning; it should hand the URL to the system browser
  instead (`open`), which sends `none`. A missing header is `elsewhere` too.
- **The grace needs no new store method.** To answer the same tokens again while keeping only hashes, the tokens of a
  refresh are HMAC-SHA256 keyed with the spent refresh token; the grace recomputes them, checks the new refresh token
  (same grant and family, unused, unrevoked, unexpired) and the access token (live), and answers them with what is
  left of `expires_in`. What the stores must guarantee is in the conformance group `RefreshGrace`: the first
  `UsedAt` stays (so the window cannot be stretched by replays), and a concurrent loser of `UseRefresh` inside `Tx`
  already sees the winner's new token (SQLite serializes write transactions; MongoDB retries the loser after the
  write conflict).
- **What counts as "untouched".** Once the new refresh token was used (the client moved on) or revoked, the spent
  one coming back is reuse even inside the minute. The grant, resource and person checks run for a replay as for a
  refresh; a replay writes nothing, is logged at info and not audited.
- **The grace applies to every client**, ChatGPT and Claude included: the only bytes that change are the answers in
  that minute, which were `invalid_grant` plus a revoked family before.

### Open points

- The review's own residual of M1 stays: a link sent in a messenger and opened from there also reads as `app`. With
  `Ports` declared, only the app's port can receive the code; the application should declare its port (the desk:
  8742).
