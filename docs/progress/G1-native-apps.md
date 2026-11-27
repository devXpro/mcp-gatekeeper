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
