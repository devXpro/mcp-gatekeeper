# Native apps: private-use URI scheme redirects (RFC 8252 §7.1) — progress

`docs/progress/G2.md` belongs to the SQLite store card of the first build, so this note has its own name.

Status: **done**, on branch `native-schemes` from v0.3.0, not tagged (the release is made by whoever releases).

- [x] `oauth.NativeApp.Schemes []string`, checked by `New`: lowercase reverse-DNS with at least one dot, at most 128
  characters, no repeats in one app or across apps
- [x] DCR: `<scheme>:/oauth/callback` of the app's own schemes, next to loopback callbacks; same `software_id`,
  `none`, PKCE S256 rules
- [x] authorize: exact match, only while the scheme is still declared; `Ports` do not apply to it; `started_from`
  unchanged
- [x] consent view `app.scheme` for a scheme redirect (`redirect_host` empty)
- [x] UI package: "<Name> on your device", "Returns to the <Name> app on this device" (EN, RU), `<scheme>:` in the
  Returns to row; approve navigates to that scheme's callback only, for a native app only
- [x] tests: `oauth/schemes_test.go` (positive and negative), `TestAssistantsUnchangedByNativeApps` also with a scheme
  declared; `ui/src/lib/consent.test.ts` (`returnable`), `ui/src/features/consent/consent.test.tsx`
- [x] README, docs/security/G4.md, CHANGELOG `[Unreleased]`
- [x] gofmt, go vet, golangci-lint (0 issues), `go test -race ./...`; `npm ci`, typecheck, lint, vitest green

## Decisions

- **Exact string, not a parsed URL.** `schemeCallback` cuts at the first `:` and wants exactly `/oauth/callback`
  after it, so `scheme://…`, `scheme:///…`, a query, a fragment, an escape or capitals never pass, and registration and
  authorize compare the same bytes.
- **Error order.** A scheme nobody declares is refused with the redirect URIs (`invalid_redirect_uri`) before
  `software_id` is read; a scheme of another app than `software_id`'s is `invalid_redirect_uri` after it.
- **Refusal wording.** Without native apps: v0.2.0's. With apps but no scheme: v0.3.0's. With a scheme declared, it
  also names `scheme:/oauth/callback` (no angle brackets: Go's JSON escapes them).
- **Mixing.** One client may hold loopback and scheme callbacks together; nothing requires separate registrations.
- **Title on the consent screen.** Besides the return line the task asked for, a scheme redirect also changes the
  title from "<Name> on your computer" to "<Name> on your device" (`consent.native.device`): a phone app being called
  "on your computer" right where the person decides reads like a mismatch. The Returns to row shows `<scheme>:`
  instead of an empty host.
- **`returnable` moved** from `ConsentPage.tsx` to `lib/consent.ts` (exported) so it has unit tests; the scheme check
  is that very scheme, no host, the `/oauth/callback` path and no `//`.

## Open points

- An application embedding the UI package must rebuild its SPA; an old SPA refuses the scheme redirect ("no
  redirect") as it did loopback ones before v0.3.0.
