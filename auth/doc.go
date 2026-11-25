// Package auth signs people in with passkeys and keeps their browser sessions: setup links, invites, step-up and the
// passkey list. It is Family Hub's internal/auth (Family Hub docs/PLAN.md §2 "Login", §5.9 "Auth", card T1.2, the
// fixes of T2.F2) on plain net/http, log/slog and the gatekeeper's store.
//
// # Passkeys
//
// WebAuthn runs through github.com/go-webauthn/webauthn. The relying party ID and the only origin come from
// core.Site, its display name from core.Brand.Product. Every ceremony asks for a discoverable credential and user
// verification (Face ID, Touch ID) and no attestation. The WebAuthn user handle is the person id. A begin answers
// {"options": …}, the options JSON the browser takes (PublicKeyCredentialCreationOptionsJSON or
// PublicKeyCredentialRequestOptionsJSON); a finish sends {"credential": …}, the browser's answer unchanged, and the
// server finds the pending ceremony again by the challenge inside it. A ceremony lives in memory for 5 minutes and is
// finished at most once, by the endpoint of its own kind and, for step-up and a new passkey, by the session that began
// it. A signature counter that goes backwards is refused.
//
// # Sessions
//
// A sign-in or a registration creates a core.Session and sets the cookie Brand.SessionCookie (Family Hub:
// __Host-fh_session; Path=/; Secure; HttpOnly; SameSite=Strict) to 32 random bytes; only their sha256 is stored. A
// session ends 12 hours after its last request or 7 days after sign-in; LastSeenAt is written at most once a minute,
// and an hourly sweep deletes dead sessions. Signing in counts as step-up; a step-up assertion is fresh for 5 minutes.
// Deleting a passkey and POST /api/me/sessions/revoke ("sign out on other devices", step-up) end every session of the
// person in one transaction and give the current browser a new session and cookie with the old one's sign-in time,
// absolute end and step-up.
//
// # Access terms
//
// A person who is not core.Person.Active (disabled, or past core.Person.AccessUntil, a guest's term) is out: Viewer
// refuses their session and deletes it, and a sign-in with their passkey is refused with 403 access_ended
// (CodeAccessEnded) "your access has ended" (a disabled person's fails like a passkey that did not verify). A member
// invite may carry a term and the application's permissions (IssueInviteWithAccess); registering with it copies both
// to the new person in the transaction that uses the invite, and an invite whose term has ended reads as a dead link.
//
// # What applications and the other packages use
//
//	auth.New(auth.Options{…})            *Auth: core.Sessions and core.RouteRegistrar; Start and Stop run the sweeps
//	a.RegisterRoutes(mux)                the routes below, on Go 1.22 patterns
//	a.RequireViewer, a.RequireStepUp     core.Sessions: 401 no_session, 403 step_up_required; RequireViewer also
//	                                     applies the CSRF checks to mutating methods (403 forbidden)
//	a.Viewer(r)                          the signed-in person, or core.ErrNoSession
//	a.SameOrigin                         the CSRF checks alone, for routes without a session
//	a.IssueInvite(ctx, kind, acc, name, by), a.IssueInviteIn(ctx, st, …)
//	                                     owner and member invites: {ID, URL with #t=, ExpiresAt}, 24 hours
//	a.IssueInviteWithAccess(ctx, kind, acc, name, by, until, perms)
//	                                     a member invite with a term and permissions for the person
//	a.IssueSetupLink(ctx)                the setup-link command for a caller in the process (a first-run page)
//	a.IssueSetupLinkTTL(ctx, ttl)        the same with a shorter life (≤ 15 minutes)
//	a.SuperadminCanSignIn(ctx)           whether an enabled superadmin has a passkey of this site (no setup link then)
//	a.ClearSessionCookie(w)              drops the cookie (after the application ended the session itself)
//	a.AdminCommands()                    setup-link and reset-access; Options.Admin registers them on a socket
//	Options.OnAccessReset                the application hears of every reset-access (an alert for its owner)
//	auth.NormalizeName(v)                the name rule (1–40 characters, no controls, quotes, backslashes, backticks)
//
// # Setup links and invites
//
// Tokens are 32 random bytes, stored as sha256, carried in the URL fragment: <public URL>/setup#t=… (15 minutes) and
// <public URL>/join#t=… (24 hours). Each works once; a new setup link revokes the older ones. The setup-link admin
// command makes one only while no enabled superadmin has a passkey: with no superadmin, registering creates the first
// account (named by account_name) and its owner with the superadmin flag; after reset-access, which wipes the
// superadmin's passkeys and sessions, revokes their OAuth grants, runs the application's ResetSteps (Family Hub:
// deletes their legacy keys) and revokes the open invites they made, it adds a new passkey to the same superadmin.
// IssueSetupLink makes the same link under the same rule for a caller inside the process, IssueSetupLinkTTL a shorter
// one, and SuperadminCanSignIn answers that rule's question.
//
// An owner invite to an account without an owner makes its owner, who may rename the account (account_name); one to
// an account that has an owner makes a co-owner (core.RoleOwner, not superadmin), who joins it as it is named. Who
// may invite whom is package people's rule.
//
// # Limits and checks
//
// Every mutating call needs Brand.CSRFHeader: 1 (Family Hub: X-Family-Hub), and an Origin and a Sec-Fetch-Site, when
// the browser sends them, of the public URL and same-origin. Rate limits have separate buckets per class: auth/token
// and registration per client address (20 a minute); sign-in per client address, counting begins (30) and failed
// finishes (10); step-up and a new passkey per session the same way. No bucket is shared by all clients (T2.R H2).
// The client address is core.ClientIP; IPv6 counts per /64.
//
// # Audit and logs
//
// Audit actions: auth.register, auth.join, auth.login, auth.login.fail (a system entry), auth.stepup,
// auth.stepup.fail, auth.logout, auth.sessions.revoke, auth.passkey.add, auth.passkey.rename, auth.passkey.delete,
// admin.setup-link and admin.reset-access. auth.login.fail is coalesced: at most one entry per address group (an IPv4
// address or an IPv6 /64, which is also its IP) a minute, with detail count = the failures since the group's
// previous entry. admin.setup-link and admin.reset-access name the admin socket's peer (detail peer_pid and
// peer_exe, when the socket knew them, and peer_chain, who started it, when known; review GK-5); an in-process setup
// link has detail via=in-process. Tokens, cookies, links, challenges and credentials never reach a log or an audit
// entry; a failed ceremony logs only the name of the check that failed.
//
// The hourly sweep also purges what has expired from a store that cannot expire rows by itself (store.Purger, e.g.
// sqlitestore; review GK-3). Texts that name the application use core.Brand.AppWord ("hub" by default, review
// GK-18).
//
// # Routes
//
//	POST   /api/auth/token              public: what a setup link or invite is
//	POST   /api/auth/register/begin     public: a passkey for a setup link or invite
//	POST   /api/auth/register/finish    public: creates the person (and the first account) and signs in
//	POST   /api/auth/login/begin        public
//	POST   /api/auth/login/finish       public: signs in
//	POST   /api/auth/stepup/begin       session
//	POST   /api/auth/stepup/finish      session
//	POST   /api/auth/logout             204, with or without a session
//	GET    /api/me                      session
//	GET    /api/me/passkeys             session
//	POST   /api/me/passkeys/begin       session + step-up
//	POST   /api/me/passkeys/finish      session + step-up
//	PATCH  /api/me/passkeys/{id}        session
//	DELETE /api/me/passkeys/{id}        session + step-up; never the last passkey; ends the other sessions
//	POST   /api/me/sessions/revoke      session + step-up: sign out on other devices; 204 with a new cookie
package auth
