package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/adminsock"
	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// access is what an invite gives: a term and permissions.
type access struct {
	until *time.Time
	perms []string
}

// memberInvite issues a member invite for Борис to the superadmin's account with access a and returns its token.
func (e *env) memberInvite(admin signedIn, a access) string {
	e.t.Helper()
	inv, err := e.a.IssueInviteWithAccess(context.Background(), core.InviteMember, core.AccountID(admin.Account.ID),
		"Борис", core.PersonID(admin.Person.ID), a.until, a.perms)
	require.NoError(e.t, err)
	token := tokenOf(e.t, inv.URL, testOrigin+"/join#t=")
	e.secret(token)
	return token
}

func (e *env) person(id string) core.Person {
	e.t.Helper()
	p, err := e.st.People().Get(context.Background(), core.PersonID(id))
	require.NoError(e.t, err)
	return p
}

// A member invite's term and permissions become the person's, in the transaction that uses the invite.
func TestInviteAccessIsCopied(t *testing.T) {
	e := newEnv(t)
	_, admin := e.superadmin(newDevice())
	until := e.clock.Now().Add(30 * 24 * time.Hour)
	token := e.memberInvite(admin, access{until: &until, perms: []string{"plugin:tv", "plugin:lamp"}})
	stored, ok := e.st.Invites().(fakeInvites).get(hashToken(token))
	require.True(t, ok)
	require.NotNil(t, stored.AccessUntil)
	assert.True(t, until.Equal(*stored.AccessUntil))
	assert.Equal(t, []string{"plugin:tv", "plugin:lamp"}, stored.Permissions)

	// A failure after the invite was used rolls everything back: no person, and the invite still works.
	b := e.browser()
	e.st.setFail("Sessions.Create", assert.AnError)
	wantError(t, b.register(newDevice(), token, "", ""), http.StatusInternalServerError, "internal")
	e.st.setFail("Sessions.Create", nil)
	people, err := e.st.People().ListByAccount(context.Background(), core.AccountID(admin.Account.ID))
	require.NoError(t, err)
	assert.Len(t, people, 1, "only the superadmin")

	rec := b.register(newDevice(), token, "", "")
	wantStatus(t, rec, http.StatusOK)
	got := decodeAs[signedIn](t, rec)
	assert.Equal(t, personBody{ID: got.Person.ID, Name: "Борис", Role: "member"}, got.Person)
	p := e.person(got.Person.ID)
	require.NotNil(t, p.AccessUntil)
	assert.True(t, until.Equal(*p.AccessUntil))
	assert.Equal(t, []string{"plugin:tv", "plugin:lamp"}, p.Permissions)
	used, _ := e.st.Invites().(fakeInvites).get(hashToken(token))
	assert.NotNil(t, used.UsedAt)

	// Without access, nothing is set: Family Hub's invites.
	plain := e.invited(newDevice(), core.InviteMember, core.AccountID(admin.Account.ID), "Карл", core.PersonID(admin.Person.ID))
	v := decodeAs[meBody](t, plain.do(http.MethodGet, "/api/me", nil))
	p = e.person(v.Person.ID)
	assert.Nil(t, p.AccessUntil)
	assert.Nil(t, p.Permissions)
}

func TestIssueInviteWithAccessRefusals(t *testing.T) {
	e := newEnv(t)
	_, admin := e.superadmin(newDevice())
	ctx := context.Background()
	acc, by := core.AccountID(admin.Account.ID), core.PersonID(admin.Person.ID)
	past, future := e.clock.Now(), e.clock.Now().Add(time.Hour)
	for name, tc := range map[string]struct {
		kind   core.InviteKind
		access access
	}{
		"an owner with a term":        {core.InviteOwner, access{until: &future}},
		"an owner with permissions":   {core.InviteOwner, access{perms: []string{"all"}}},
		"a term that has ended":       {core.InviteMember, access{until: &past}},
		"a setup link":                {core.InviteSetup, access{}},
		"a member of no account kind": {"guest", access{}},
	} {
		_, err := e.a.IssueInviteWithAccess(ctx, tc.kind, acc, "Борис", by, tc.access.until, tc.access.perms)
		require.Error(t, err, name)
	}
	_, err := e.a.IssueInviteWithAccess(ctx, core.InviteOwner, acc, "Борис", by, nil, []string{})
	require.NoError(t, err, "an empty list is no permissions")
}

// Two browsers finish a registration with the same invite at once: one person is made, the other gets the dead-link
// answer, and the invite is used.
func TestConcurrentRedeem(t *testing.T) {
	e := newEnv(t)
	_, admin := e.superadmin(newDevice())
	until := e.clock.Now().Add(time.Hour)
	token := e.memberInvite(admin, access{until: &until, perms: []string{"plugin:tv"}})
	type attempt struct {
		b    *browser
		body map[string]any
	}
	var tries []attempt
	for range 2 {
		b, d := e.browser(), newDevice()
		opts := b.begin("/api/auth/register/begin", map[string]string{"token": token})
		tries = append(tries, attempt{b, map[string]any{"credential": d.create(t, opts)}})
	}
	codes := make([]int, len(tries))
	var wg sync.WaitGroup
	for i, a := range tries {
		wg.Go(func() { codes[i] = a.b.do(http.MethodPost, "/api/auth/register/finish", a.body).Code })
	}
	wg.Wait()
	assert.ElementsMatch(t, []int{http.StatusOK, http.StatusNotFound}, codes)
	people, err := e.st.People().ListByAccount(context.Background(), core.AccountID(admin.Account.ID))
	require.NoError(t, err)
	require.Len(t, people, 2, "the superadmin and one guest")
	_, err = e.st.Invites().Consume(context.Background(), hashToken(token), e.clock.Now())
	require.ErrorIs(t, err, core.ErrUsed)
}

// A guest whose term ended is out: the session is refused and deleted, sign-in says why, and extending the term lets
// them sign in again.
func TestTermEndsTheSession(t *testing.T) {
	e := newEnv(t)
	_, admin := e.superadmin(newDevice())
	until := e.clock.Now().Add(time.Hour)
	phone := newDevice()
	b := e.browser()
	wantStatus(t, b.register(phone, e.memberInvite(admin, access{until: &until}), "", ""), http.StatusOK)
	guest := decodeAs[meBody](t, b.do(http.MethodGet, "/api/me", nil)).Person.ID
	require.NotEmpty(t, guest)
	sessionsOf := func() int {
		n := 0
		for _, s := range e.st.Sessions().(fakeSessions).all() {
			if s.PersonID == core.PersonID(guest) {
				n++
			}
		}
		return n
	}
	require.Equal(t, 1, sessionsOf())

	e.clock.Add(time.Hour - time.Millisecond)
	wantStatus(t, b.do(http.MethodGet, "/api/me", nil), http.StatusOK)
	e.clock.Add(time.Millisecond)
	wantError(t, b.do(http.MethodGet, "/api/me", nil), http.StatusUnauthorized, "no_session")
	assert.Zero(t, sessionsOf(), "the session is dropped")

	// Sign-in verifies the passkey, then refuses with the reason and opens no session.
	// Its own code, not the CSRF refusal's forbidden: the UI tests code === "access_ended".
	rec := e.browser().login(phone)
	wantStatus(t, rec, http.StatusForbidden)
	assert.Equal(t, `{"error":"access_ended","message":"your access has ended; ask the owner to extend it"}`,
		rec.Body.String())
	assert.Equal(t, "access_ended", CodeAccessEnded)
	assert.Empty(t, rec.Result().Cookies(), "no session cookie")
	assert.Zero(t, sessionsOf())
	assert.NotContains(t, e.actions(), "auth.login.fail", "not a failed sign-in")

	later := e.clock.Now().Add(24 * time.Hour)
	require.NoError(t, e.st.People().SetAccess(context.Background(), core.PersonID(guest), &later, nil))
	wantStatus(t, e.browser().login(phone), http.StatusOK)
}

// An invite whose term ends before it is used makes nobody: the link reads as dead, at the token, at the begin, and
// at the finish when the term ends during the ceremony.
func TestInviteTermEndedBeforeUse(t *testing.T) {
	e := newEnv(t)
	_, admin := e.superadmin(newDevice())
	until := e.clock.Now().Add(2 * time.Minute)
	token := e.memberInvite(admin, access{until: &until})
	b := e.browser()
	wantStatus(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token}), http.StatusOK)
	opts := b.begin("/api/auth/register/begin", map[string]string{"token": token})
	e.clock.Add(3 * time.Minute)
	wantError(t, b.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": newDevice().create(t, opts)}),
		http.StatusNotFound, "not_found")
	inv, _ := e.st.Invites().(fakeInvites).get(hashToken(token))
	assert.Nil(t, inv.UsedAt, "rolled back")
	wantError(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token}), http.StatusNotFound, "not_found")
	wantError(t, b.do(http.MethodPost, "/api/auth/register/begin", map[string]string{"token": token}),
		http.StatusNotFound, "not_found")
}

// The superadmin invites an owner into their own account (§4.4, co-owners): the second owner joins it as it is, with
// no new account and no superadmin flag, and the account keeps its name.
func TestCoOwnerInvite(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner, admin := e.superadmin(newDevice())
	inv, err := e.a.IssueInvite(ctx, core.InviteOwner, core.AccountID(admin.Account.ID), "Борис", core.PersonID(admin.Person.ID))
	require.NoError(t, err)
	token := tokenOf(t, inv.URL, testOrigin+"/join#t=")
	e.secret(token)
	b := e.browser()
	rec := b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token})
	wantStatus(t, rec, http.StatusOK)
	assert.Equal(t, `{"kind":"owner","name":"Борис","account_name":"Семья","co_owner":true}`, rec.Body.String(),
		"the join page knows not to ask for the account's name")

	// The name sent anyway is ignored: the account keeps its own.
	rec = b.register(newDevice(), token, "", "Другое имя")
	wantStatus(t, rec, http.StatusOK)
	got := decodeAs[signedIn](t, rec)
	assert.Equal(t, personBody{ID: got.Person.ID, Name: "Борис", Role: "owner"}, got.Person)
	assert.Equal(t, admin.Account, got.Account, "the same account, under its own name")
	accounts, err := e.st.Accounts().List(ctx)
	require.NoError(t, err)
	require.Len(t, accounts, 1, "no new account")
	assert.Equal(t, "Семья", accounts[0].Name, "not renamed in the store")
	people, err := e.st.People().ListByAccount(ctx, core.AccountID(admin.Account.ID))
	require.NoError(t, err)
	require.Len(t, people, 2)
	for _, p := range people {
		assert.Equal(t, core.RoleOwner, p.Role)
		assert.Equal(t, p.ID == core.PersonID(admin.Person.ID), p.Superadmin)
		assert.Nil(t, p.AccessUntil)
	}
	assert.Equal(t, "auth.join", e.lastAudit().Action)
	wantStatus(t, owner.do(http.MethodGet, "/api/me", nil), http.StatusOK) // the first owner stays signed in

	// An owner invite to an account without an owner yet (one the superadmin just made: the only kind Family Hub
	// issues) has no co_owner, byte for byte as before, and still names the account.
	fresh := core.Account{ID: "acc_freshfreshfresh", Name: "Новая", CreatedAt: e.clock.Now()}
	require.NoError(t, e.st.Accounts().Create(ctx, fresh))
	inv, err = e.a.IssueInvite(ctx, core.InviteOwner, fresh.ID, "Карл", core.PersonID(admin.Person.ID))
	require.NoError(t, err)
	token = tokenOf(t, inv.URL, testOrigin+"/join#t=")
	e.secret(token)
	b = e.browser()
	rec = b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token})
	wantStatus(t, rec, http.StatusOK)
	assert.Equal(t, `{"kind":"owner","name":"Карл","account_name":"Новая"}`, rec.Body.String())
	rec = b.register(newDevice(), token, "", "Наш дом")
	wantStatus(t, rec, http.StatusOK)
	assert.Equal(t, accountBody{ID: string(fresh.ID), Name: "Наш дом"}, decodeAs[signedIn](t, rec).Account)

	// A member invite to an account with owners is no co-owner either.
	member, err := e.a.IssueInvite(ctx, core.InviteMember, core.AccountID(admin.Account.ID), "Ира", core.PersonID(admin.Person.ID))
	require.NoError(t, err)
	token = tokenOf(t, member.URL, testOrigin+"/join#t=")
	e.secret(token)
	rec = e.browser().do(http.MethodPost, "/api/auth/token", map[string]string{"token": token})
	wantStatus(t, rec, http.StatusOK)
	assert.Equal(t, `{"kind":"member","name":"Ира","account_name":"Семья"}`, rec.Body.String())

	// The owner check failing is a 500, at the token and at the finish.
	inv, err = e.a.IssueInvite(ctx, core.InviteOwner, core.AccountID(admin.Account.ID), "Ира", core.PersonID(admin.Person.ID))
	require.NoError(t, err)
	token = tokenOf(t, inv.URL, testOrigin+"/join#t=")
	e.secret(token)
	b = e.browser()
	opts := b.begin("/api/auth/register/begin", map[string]string{"token": token, "account_name": "Ещё имя"})
	e.st.setFail("People.ListByAccount", assert.AnError)
	wantError(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token}),
		http.StatusInternalServerError, "internal")
	wantError(t, b.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": newDevice().create(t, opts)}),
		http.StatusInternalServerError, "internal")
}

// IssueSetupLink is the setup-link command in-process: the same rule, the same link, the older ones revoked.
func TestIssueSetupLink(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	older := e.setupLink()
	url, expires, err := e.a.IssueSetupLink(ctx)
	require.NoError(t, err)
	token := tokenOf(t, url+" ", testOrigin+"/setup#t=")
	e.secret(token)
	assert.Equal(t, e.clock.Now().Add(SetupLinkTTL), expires)
	last := e.lastAudit()
	assert.Equal(t, core.AuditEntry{ID: last.ID, At: e.clock.Now(), Action: "admin.setup-link",
		Detail: map[string]string{"expires_at": "2026-11-20T12:15:00.000Z", "via": "in-process"}}, last)
	assert.True(t, e.logged("auth: a setup link was made in-process"))
	b := e.browser()
	wantError(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": older}), http.StatusNotFound, "not_found")
	wantStatus(t, b.register(newDevice(), token, "Алиса", "Семья"), http.StatusOK)

	// The superadmin has a passkey now: refused, as on the socket.
	_, _, err = e.a.IssueSetupLink(ctx)
	require.ErrorIs(t, err, core.ErrConflict)
	assert.Contains(t, err.Error(), "`hub admin reset-access`")
	// After reset-access it adds a passkey to the same superadmin.
	_, err = e.command("reset-access")
	require.NoError(t, err)
	_, _, err = e.a.IssueSetupLink(ctx)
	require.NoError(t, err)
	e.st.setFail("Tx", assert.AnError)
	_, _, err = e.a.IssueSetupLink(ctx)
	require.ErrorIs(t, err, assert.AnError)
}

// The socket's peer goes into the audit of setup-link and reset-access, and reset-access tells the application
// (review GK-5). Who started the peer (peer_chain) is added when the socket knew it, and left out otherwise.
func TestAdminCommandsNameTheirPeer(t *testing.T) {
	var resets []AccessReset
	e := newEnv(t, func(o *Options) {
		o.OnAccessReset = func(ctx context.Context, r AccessReset) {
			assert.NoError(t, ctx.Err())
			resets = append(resets, r)
		}
	})
	plain := adminsock.Peer{UID: 501, PID: 4242, Exe: "/usr/local/bin/app"}
	_, err := e.commandFrom(plain, "setup-link")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"expires_at": "2026-11-20T12:15:00.000Z", "peer_pid": "4242",
		"peer_exe": "/usr/local/bin/app"}, e.lastAudit().Detail)
	assert.True(t, e.logged("auth: a setup link was made on the admin socket", "peer_pid", "4242",
		"peer_exe", "/usr/local/bin/app"))

	const chain = "/bin/zsh (pid 4241) < login (pid 4240) < /usr/local/bin/terminal (pid 12)"
	peer := plain
	peer.Chain = chain
	out, err := e.commandFrom(peer, "reset-access")
	require.NoError(t, err)
	assert.Contains(t, out, "The hub has no superadmin yet: nothing to wipe.")
	require.Len(t, resets, 1)
	assert.Equal(t, AccessReset{At: e.clock.Now(), People: []core.PersonID{}, Peer: peer}, resets[0])
	assert.Equal(t, chain, e.lastAudit().Detail["peer_chain"])

	_, err = e.commandFrom(peer, "setup-link")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"expires_at": "2026-11-20T12:15:00.000Z", "peer_pid": "4242",
		"peer_exe": "/usr/local/bin/app", "peer_chain": chain}, e.lastAudit().Detail)
	assert.True(t, e.logged("auth: a setup link was made on the admin socket", "peer_pid", "4242", "peer_chain", chain))

	_, admin := e.superadmin(newDevice())
	_, err = e.commandFrom(peer, "reset-access")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"people": "1", "passkeys": "1", "grants": "0", "legacy_keys": "0", "invites": "0",
		"peer_pid": "4242", "peer_exe": "/usr/local/bin/app", "peer_chain": chain}, e.lastAudit().Detail)
	assert.True(t, e.logged("auth: access was reset on the admin socket", "peer_pid", "4242", "people", "1",
		"peer_chain", chain))
	require.Len(t, resets, 2)
	assert.Equal(t, []core.PersonID{core.PersonID(admin.Person.ID)}, resets[1].People)

	// A failed reset tells nobody.
	e.st.setFail("Tx", assert.AnError)
	_, err = e.commandFrom(peer, "reset-access")
	require.Error(t, err)
	assert.Len(t, resets, 2)
}

// purgingStore is a store that cannot expire rows by itself (sqlitestore): the sweep purges it.
type purgingStore struct {
	*fakeStore
	mu    sync.Mutex
	calls []time.Time
	stats store.PurgeStats
	err   error
}

func (p *purgingStore) Purge(_ context.Context, now time.Time) (store.PurgeStats, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, now)
	return p.stats, p.err
}

// Review GK-3: the hourly sweep calls store.Purger when the store has it.
func TestSweepPurges(t *testing.T) {
	e := newEnv(t)
	ps := &purgingStore{fakeStore: e.st, stats: store.PurgeStats{Tokens: 3, Audit: 1}}
	e.a.st = ps
	e.a.sweep(context.Background())
	assert.Equal(t, []time.Time{e.clock.Now()}, ps.calls)
	assert.True(t, e.logged("auth: purged expired records", "tokens", "3", "codes", "0", "audit", "1"))

	ps.stats, ps.err = store.PurgeStats{}, assert.AnError
	e.a.sweep(context.Background())
	assert.Len(t, ps.calls, 2)
	assert.True(t, e.logged("auth: cannot purge expired records"))

	// Start sweeps at once.
	ps.err = nil
	require.NoError(t, e.a.Start(context.Background()))
	require.NoError(t, e.a.Stop(context.Background()))
	assert.Len(t, ps.calls, 3)

	// A store without Purge (MongoDB's TTL indexes do the work) is only swept of sessions.
	plain := newEnv(t)
	plain.a.sweep(context.Background())
	assert.False(t, plain.logged("auth: cannot purge expired records"))
}

// Review GK-18: the texts name the application by Brand.AppWord; the default keeps Family Hub's bytes.
func TestAppWord(t *testing.T) {
	for _, tc := range []struct {
		noun, word string
	}{{"", "hub"}, {"Homie", "Homie"}} {
		t.Run(tc.word, func(t *testing.T) {
			e := newEnv(t, func(o *Options) { o.Brand.AppNoun = tc.noun })
			out, err := e.command("reset-access")
			require.NoError(t, err)
			assert.Contains(t, out, "The "+tc.word+" has no superadmin yet: nothing to wipe.\n")
			assert.Contains(t, out, "Whoever opens it first takes the "+tc.word+":\ndo not share it.\n")

			b, admin := e.superadmin(newDevice())
			require.NoError(t, e.st.Passkeys().DeleteByPerson(context.Background(), core.PersonID(admin.Person.ID)))
			body := wantError(t, b.do(http.MethodPost, "/api/auth/stepup/begin", map[string]any{}), http.StatusConflict, "conflict")
			assert.Equal(t, "you have no passkey of this "+tc.word+" to confirm with", body.Message)

			require.NoError(t, e.st.People().Disable(context.Background(), core.PersonID(admin.Person.ID), e.clock.Now()))
			_, err = e.command("setup-link")
			assert.EqualError(t, err, "every superadmin of the "+tc.word+" is disabled")
			assert.Equal(t, "the "+tc.word+" already has a superadmin", e.a.errSuperadminExists().Error())
		})
	}
}

// IssueSetupLinkTTL makes a shorter link; the store, the answer and the audit all carry its real end. A life that is
// not positive or over the default is the default.
func TestIssueSetupLinkTTL(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	url, expires, err := e.a.IssueSetupLinkTTL(ctx, 3*time.Minute)
	require.NoError(t, err)
	token := tokenOf(t, url+" ", testOrigin+"/setup#t=")
	e.secret(token)
	end := e.clock.Now().Add(3 * time.Minute)
	assert.Equal(t, end, expires)
	stored, ok := e.st.Invites().(fakeInvites).get(hashToken(token))
	require.True(t, ok)
	assert.Equal(t, end, stored.ExpiresAt)
	assert.Equal(t, map[string]string{"expires_at": "2026-11-20T12:03:00.000Z", "via": "in-process"}, e.lastAudit().Detail)
	b := e.browser()
	e.clock.Add(3*time.Minute - time.Millisecond)
	wantStatus(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token}), http.StatusOK)
	e.clock.Add(time.Millisecond)
	wantError(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token}), http.StatusNotFound, "not_found")

	for _, ttl := range []time.Duration{0, -time.Minute, SetupLinkTTL + time.Second, time.Hour, SetupLinkTTL} {
		_, expires, err := e.a.IssueSetupLinkTTL(ctx, ttl)
		require.NoError(t, err)
		assert.Equal(t, e.clock.Now().Add(SetupLinkTTL), expires, "%s", ttl)
		assert.Equal(t, rfc3339(e.clock.Now().Add(SetupLinkTTL)), e.lastAudit().Detail["expires_at"], "%s", ttl)
	}
}

// SuperadminCanSignIn is the setup links' rule: an enabled superadmin with a passkey registered for this RP ID.
func TestSuperadminCanSignIn(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	can, err := e.a.SuperadminCanSignIn(ctx)
	require.NoError(t, err)
	assert.False(t, can, "nobody set up yet")

	_, admin := e.superadmin(newDevice())
	id := core.PersonID(admin.Person.ID)
	can, err = e.a.SuperadminCanSignIn(ctx)
	require.NoError(t, err)
	assert.True(t, can)
	_, _, err = e.a.IssueSetupLink(ctx)
	require.ErrorIs(t, err, core.ErrConflict, "the same rule refuses a link")

	// A member's passkey does not count, nor a superadmin passkey of another RP ID (another host of the home).
	e.invited(newDevice(), core.InviteMember, core.AccountID(admin.Account.ID), "Борис", id)
	require.NoError(t, e.st.Passkeys().DeleteByPerson(ctx, id))
	require.NoError(t, e.st.Passkeys().Add(ctx, core.Passkey{ID: "pk_otherotherotherot", PersonID: id,
		CredentialID: []byte("other"), Data: mustEncode(t, "other.example.com")}))
	can, err = e.a.SuperadminCanSignIn(ctx)
	require.NoError(t, err)
	assert.False(t, can)
	_, _, err = e.a.IssueSetupLink(ctx)
	require.NoError(t, err, "and a link is allowed")

	// A disabled superadmin with a usable passkey cannot sign in either.
	require.NoError(t, e.st.Passkeys().Add(ctx, core.Passkey{ID: "pk_herehereherehere", PersonID: id,
		CredentialID: []byte("cred"), Data: mustEncode(t, testHost)}))
	can, err = e.a.SuperadminCanSignIn(ctx)
	require.NoError(t, err)
	assert.True(t, can)
	require.NoError(t, e.st.People().Disable(ctx, id, e.clock.Now()))
	can, err = e.a.SuperadminCanSignIn(ctx)
	require.NoError(t, err)
	assert.False(t, can)

	e.st.setFail("Passkeys.ListByPerson", assert.AnError)
	require.NoError(t, e.st.People().Create(ctx, core.Person{ID: "per_secondsecondsec", AccountID: core.AccountID(admin.Account.ID),
		Name: "Карл", Role: core.RoleOwner, Superadmin: true, CreatedAt: e.clock.Now()}))
	_, err = e.a.SuperadminCanSignIn(ctx)
	require.ErrorIs(t, err, assert.AnError)
}
