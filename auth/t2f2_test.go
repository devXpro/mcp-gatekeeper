package auth

// T2.F2 (docs/reviews/T2.R.md): sessions end with a deleted passkey and on "sign out on other devices", reset-access
// ends everything the superadmin's identity left behind, no shared bucket on invites, failed sign-ins coalesced.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// sessionCookie is the session cookie a response set.
func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatalf("no %s cookie in %v", cookieName, rec.Header())
	return nil
}

func sessionOf(t *testing.T, e *env, cookie string) core.Session {
	t.Helper()
	s, err := e.st.Sessions().Get(context.Background(), hashToken(cookie))
	require.NoError(t, err)
	return s
}

// Regression for the PoC TestT2R_PasskeyDeleteKeepsSessions (M3): Bella's phone is stolen with its session; on her
// Mac she deletes the phone's passkey, and the phone is signed out at once. The Mac carries on in a new session with
// the same step-up and absolute end.
func TestT2R_PasskeyDeleteEndsOtherSessions(t *testing.T) {
	e := newEnv(t)
	alice, admin := e.superadmin(newDevice())
	phoneKey := newDevice()
	phone := e.invited(phoneKey, core.InviteMember, core.AccountID(admin.Account.ID), "Белла", core.PersonID(admin.Person.ID))
	macKey := newDevice()
	wantStatus(t, phone.addPasskey(macKey, "MacBook"), http.StatusCreated)
	e.clock.Add(time.Minute)
	mac := e.browser()
	wantStatus(t, mac.login(macKey), http.StatusOK)
	before := sessionOf(t, e, mac.cookie)
	oldCookie := mac.cookie

	list := decodeAs[[]passkeyBody](t, mac.do(http.MethodGet, "/api/me/passkeys", nil))
	require.Len(t, list, 2)
	var phoneID string
	for _, pk := range list {
		if pk.Name != "MacBook" {
			phoneID = pk.ID
		}
	}
	e.clock.Add(2 * time.Minute)
	rec := mac.do(http.MethodDelete, "/api/me/passkeys/"+phoneID, nil)
	wantStatus(t, rec, http.StatusNoContent)

	// The thief's phone is out, for reads and writes.
	wantError(t, phone.do(http.MethodGet, "/api/me", nil), http.StatusUnauthorized, "no_session")
	wantError(t, phone.do(http.MethodPost, "/test/write", nil), http.StatusUnauthorized, "no_session")
	// The Mac has a new cookie; the old one is dead.
	ck := sessionCookie(t, rec)
	assert.NotEqual(t, oldCookie, ck.Value)
	assert.Equal(t, int((AbsoluteTimeout - 2*time.Minute).Seconds()), ck.MaxAge, "the cookie ends with the session")
	assert.True(t, ck.Secure && ck.HttpOnly && ck.SameSite == http.SameSiteStrictMode && ck.Path == "/")
	stale := e.browser()
	stale.cookie = oldCookie
	wantError(t, stale.do(http.MethodGet, "/api/me", nil), http.StatusUnauthorized, "no_session")
	wantStatus(t, mac.do(http.MethodGet, "/api/me", nil), http.StatusOK)
	wantStatus(t, mac.do(http.MethodPost, "/test/danger", nil), http.StatusNoContent) // the step-up is kept
	after := sessionOf(t, e, mac.cookie)
	assert.Equal(t, before.CreatedAt, after.CreatedAt)
	assert.Equal(t, before.ExpiresAt, after.ExpiresAt, "no longer than the sign-in allowed")
	assert.Equal(t, before.StepUpUntil, after.StepUpUntil)
	assert.Equal(t, before.UserAgent, after.UserAgent)
	assert.Equal(t, e.clock.Now(), after.LastSeenAt)
	assert.Equal(t, "auth.passkey.delete", e.lastAudit().Action)
	// Somebody else's sessions are untouched.
	wantStatus(t, alice.do(http.MethodGet, "/api/me", nil), http.StatusOK)
}

// Regression for the PoC TestT2R_InviteRedemptionDoS (H2): three addresses spending their buckets of auth/token do
// not stop a real invitee from a fourth.
func TestT2R_InviteRedemptionNotBlockedByOthers(t *testing.T) {
	e := newEnv(t)
	_, admin := e.superadmin(newDevice())
	inv, err := e.a.IssueInvite(context.Background(), core.InviteMember, core.AccountID(admin.Account.ID), "Бабушка", core.PersonID(admin.Person.ID))
	require.NoError(t, err)
	token := tokenOf(t, inv.URL, testOrigin+"/join#t=")

	for i := 1; i <= 3; i++ {
		b := e.browser()
		b.ip = fmt.Sprintf("203.0.113.%d", i)
		for range tokenPerAddress + 5 {
			b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": "junk"})
		}
		wantError(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": "junk"}),
			http.StatusTooManyRequests, "rate_limited")
	}
	granny := e.browser()
	granny.ip = "198.51.100.77"
	rec := granny.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token})
	wantStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"kind":"member","name":"Бабушка","account_name":"Семья"}`, rec.Body.String())
	wantStatus(t, granny.register(newDevice(), token, "", ""), http.StatusOK)
}

func TestRevokeSessions(t *testing.T) {
	e := newEnv(t)
	phone := newDevice()
	b, admin := e.superadmin(phone)
	second := e.browser()
	second.ip = "198.51.100.40"
	wantStatus(t, second.login(phone), http.StatusOK)
	bella := e.invited(newDevice(), core.InviteMember, core.AccountID(admin.Account.ID), "Белла", core.PersonID(admin.Person.ID))
	const path = "/api/me/sessions/revoke"

	// Session, CSRF and step-up.
	wantError(t, e.browser().do(http.MethodPost, path, map[string]any{}), http.StatusUnauthorized, "no_session")
	noHeader := *b
	noHeader.csrf = false
	wantError(t, noHeader.do(http.MethodPost, path, map[string]any{}), http.StatusForbidden, "forbidden")
	crossSite := *b
	crossSite.origin = "https://evil.example"
	wantError(t, crossSite.do(http.MethodPost, path, map[string]any{}), http.StatusForbidden, "forbidden")
	e.clock.Add(StepUpWindow)
	wantError(t, b.do(http.MethodPost, path, map[string]any{}), http.StatusForbidden, "step_up_required")
	wantStatus(t, b.stepUp(phone), http.StatusOK)
	wantStatus(t, second.do(http.MethodGet, "/api/me", nil), http.StatusOK)

	// The store fails: nothing changes.
	for _, method := range []string{"Tx", "Sessions.Get", "Sessions.DeleteByPerson", "Sessions.Create"} {
		e.st.setFail(method, assert.AnError)
		wantError(t, b.do(http.MethodPost, path, map[string]any{}), http.StatusInternalServerError, "internal")
		e.st.setFail(method, nil)
		wantStatus(t, second.do(http.MethodGet, "/api/me", nil), http.StatusOK)
	}

	before := sessionOf(t, e, b.cookie)
	oldCookie := b.cookie
	e.clock.Add(time.Second)
	e.st.setReplay(true) // the driver may run a transaction twice
	rec := b.do(http.MethodPost, path, nil)
	e.st.setReplay(false)
	wantStatus(t, rec, http.StatusNoContent)
	assert.Empty(t, rec.Body.String())
	ck := sessionCookie(t, rec)
	assert.NotEqual(t, oldCookie, ck.Value)
	assert.Equal(t, int(before.ExpiresAt.Sub(e.clock.Now()).Seconds()), ck.MaxAge)

	// Every other session of the person is gone, the old cookie included; this browser and other people carry on.
	wantError(t, second.do(http.MethodGet, "/api/me", nil), http.StatusUnauthorized, "no_session")
	stale := e.browser()
	stale.cookie = oldCookie
	wantError(t, stale.do(http.MethodGet, "/api/me", nil), http.StatusUnauthorized, "no_session")
	wantStatus(t, b.do(http.MethodGet, "/api/me", nil), http.StatusOK)
	wantStatus(t, b.do(http.MethodPost, "/test/danger", nil), http.StatusNoContent)
	wantStatus(t, bella.do(http.MethodGet, "/api/me", nil), http.StatusOK)
	after := sessionOf(t, e, b.cookie)
	assert.Equal(t, before.ExpiresAt, after.ExpiresAt)
	assert.Equal(t, before.StepUpUntil, after.StepUpUntil)
	assert.Len(t, e.st.Sessions().(fakeSessions).all(), 2, "b's new session and Bella's")
	last := e.lastAudit()
	assert.Equal(t, core.AuditEntry{ID: last.ID, At: e.clock.Now(), AccountID: core.AccountID(admin.Account.ID),
		Actor: core.PersonID(admin.Person.ID), Action: "auth.sessions.revoke", Target: admin.Person.ID, IP: b.ip}, last)

	// A JSON body other than an object is refused.
	wantError(t, b.do(http.MethodPost, path, "[]"), http.StatusBadRequest, "invalid")
}

// A session that another device ended meanwhile is never revived by a rotation.
func TestRotateEndedSession(t *testing.T) {
	e := newEnv(t)
	b, _ := e.superadmin(newDevice())
	req := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/", nil)
	req.Header.Set("Cookie", cookieName+"="+b.cookie)
	v, err := e.a.Viewer(req)
	require.NoError(t, err)
	require.NoError(t, e.st.Sessions().Delete(context.Background(), v.Session.IDHash))
	err = e.st.Tx(context.Background(), func(ctx context.Context) error {
		_, _, err := e.a.rotateIn(ctx, v, e.clock.Now())
		return err
	})
	require.ErrorIs(t, err, errNoSession)
	assert.Empty(t, e.st.Sessions().(fakeSessions).all())
}

func TestResetAccessEndsConnectorsKeysAndInvites(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, admin := e.superadmin(newDevice())
	acc, alice := core.AccountID(admin.Account.ID), core.PersonID(admin.Person.ID)
	bellaB := e.invited(newDevice(), core.InviteMember, acc, "Белла", alice)
	bellaID := core.PersonID(decodeAs[meBody](t, bellaB.do(http.MethodGet, "/api/me", nil)).Person.ID)
	friends := core.Account{ID: "acc_friendsfriendsfr", Name: "Друзья", CreatedAt: e.clock.Now()}
	require.NoError(t, e.st.Accounts().Create(ctx, friends))
	iraB := e.invited(newDevice(), core.InviteOwner, friends.ID, "Ира", alice)
	iraID := core.PersonID(decodeAs[meBody](t, iraB.do(http.MethodGet, "/api/me", nil)).Person.ID)
	neighbours := core.Account{ID: "acc_neighboursneighb", Name: "Соседи", CreatedAt: e.clock.Now()}
	require.NoError(t, e.st.Accounts().Create(ctx, neighbours))

	// Open invites: two of Alice's (his family, another family's owner), one of Bella's, one of Alice's expired.
	grannyInv, err := e.a.IssueInvite(ctx, core.InviteMember, acc, "Бабушка", alice)
	require.NoError(t, err)
	olegInv, err := e.a.IssueInvite(ctx, core.InviteOwner, neighbours.ID, "Олег", alice)
	require.NoError(t, err)
	grandpaInv, err := e.a.IssueInvite(ctx, core.InviteMember, acc, "Дед", bellaID)
	require.NoError(t, err)
	past := e.clock.Now().Add(-time.Hour)
	require.NoError(t, e.st.Invites().Create(ctx, core.Invite{ID: "inv_expiredexpiredex", TokenHash: hashToken(newToken()),
		Kind: core.InviteMember, AccountID: acc, Name: "Старое", CreatedBy: alice, CreatedAt: past.Add(-InviteTTL), ExpiresAt: past}))

	// Grants: Alice's live one and an old revoked one, Bella's, Ira's.
	revokedAt := e.clock.Now().Add(-24 * time.Hour)
	grants := []core.Grant{
		{ID: "gr_alice", PersonID: alice, AccountID: acc, ClientID: "cl_x", ResourceID: "notes", CreatedAt: past},
		{ID: "gr_aliceold", PersonID: alice, AccountID: acc, ClientID: "cl_x", ResourceID: "photos", CreatedAt: past, RevokedAt: &revokedAt},
		{ID: "gr_bella", PersonID: bellaID, AccountID: acc, ClientID: "cl_y", ResourceID: "notes", CreatedAt: past},
		{ID: "gr_ira", PersonID: iraID, AccountID: friends.ID, ClientID: "cl_z", ResourceID: "notes", CreatedAt: past},
	}
	for _, g := range grants {
		require.NoError(t, e.st.OAuth().PutGrant(ctx, g))
	}
	for _, m := range []string{"photos", "notes"} {
		e.st.putModule(ctx, m)
	}
	keys := []legacyKey{
		{Hash: hashToken("k1"), ModuleID: "notes", PersonID: alice, Label: "Аля"},
		{Hash: hashToken("k2"), ModuleID: "photos", PersonID: alice, Label: "Аля"},
		{Hash: hashToken("k3"), ModuleID: "notes", PersonID: bellaID, Label: "Белла"},
	}
	for _, k := range keys {
		e.st.putLegacyKey(ctx, k)
	}

	grantState := func() map[core.GrantID]bool {
		out := map[core.GrantID]bool{}
		for _, g := range grants {
			got, err := e.st.OAuth().GetGrant(ctx, g.ID)
			require.NoError(t, err)
			out[g.ID] = got.RevokedAt != nil
		}
		return out
	}
	keyCount := func() int {
		n := 0
		for _, m := range []string{"photos", "notes"} {
			list, err := e.st.legacyKeysOf(ctx, m)
			require.NoError(t, err)
			n += len(list)
		}
		return n
	}
	inviteWorks := func(url string) bool {
		rec := e.browser().do(http.MethodPost, "/api/auth/token", map[string]string{"token": tokenOf(t, url, testOrigin+"/join#t=")})
		return rec.Code == http.StatusOK
	}
	initial := map[core.GrantID]bool{"gr_alice": false, "gr_aliceold": true, "gr_bella": false, "gr_ira": false}
	require.Equal(t, initial, grantState())

	// Any failure on the way rolls everything back.
	for _, method := range []string{"OAuth.RevokeGrant", "LegacyKeys.ListByModule", "LegacyKeys.Delete", "Invites.Revoke"} {
		e.st.setFail(method, assert.AnError)
		_, err := e.command("reset-access")
		require.ErrorIs(t, err, assert.AnError, method)
		e.st.setFail(method, nil)
		assert.Equal(t, initial, grantState(), method)
		assert.Equal(t, 3, keyCount(), method)
		assert.True(t, inviteWorks(grannyInv.URL), method)
	}

	e.st.setReplay(true)
	out, err := e.command("reset-access")
	e.st.setReplay(false)
	require.NoError(t, err)
	assert.Contains(t, out, "Ended 1 passkeys, 1 connectors (OAuth grants), 2 legacy keys and 2 open invites.\n")

	assert.Equal(t, map[core.GrantID]bool{"gr_alice": true, "gr_aliceold": true, "gr_bella": false, "gr_ira": false}, grantState())
	old, err := e.st.OAuth().GetGrant(ctx, "gr_aliceold")
	require.NoError(t, err)
	assert.Equal(t, ms(revokedAt), *old.RevokedAt, "an old revocation keeps its time")
	left, err := e.st.legacyKeysOf(ctx, "notes")
	require.NoError(t, err)
	require.Len(t, left, 1)
	assert.Equal(t, bellaID, left[0].PersonID)
	assert.Equal(t, 1, keyCount())
	assert.False(t, inviteWorks(grannyInv.URL), "Alice's invite into his family")
	assert.False(t, inviteWorks(olegInv.URL), "Alice's invite of another family's owner")
	assert.True(t, inviteWorks(grandpaInv.URL), "Bella's invite stays")
	// The people who joined through Alice's invites stay.
	wantStatus(t, bellaB.do(http.MethodGet, "/api/me", nil), http.StatusOK)
	wantStatus(t, iraB.do(http.MethodGet, "/api/me", nil), http.StatusOK)

	var reset core.AuditEntry
	for _, a := range e.st.Audit().(fakeAudit).entries() {
		if a.Action == "admin.reset-access" {
			reset = a
		}
	}
	assert.Equal(t, map[string]string{"people": "1", "passkeys": "1", "grants": "1", "legacy_keys": "2", "invites": "2"},
		reset.Detail)
}

// loginFails returns the auth.login.fail entries, oldest first.
func (e *env) loginFails() []core.AuditEntry {
	var out []core.AuditEntry
	for _, a := range e.st.Audit().(fakeAudit).entries() {
		if a.Action == "auth.login.fail" {
			out = append(out, a)
		}
	}
	return out
}

// failLogin runs a sign-in with a passkey the hub does not know.
func (b *browser) failLogin() {
	b.e.t.Helper()
	wantError(b.e.t, b.login(newDevice()), http.StatusBadRequest, "invalid")
}

func failEntry(at time.Time, ip string, count int) core.AuditEntry {
	return core.AuditEntry{At: at, Action: "auth.login.fail", IP: ip, Detail: map[string]string{"count": strconv.Itoa(count)}}
}

func withoutIDs(entries []core.AuditEntry) []core.AuditEntry {
	for i := range entries {
		entries[i].ID = ""
	}
	return entries
}

// L8: one auth.login.fail entry per address group a minute, with the count since the group's previous entry.
func TestLoginFailCoalesced(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.superadmin(newDevice())
	t0 := e.clock.Now()
	a := e.browser()
	a.ip = "203.0.113.7"
	for range 4 {
		a.failLogin()
	}
	v6 := e.browser()
	for _, ip := range []string{"2001:db8:9:9::1", "2001:db8:9:9:abcd::2"} {
		v6.ip = ip
		v6.failLogin()
	}
	want := []core.AuditEntry{failEntry(t0, "203.0.113.7", 1), failEntry(t0, "2001:db8:9:9::/64", 1)}
	assert.Equal(t, want, withoutIDs(e.loginFails()), "the first failure of a group is written at once")

	// After the minute, the next failure reports the ones counted meanwhile.
	e.clock.Add(time.Minute + time.Second)
	t1 := e.clock.Now()
	a.failLogin()
	a.failLogin()
	a.failLogin()
	want = append(want, failEntry(t1, "203.0.113.7", 4))
	assert.Equal(t, want, withoutIDs(e.loginFails()))

	// The flush writes the groups whose minute is over; Stop writes the rest.
	e.a.flushLoginFails(ctx, false)
	want = append(want, failEntry(t1, "2001:db8:9:9::/64", 1))
	assert.Equal(t, want, withoutIDs(e.loginFails()))
	e.clock.Add(time.Second)
	e.a.flushLoginFails(ctx, false)
	assert.Len(t, e.loginFails(), len(want), "the address's minute is not over")
	require.NoError(t, e.a.Start(ctx))
	require.NoError(t, e.a.Stop(ctx))
	want = append(want, failEntry(e.clock.Now(), "203.0.113.7", 2))
	assert.Equal(t, want, withoutIDs(e.loginFails()))
	e.a.flushLoginFails(ctx, true)
	assert.Len(t, e.loginFails(), len(want), "nothing is written twice")

	// A quiet group starts over.
	e.clock.Add(time.Hour)
	a.failLogin()
	assert.Equal(t, failEntry(e.clock.Now(), "203.0.113.7", 1), withoutIDs(e.loginFails()[len(want):])[0])
}

// More address groups than the map holds in one minute share one entry without an address.
func TestLoginFailOverflow(t *testing.T) {
	f := newFailedLogins()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for i := range maxFailGroups {
		got, ok := f.note("g"+strconv.Itoa(i), now)
		require.True(t, ok)
		require.Equal(t, failedSince{group: "g" + strconv.Itoa(i), count: 1}, got)
	}
	got, ok := f.note("new1", now)
	assert.True(t, ok)
	assert.Equal(t, failedSince{group: failOverflow, count: 1}, got)
	_, ok = f.note("new2", now)
	assert.False(t, ok, "counted in the overflow group")
	_, ok = f.note("g1", now)
	assert.False(t, ok, "a known group keeps its own count")
	assert.LessOrEqual(t, len(f.m), maxFailGroups+1)
	assert.ElementsMatch(t, []failedSince{{group: failOverflow, count: 1}, {group: "g1", count: 1}},
		f.due(now.Add(failWindow), false))
	assert.Empty(t, f.m)

	// Quiet groups make room without a flush.
	for i := range maxFailGroups {
		f.note("h"+strconv.Itoa(i), now)
	}
	later := now.Add(failWindow)
	got, ok = f.note("fresh", later)
	assert.True(t, ok)
	assert.Equal(t, failedSince{group: "fresh", count: 1}, got)
	assert.Len(t, f.m, 1)

	// The overflow entry has no address.
	e := newEnv(t)
	for i := range maxFailGroups {
		e.a.fails.note("x"+strconv.Itoa(i), e.clock.Now())
	}
	b := e.browser()
	b.ip = "192.0.2.99"
	b.failLogin()
	assert.Equal(t, []core.AuditEntry{failEntry(e.clock.Now(), "", 1)}, withoutIDs(e.loginFails()))
}
