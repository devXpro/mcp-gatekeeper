package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestSetupRegistrationAndLogin(t *testing.T) {
	e := newEnv(t)
	e.st.setReplay(true) // every transaction runs twice, as the driver may: only the tx may be used inside
	ctx := context.Background()
	phone := newDevice()
	token := e.setupLink()

	b := e.browser()
	rec := b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token})
	wantStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"kind":"setup","name":""}`, rec.Body.String())

	// The options ask for a discoverable, user-verified passkey of this domain, without attestation.
	opts := b.begin("/api/auth/register/begin", map[string]string{"token": token, "name": " Алиса ", "account_name": "Семья"})
	var o struct {
		RP struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		User struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
		Selection struct {
			ResidentKey        string `json:"residentKey"`
			RequireResidentKey bool   `json:"requireResidentKey"`
			UserVerification   string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		Attestation string `json:"attestation"`
		Timeout     int    `json:"timeout"`
		Challenge   string `json:"challenge"`
	}
	require.NoError(t, json.Unmarshal(opts, &o))
	assert.Equal(t, testHost, o.RP.ID)
	assert.Equal(t, "Family Hub", o.RP.Name)
	assert.Equal(t, "Алиса", o.User.Name)
	assert.Equal(t, "Алиса", o.User.DisplayName)
	handle, err := base64.RawURLEncoding.DecodeString(o.User.ID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(handle), "per_"), "user handle %q is a person id", handle)
	assert.Equal(t, "required", o.Selection.ResidentKey)
	assert.True(t, o.Selection.RequireResidentKey)
	assert.Equal(t, "required", o.Selection.UserVerification)
	assert.Equal(t, "none", o.Attestation)
	assert.Equal(t, int(CeremonyTTL/time.Millisecond), o.Timeout)
	assert.NotContains(t, string(opts), `"publicKey"`, "options are the inner object")

	rec = b.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": phone.create(t, opts)})
	wantStatus(t, rec, http.StatusOK)
	got := decodeAs[signedIn](t, rec)
	assert.Equal(t, string(handle), got.Person.ID)
	assert.Equal(t, "Алиса", got.Person.Name)
	assert.Equal(t, "owner", got.Person.Role)
	assert.True(t, got.Person.Superadmin)
	assert.True(t, strings.HasPrefix(got.Account.ID, "acc_"))
	assert.Equal(t, "Семья", got.Account.Name)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	ck := cookies[0]
	assert.Equal(t, cookieName, ck.Name)
	assert.True(t, ck.Secure)
	assert.True(t, ck.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, ck.SameSite)
	assert.Equal(t, "/", ck.Path)
	assert.Empty(t, ck.Domain)
	assert.Equal(t, int(AbsoluteTimeout/time.Second), ck.MaxAge)
	assert.True(t, wellFormedToken(ck.Value))

	// Stored: the account, the superadmin owner, the passkey, the used link and a session that keeps only the hash.
	now := e.clock.Now()
	pid, aid := core.PersonID(got.Person.ID), core.AccountID(got.Account.ID)
	acc, err := e.st.Accounts().Get(ctx, aid)
	require.NoError(t, err)
	assert.Equal(t, now, acc.CreatedAt)
	p, err := e.st.People().Get(ctx, pid)
	require.NoError(t, err)
	assert.Equal(t, core.Person{ID: pid, AccountID: aid, Name: "Алиса", Role: core.RoleOwner, Superadmin: true, CreatedAt: now}, p)
	pks, err := e.st.Passkeys().ListByPerson(ctx, pid)
	require.NoError(t, err)
	require.Len(t, pks, 1)
	assert.Equal(t, "Mac", pks[0].Name, "named after the User-Agent")
	assert.Equal(t, phone.cred.ID, pks[0].CredentialID)
	assert.True(t, strings.HasPrefix(pks[0].ID, "pk_"))
	require.NotNil(t, pks[0].LastUsedAt)
	rpID, cred, err := decodeCredential(pks[0].Data)
	require.NoError(t, err)
	assert.Equal(t, testHost, rpID)
	assert.True(t, cred.Flags.UserVerified)
	assert.True(t, cred.Flags.BackupEligible)
	sessions := e.st.Sessions().(fakeSessions).all()
	require.Len(t, sessions, 1)
	sum := sha256.Sum256([]byte(b.cookie))
	assert.Equal(t, sum[:], sessions[0].IDHash)
	assert.Equal(t, pid, sessions[0].PersonID)
	assert.Equal(t, now.Add(AbsoluteTimeout), sessions[0].ExpiresAt)
	assert.Equal(t, now.Add(StepUpWindow), sessions[0].StepUpUntil, "registering counts as step-up")
	assert.Equal(t, safariMac, sessions[0].UserAgent)
	inv, ok := e.st.Invites().(fakeInvites).get(hashToken(token))
	require.True(t, ok)
	require.NotNil(t, inv.UsedAt)

	rec = b.do(http.MethodGet, "/api/me", nil)
	wantStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"person":{"id":"`+got.Person.ID+`","name":"Алиса","role":"owner","superadmin":true},`+
		`"account":{"id":"`+got.Account.ID+`","name":"Семья"},"step_up_until":"2026-11-20T12:05:00.000Z"}`, rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	// Logout ends the session and clears the cookie.
	rec = b.do(http.MethodPost, "/api/auth/logout", map[string]any{})
	wantStatus(t, rec, http.StatusNoContent)
	assert.Empty(t, b.cookie)
	assert.Empty(t, e.st.Sessions().(fakeSessions).all())
	wantError(t, b.do(http.MethodGet, "/api/me", nil), http.StatusUnauthorized, "no_session")

	// A later sign-in on another browser with the same passkey; it counts as step-up too.
	e.clock.Add(time.Hour)
	b2 := e.browser()
	b2.ua = safariIOS
	rec = b2.login(phone)
	wantStatus(t, rec, http.StatusOK)
	assert.Equal(t, got, decodeAs[signedIn](t, rec))
	require.NotEmpty(t, b2.cookie)
	me := decodeAs[meBody](t, b2.do(http.MethodGet, "/api/me", nil))
	require.NotNil(t, me.StepUpUntil)
	assert.Equal(t, rfc3339(e.clock.Now().Add(StepUpWindow)), *me.StepUpUntil)
	pk, err := e.st.Passkeys().Get(ctx, pks[0].ID)
	require.NoError(t, err)
	assert.Equal(t, e.clock.Now(), *pk.LastUsedAt)

	assert.Equal(t, []string{"admin.setup-link", "auth.register", "auth.logout", "auth.login"}, e.actions())
	entries := e.st.Audit().(fakeAudit).entries()
	assert.Equal(t, core.AuditEntry{ID: entries[1].ID, At: now, AccountID: aid, Actor: pid, Action: "auth.register",
		Target: string(pid), Detail: map[string]string{"kind": "setup"}, IP: "198.51.100.10"}, entries[1])
	assert.Empty(t, entries[0].AccountID, "the setup link is a system entry")
	assert.Empty(t, entries[0].Actor)
	assert.Equal(t, aid, entries[3].AccountID)
	assert.Equal(t, pid, entries[3].Actor)
}

func TestTokenInfo(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, admin := e.superadmin(newDevice())
	aid, pid := core.AccountID(admin.Account.ID), core.PersonID(admin.Person.ID)

	owner, err := e.a.IssueInvite(ctx, core.InviteOwner, aid, "Ира", pid)
	require.NoError(t, err)
	member, err := e.a.IssueInvite(ctx, core.InviteMember, aid, "Белла", pid)
	require.NoError(t, err)
	b := e.browser()
	info := func(url string) *httptest.ResponseRecorder {
		return b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": tokenOf(t, url, testOrigin+"/join#t=")})
	}
	// The superadmin's own account has its owner: this owner invite makes a co-owner (the first owner of a new
	// account, Family Hub's case, has no co_owner: TestCoOwnerInvite).
	assert.JSONEq(t, `{"kind":"owner","name":"Ира","account_name":"Семья","co_owner":true}`, info(owner.URL).Body.String())
	assert.JSONEq(t, `{"kind":"member","name":"Белла","account_name":"Семья"}`, info(member.URL).Body.String())

	// Withdrawn, expired, unknown and malformed tokens all answer 404 (used ones too: TestRegisterFinishRefusals).
	require.NoError(t, e.st.Invites().Revoke(ctx, owner.ID, e.clock.Now()))
	wantError(t, info(owner.URL), http.StatusNotFound, "not_found")
	e.clock.Add(InviteTTL)
	wantError(t, info(member.URL), http.StatusNotFound, "not_found")
	for _, token := range []string{newToken(), "short", "", strings.Repeat("!", 43)} {
		wantError(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token}), http.StatusNotFound, "not_found")
	}

	// An invite whose account is gone is no invite.
	inv, err := e.a.IssueInvite(ctx, core.InviteMember, aid, "Лёша", pid)
	require.NoError(t, err)
	require.NoError(t, e.st.Accounts().Delete(ctx, aid))
	wantError(t, info(inv.URL), http.StatusNotFound, "not_found")
}

func TestInviteRegistration(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, admin := e.superadmin(newDevice())
	superID := core.PersonID(admin.Person.ID)

	// The superadmin makes a second family (T1.4 does that) and invites its owner.
	friends := core.Account{ID: "acc_friendsfriendsfr", Name: "Друзья", CreatedAt: e.clock.Now()}
	require.NoError(t, e.st.Accounts().Create(ctx, friends))
	inv, err := e.a.IssueInvite(ctx, core.InviteOwner, friends.ID, " Ира ", superID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(inv.ID, "inv_"))
	assert.Equal(t, e.clock.Now().Add(InviteTTL), inv.ExpiresAt)
	token := tokenOf(t, inv.URL, testOrigin+"/join#t=")
	stored, ok := e.st.Invites().(fakeInvites).get(hashToken(token))
	require.True(t, ok)
	assert.Equal(t, core.Invite{ID: inv.ID, TokenHash: hashToken(token), Kind: core.InviteOwner, AccountID: friends.ID,
		Name: "Ира", CreatedBy: superID, CreatedAt: e.clock.Now(), ExpiresAt: inv.ExpiresAt}, stored)

	// The owner keeps the name the superadmin typed and renames the family.
	b := e.browser()
	b.ip = "2001:db8:1:2:3:4:5:6"
	rec := b.register(newDevice(), token, "", "Друзья навсегда")
	wantStatus(t, rec, http.StatusOK)
	ira := decodeAs[signedIn](t, rec)
	assert.Equal(t, personBody{ID: ira.Person.ID, Name: "Ира", Role: "owner"}, ira.Person)
	assert.Equal(t, accountBody{ID: string(friends.ID), Name: "Друзья навсегда"}, ira.Account)
	acc, err := e.st.Accounts().Get(ctx, friends.ID)
	require.NoError(t, err)
	assert.Equal(t, "Друзья навсегда", acc.Name)
	last := e.lastAudit()
	assert.Equal(t, "auth.join", last.Action)
	assert.Equal(t, friends.ID, last.AccountID)
	assert.Equal(t, core.PersonID(ira.Person.ID), last.Actor)
	assert.Equal(t, map[string]string{"kind": "owner", "invite": inv.ID}, last.Detail)
	assert.Equal(t, "2001:db8:1:2:3:4:5:6", last.IP)

	// A member picks a name of their own; account_name means nothing for a member.
	minv, err := e.a.IssueInvite(ctx, core.InviteMember, friends.ID, "Лёша", core.PersonID(ira.Person.ID))
	require.NoError(t, err)
	mb := e.browser()
	rec = mb.register(newDevice(), tokenOf(t, minv.URL, testOrigin+"/join#t="), "Алексей", "Чужая семья")
	wantStatus(t, rec, http.StatusOK)
	lesha := decodeAs[signedIn](t, rec)
	assert.Equal(t, personBody{ID: lesha.Person.ID, Name: "Алексей", Role: "member"}, lesha.Person)
	assert.Equal(t, "Друзья навсегда", lesha.Account.Name)
	rec = mb.do(http.MethodGet, "/test/viewer", nil)
	wantStatus(t, rec, http.StatusOK)
	assert.Equal(t, lesha.Person.ID+" "+string(friends.ID), rec.Body.String())
	assert.Equal(t, map[string]string{"kind": "member", "invite": minv.ID}, e.lastAudit().Detail)
}

func TestIssueInviteChecks(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, admin := e.superadmin(newDevice())
	aid, pid := core.AccountID(admin.Account.ID), core.PersonID(admin.Person.ID)
	for _, tc := range []struct {
		name    string
		kind    core.InviteKind
		account core.AccountID
		who     string
		by      core.PersonID
		is      error
	}{
		{"a setup link", core.InviteSetup, aid, "Белла", pid, nil},
		{"an unknown kind", "guest", aid, "Белла", pid, nil},
		{"no account", core.InviteMember, "", "Белла", pid, nil},
		{"nobody asked", core.InviteMember, aid, "Белла", "", nil},
		{"no name", core.InviteMember, aid, "  ", pid, ErrInvalidName},
		{"a line break", core.InviteMember, aid, "Белла\nowner", pid, ErrInvalidName},
		{"a quote", core.InviteMember, aid, `Белла"`, pid, ErrInvalidName},
		{"an unknown account", core.InviteMember, "acc_nonenonenonenone", "Белла", pid, core.ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.a.IssueInvite(ctx, tc.kind, tc.account, tc.who, tc.by)
			require.Error(t, err)
			if tc.is != nil {
				require.ErrorIs(t, err, tc.is)
			}
		})
	}
	e.st.setFail("Invites.Create", assert.AnError)
	_, err := e.a.IssueInvite(ctx, core.InviteMember, aid, "Белла", pid)
	require.ErrorIs(t, err, assert.AnError)
	e.st.setFail("Invites.Create", nil)

	// Inside a transaction: the account it creates is visible, and a rollback takes the invite with it. Both forms
	// join the transaction the context carries.
	for _, in := range []bool{true, false} {
		var url string
		err = e.st.Tx(ctx, func(ctx context.Context) error {
			if err := e.st.Accounts().Create(ctx, core.Account{ID: "acc_newnewnewnewnewn", Name: "Новые", CreatedAt: e.clock.Now()}); err != nil {
				return err
			}
			issue := e.a.IssueInvite
			if in {
				issue = func(ctx context.Context, kind core.InviteKind, account core.AccountID, name string,
					by core.PersonID) (IssuedInvite, error) {
					return e.a.IssueInviteIn(ctx, e.st, kind, account, name, by)
				}
			}
			inv, err := issue(ctx, core.InviteOwner, "acc_newnewnewnewnewn", "Оля", pid)
			url = inv.URL
			if err != nil {
				return err
			}
			return assert.AnError
		})
		require.ErrorIs(t, err, assert.AnError)
		_, ok := e.st.Invites().(fakeInvites).get(hashToken(tokenOf(t, url, testOrigin+"/join#t=")))
		assert.False(t, ok, "rolled back")
		_, err = e.st.Accounts().Get(ctx, "acc_newnewnewnewnewn")
		require.ErrorIs(t, err, core.ErrNotFound)
	}
}

func TestRegisterBeginChecks(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	token := e.setupLink()
	for _, tc := range []struct {
		name string
		body map[string]any
		want string
	}{
		{"no name", map[string]any{"token": token, "account_name": "Семья"}, "name is required"},
		{"no account name", map[string]any{"token": token, "name": "Алиса"}, "account_name is required"},
		{"blank name", map[string]any{"token": token, "name": "   ", "account_name": "Семья"}, "name must be 1 to 40 characters"},
		{"41 characters", map[string]any{"token": token, "name": strings.Repeat("я", 41), "account_name": "Семья"},
			"name must be 1 to 40 characters"},
		{"a line break", map[string]any{"token": token, "name": "Алиса\nadmin", "account_name": "Семья"}, "name must not"},
		{"a bidi override", map[string]any{"token": token, "name": "Алиса" + string(rune(0x202e)), "account_name": "Семья"},
			"name must not"},
		{"a backtick in the account", map[string]any{"token": token, "name": "Алиса", "account_name": "Се`мья"},
			"account_name must not"},
		{"a number for a name", map[string]any{"token": token, "name": 5}, "name has the wrong type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := wantError(t, b.do(http.MethodPost, "/api/auth/register/begin", tc.body), http.StatusBadRequest, "invalid")
			assert.Contains(t, body.Message, tc.want)
		})
	}
	wantError(t, b.do(http.MethodPost, "/api/auth/register/begin", map[string]any{"name": "Алиса", "account_name": "Семья"}),
		http.StatusNotFound, "not_found")
	// 40 characters are fine, counted as characters, not bytes.
	wantStatus(t, b.do(http.MethodPost, "/api/auth/register/begin",
		map[string]any{"token": token, "name": strings.Repeat("я", 40), "account_name": "Семья"}), http.StatusOK)

	// An owner or member invite with no stored name needs one in the request.
	ctx := context.Background()
	_, admin := e.superadmin(newDevice()) // the setup link is still unused
	raw := newToken()
	require.NoError(t, e.st.Invites().Create(ctx, core.Invite{ID: "inv_nonamenonamenona", TokenHash: hashToken(raw),
		Kind: core.InviteMember, AccountID: core.AccountID(admin.Account.ID), CreatedBy: core.PersonID(admin.Person.ID),
		CreatedAt: e.clock.Now(), ExpiresAt: e.clock.Now().Add(time.Hour)}))
	wantError(t, b.do(http.MethodPost, "/api/auth/register/begin", map[string]any{"token": raw}), http.StatusBadRequest, "invalid")
	wantStatus(t, b.do(http.MethodPost, "/api/auth/register/begin", map[string]any{"token": raw, "name": "Белла"}), http.StatusOK)
}

func TestRegistrationRejected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(d *device)
	}{
		{"wrong origin", func(d *device) { d.rp.Origin = "https://evil.example.com" }},
		{"origin over http", func(d *device) { d.rp.Origin = "http://" + testHost }},
		{"a sibling origin", func(d *device) { d.rp.Origin = "https://other.example.com" }},
		{"wrong RP ID", func(d *device) { d.rp.ID = "evil.example.com" }},
		{"parent domain as RP ID", func(d *device) { d.rp.ID = "example.com" }},
		{"user not verified", func(d *device) { d.auth.Options.UserNotVerified = true }},
		{"user not present", func(d *device) { d.auth.Options.UserNotPresent = true }},
		{"backup state without eligibility", func(d *device) { d.auth.Options.BackupEligible = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			token := e.setupLink()
			bad := newDevice()
			tc.spoil(bad)
			b := e.browser()
			wantError(t, b.register(bad, token, "Алиса", "Семья"), http.StatusBadRequest, "invalid")
			assert.Empty(t, b.cookie, "no cookie after a failed registration")
			accounts, err := e.st.Accounts().List(context.Background())
			require.NoError(t, err)
			assert.Empty(t, accounts)
			assert.Empty(t, e.st.Sessions().(fakeSessions).all())
			// The link still works.
			wantStatus(t, e.browser().register(newDevice(), token, "Алиса", "Семья"), http.StatusOK)
		})
	}
}

func TestRegisterFinishRefusals(t *testing.T) {
	ctx := context.Background()
	countPeople := func(t *testing.T, e *env) int {
		t.Helper()
		n := 0
		accounts, err := e.st.Accounts().List(ctx)
		require.NoError(t, err)
		for _, a := range accounts {
			people, err := e.st.People().ListByAccount(ctx, a.ID)
			require.NoError(t, err)
			n += len(people)
		}
		return n
	}

	t.Run("two registrations race for one link", func(t *testing.T) {
		e := newEnv(t)
		token := e.setupLink()
		b1, b2 := e.browser(), e.browser()
		d1, d2 := newDevice(), newDevice()
		o1 := b1.begin("/api/auth/register/begin", map[string]string{"token": token, "name": "Алиса", "account_name": "Семья"})
		o2 := b2.begin("/api/auth/register/begin", map[string]string{"token": token, "name": "Мэллори", "account_name": "Чужие"})
		wantStatus(t, b1.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": d1.create(t, o1)}), http.StatusOK)
		wantError(t, b2.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": d2.create(t, o2)}),
			http.StatusNotFound, "not_found")
		assert.Equal(t, 1, countPeople(t, e))
		assert.Empty(t, b2.cookie)
		wantError(t, b2.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token}), http.StatusNotFound, "not_found")
	})

	t.Run("the link expires between begin and finish", func(t *testing.T) {
		e := newEnv(t)
		token := e.setupLink()
		e.clock.Add(SetupLinkTTL - time.Minute)
		b, d := e.browser(), newDevice()
		opts := b.begin("/api/auth/register/begin", map[string]string{"token": token, "name": "Алиса", "account_name": "Семья"})
		e.clock.Add(2 * time.Minute)
		wantError(t, b.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": d.create(t, opts)}),
			http.StatusNotFound, "not_found")
		assert.Equal(t, 0, countPeople(t, e))
		assert.Empty(t, e.st.Sessions().(fakeSessions).all())
		assert.Empty(t, b.cookie)
	})

	t.Run("the same authenticator twice", func(t *testing.T) {
		e := newEnv(t)
		phone := newDevice()
		_, admin := e.superadmin(phone)
		inv, err := e.a.IssueInvite(ctx, core.InviteMember, core.AccountID(admin.Account.ID), "Белла", core.PersonID(admin.Person.ID))
		require.NoError(t, err)
		token := tokenOf(t, inv.URL, testOrigin+"/join#t=")
		copied := *phone // the same credential id again
		wantError(t, e.browser().register(&copied, token, "", ""), http.StatusConflict, "conflict")
		assert.Equal(t, 1, countPeople(t, e), "rolled back")
		// The invite was not used up.
		wantStatus(t, e.browser().do(http.MethodPost, "/api/auth/token", map[string]string{"token": token}), http.StatusOK)
		wantStatus(t, e.browser().register(newDevice(), token, "", ""), http.StatusOK)
	})

	t.Run("a superadmin appeared meanwhile", func(t *testing.T) {
		e := newEnv(t)
		token := e.setupLink()
		b, d := e.browser(), newDevice()
		opts := b.begin("/api/auth/register/begin", map[string]string{"token": token, "name": "Алиса", "account_name": "Семья"})
		require.NoError(t, e.st.Accounts().Create(ctx, core.Account{ID: "acc_otherotherotherot", Name: "Другие", CreatedAt: e.clock.Now()}))
		require.NoError(t, e.st.People().Create(ctx, core.Person{ID: "per_otherotherotherot", AccountID: "acc_otherotherotherot",
			Name: "Кто-то", Role: core.RoleOwner, Superadmin: true, CreatedAt: e.clock.Now()}))
		wantError(t, b.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": d.create(t, opts)}),
			http.StatusConflict, "conflict")
		assert.Equal(t, 1, countPeople(t, e))
	})

	t.Run("the account of an invite is deleted meanwhile", func(t *testing.T) {
		e := newEnv(t)
		_, admin := e.superadmin(newDevice())
		friends := core.Account{ID: "acc_friendsfriendsfr", Name: "Друзья", CreatedAt: e.clock.Now()}
		require.NoError(t, e.st.Accounts().Create(ctx, friends))
		inv, err := e.a.IssueInvite(ctx, core.InviteOwner, friends.ID, "Ира", core.PersonID(admin.Person.ID))
		require.NoError(t, err)
		b, d := e.browser(), newDevice()
		opts := b.begin("/api/auth/register/begin", map[string]string{"token": tokenOf(t, inv.URL, testOrigin+"/join#t=")})
		require.NoError(t, e.st.Accounts().Delete(ctx, friends.ID))
		wantError(t, b.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": d.create(t, opts)}),
			http.StatusNotFound, "not_found")
	})

	t.Run("a finish is single use", func(t *testing.T) {
		e := newEnv(t)
		token := e.setupLink()
		b, d := e.browser(), newDevice()
		opts := b.begin("/api/auth/register/begin", map[string]string{"token": token, "name": "Алиса", "account_name": "Семья"})
		finish := map[string]any{"credential": d.create(t, opts)}
		wantStatus(t, b.do(http.MethodPost, "/api/auth/register/finish", finish), http.StatusOK)
		wantError(t, e.browser().do(http.MethodPost, "/api/auth/register/finish", finish), http.StatusBadRequest, "invalid")
	})

	t.Run("the store fails", func(t *testing.T) {
		for _, method := range []string{"Tx", "Invites.Consume", "Passkeys.GetByCredentialID", "People.CountSuperadmins",
			"Accounts.Create", "People.Create", "Passkeys.Add", "Sessions.Create"} {
			t.Run(method, func(t *testing.T) {
				e := newEnv(t)
				token := e.setupLink()
				b, d := e.browser(), newDevice()
				opts := b.begin("/api/auth/register/begin", map[string]string{"token": token, "name": "Алиса", "account_name": "Семья"})
				e.st.setFail(method, assert.AnError)
				wantError(t, b.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": d.create(t, opts)}),
					http.StatusInternalServerError, "internal")
				assert.Empty(t, b.cookie)
				e.st.setFail(method, nil)
				assert.Equal(t, 0, countPeople(t, e), "rolled back")
				wantStatus(t, e.browser().register(newDevice(), token, "Алиса", "Семья"), http.StatusOK)
				assert.True(t, e.logged("auth: request failed"))
			})
		}
	})

	t.Run("garbage", func(t *testing.T) {
		e := newEnv(t)
		b := e.browser()
		for _, body := range []any{map[string]any{}, map[string]any{"credential": "x"}, map[string]any{"credential": map[string]any{"id": "x"}}} {
			wantError(t, b.do(http.MethodPost, "/api/auth/register/finish", body), http.StatusBadRequest, "invalid")
		}
	})
}
