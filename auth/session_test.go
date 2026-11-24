package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestLoginRejected(t *testing.T) {
	stranger := func(*device) *device { return newDevice() } // a passkey this hub never saw
	for _, tc := range []struct {
		name  string
		spoil func(d *device) *device
	}{
		{"wrong origin", func(d *device) *device { d.rp.Origin = "https://evil.example.com"; return d }},
		{"wrong RP ID", func(d *device) *device { d.rp.ID = "evil.example.com"; return d }},
		{"user not verified", func(d *device) *device { d.auth.Options.UserNotVerified = true; return d }},
		{"user not present", func(d *device) *device { d.auth.Options.UserNotPresent = true; return d }},
		{"unknown passkey, unknown user", func(d *device) *device {
			s := stranger(d)
			s.auth.Options.UserHandle = []byte("per_nobodynobodynobo")
			return s
		}},
		{"unknown passkey of a known user", func(d *device) *device {
			s := stranger(d)
			s.auth.Options.UserHandle = d.auth.Options.UserHandle
			return s
		}},
		{"a user handle that is no person id", func(d *device) *device { d.auth.Options.UserHandle = []byte("admin"); return d }},
		{"no user handle", func(d *device) *device { d.auth.Options.UserHandle = nil; return d }},
		{"backup eligibility changed", func(d *device) *device {
			d.auth.Options.BackupEligible, d.auth.Options.BackupState = false, false
			return d
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			phone := newDevice()
			e.superadmin(phone)
			bad := *phone
			b := e.browser()
			b.ip = "203.0.113.7"
			wantError(t, b.login(tc.spoil(&bad)), http.StatusBadRequest, "invalid")
			assert.Empty(t, b.cookie)
			last := e.lastAudit()
			assert.Equal(t, core.AuditEntry{ID: last.ID, At: e.clock.Now(), Action: "auth.login.fail", IP: "203.0.113.7",
				Detail: map[string]string{"count": "1"}}, last,
				"a system entry: no account, no actor")
			assert.True(t, e.logged("auth: passkey rejected"))
			wantStatus(t, e.browser().login(phone), http.StatusOK)
		})
	}

	t.Run("a disabled person", func(t *testing.T) {
		e := newEnv(t)
		phone := newDevice()
		_, admin := e.superadmin(phone)
		require.NoError(t, e.st.People().Disable(context.Background(), core.PersonID(admin.Person.ID), e.clock.Now()))
		wantError(t, e.browser().login(phone), http.StatusBadRequest, "invalid")
		assert.Equal(t, "auth.login.fail", e.lastAudit().Action)
	})

	t.Run("the store fails looking the person up", func(t *testing.T) {
		e := newEnv(t)
		phone := newDevice()
		e.superadmin(phone)
		b := e.browser()
		opts := b.begin("/api/auth/login/begin", map[string]any{})
		e.st.setFail("People.Get", assert.AnError)
		wantError(t, b.do(http.MethodPost, "/api/auth/login/finish", map[string]any{"credential": phone.get(t, opts)}),
			http.StatusInternalServerError, "internal")
		assert.NotEqual(t, "auth.login.fail", e.lastAudit().Action, "a store failure says nothing about the client")
	})

	for _, method := range []string{"Passkeys.ListByPerson", "Accounts.Get", "Passkeys.Update", "Sessions.Create"} {
		t.Run("the store fails: "+method, func(t *testing.T) {
			e := newEnv(t)
			phone := newDevice()
			e.superadmin(phone)
			b := e.browser()
			opts := b.begin("/api/auth/login/begin", map[string]any{})
			e.st.setFail(method, assert.AnError)
			wantError(t, b.do(http.MethodPost, "/api/auth/login/finish", map[string]any{"credential": phone.get(t, opts)}),
				http.StatusInternalServerError, "internal")
			assert.Empty(t, b.cookie)
		})
	}
}

// A ceremony is single use, lives 5 minutes, and only its own endpoint (and session) can finish it.
func TestCeremonyRules(t *testing.T) {
	e := newEnv(t)
	phone := newDevice()
	owner, _ := e.superadmin(phone)
	b := e.browser()

	opts := b.begin("/api/auth/login/begin", map[string]any{})
	finish := map[string]any{"credential": phone.get(t, opts)}
	wantStatus(t, b.do(http.MethodPost, "/api/auth/login/finish", finish), http.StatusOK)
	wantError(t, b.do(http.MethodPost, "/api/auth/login/finish", finish), http.StatusBadRequest, "invalid")

	// A sign-in answer sent to the step-up endpoint does not finish anything, and does not burn the sign-in.
	opts = b.begin("/api/auth/login/begin", map[string]any{})
	answer := phone.get(t, opts)
	wantError(t, owner.do(http.MethodPost, "/api/auth/stepup/finish", map[string]any{"credential": answer}),
		http.StatusBadRequest, "invalid")
	wantStatus(t, b.do(http.MethodPost, "/api/auth/login/finish", map[string]any{"credential": answer}), http.StatusOK)

	// Expired after 5 minutes.
	opts = b.begin("/api/auth/login/begin", map[string]any{})
	answer = phone.get(t, opts)
	e.clock.Add(CeremonyTTL)
	wantError(t, b.do(http.MethodPost, "/api/auth/login/finish", map[string]any{"credential": answer}),
		http.StatusBadRequest, "invalid")

	// A step-up begun in one session cannot be finished in another one of the same person, and is not burnt by trying.
	other := e.browser()
	wantStatus(t, other.login(phone), http.StatusOK)
	opts = owner.begin("/api/auth/stepup/begin", map[string]any{})
	answer = phone.get(t, opts)
	wantError(t, other.do(http.MethodPost, "/api/auth/stepup/finish", map[string]any{"credential": answer}),
		http.StatusBadRequest, "invalid")
	wantStatus(t, owner.do(http.MethodPost, "/api/auth/stepup/finish", map[string]any{"credential": answer}), http.StatusOK)
}

// The signature counter of a hardware key must move forward; a repeat means a cloned key.
func TestCloneWarning(t *testing.T) {
	e := newEnv(t)
	key := newDevice()
	key.auth.Options.BackupEligible, key.auth.Options.BackupState = false, false
	key.cred.Counter = 5
	owner, _ := e.superadmin(key)
	wantError(t, e.browser().login(key), http.StatusBadRequest, "invalid")
	assert.True(t, e.logged("auth: passkey signature counter went backwards; possible cloned authenticator"))
	key.cred.Counter = 6
	wantStatus(t, e.browser().login(key), http.StatusOK)
	wantError(t, e.browser().login(key), http.StatusBadRequest, "invalid")
	e.clock.Add(StepUpWindow)
	wantError(t, owner.stepUp(key), http.StatusBadRequest, "invalid")
	assert.Equal(t, "auth.stepup.fail", e.lastAudit().Action)
	key.cred.Counter = 7
	wantStatus(t, owner.stepUp(key), http.StatusOK)
}

func TestStepUp(t *testing.T) {
	e := newEnv(t)
	phone := newDevice()
	b, admin := e.superadmin(phone)

	// Registering counts: dangerous actions pass for 5 minutes.
	wantStatus(t, b.do(http.MethodPost, "/test/danger", map[string]any{}), http.StatusNoContent)
	e.clock.Add(StepUpWindow - time.Millisecond)
	wantStatus(t, b.do(http.MethodPost, "/test/danger", map[string]any{}), http.StatusNoContent)
	e.clock.Add(time.Millisecond)
	wantError(t, b.do(http.MethodPost, "/test/danger", map[string]any{}), http.StatusForbidden, "step_up_required")

	// The options allow only the person's own passkeys, with user verification.
	opts := b.begin("/api/auth/stepup/begin", map[string]any{})
	var o struct {
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	}
	require.NoError(t, json.Unmarshal(opts, &o))
	assert.Equal(t, testHost, o.RPID)
	assert.Equal(t, "required", o.UserVerification)
	require.Len(t, o.AllowCredentials, 1)
	rec := b.do(http.MethodPost, "/api/auth/stepup/finish", map[string]any{"credential": phone.get(t, opts)})
	wantStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"step_up_until":"`+rfc3339(e.clock.Now().Add(StepUpWindow))+`"}`, rec.Body.String())
	wantStatus(t, b.do(http.MethodPost, "/test/danger", map[string]any{}), http.StatusNoContent)
	last := e.lastAudit()
	assert.Equal(t, "auth.stepup", last.Action)
	assert.Equal(t, core.AccountID(admin.Account.ID), last.AccountID)
	me := decodeAs[meBody](t, b.do(http.MethodGet, "/api/me", nil))
	assert.Equal(t, rfc3339(e.clock.Now().Add(StepUpWindow)), *me.StepUpUntil)

	// Without a session there is no step-up.
	wantError(t, e.browser().do(http.MethodPost, "/api/auth/stepup/begin", map[string]any{}), http.StatusUnauthorized, "no_session")
	wantError(t, e.browser().do(http.MethodPost, "/api/auth/stepup/finish", map[string]any{}), http.StatusUnauthorized, "no_session")
}

func TestStepUpRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("somebody else's passkey", func(t *testing.T) {
		e := newEnv(t)
		phone := newDevice()
		b, admin := e.superadmin(phone)
		bellaPhone := newDevice()
		e.invited(bellaPhone, core.InviteMember, core.AccountID(admin.Account.ID), "Белла", core.PersonID(admin.Person.ID))
		e.clock.Add(StepUpWindow)
		wantError(t, b.stepUp(bellaPhone), http.StatusBadRequest, "invalid")
		last := e.lastAudit()
		assert.Equal(t, "auth.stepup.fail", last.Action)
		assert.Equal(t, core.PersonID(admin.Person.ID), last.Actor, "in the account of the session")
		wantError(t, b.do(http.MethodPost, "/test/danger", map[string]any{}), http.StatusForbidden, "step_up_required")
	})

	t.Run("no passkey of this hub", func(t *testing.T) {
		e := newEnv(t)
		b, admin := e.superadmin(newDevice())
		require.NoError(t, e.st.Passkeys().DeleteByPerson(ctx, core.PersonID(admin.Person.ID)))
		wantError(t, b.do(http.MethodPost, "/api/auth/stepup/begin", map[string]any{}), http.StatusConflict, "conflict")
	})

	t.Run("the session ends during the ceremony", func(t *testing.T) {
		e := newEnv(t)
		phone := newDevice()
		b, _ := e.superadmin(phone)
		opts := b.begin("/api/auth/stepup/begin", map[string]any{})
		answer := phone.get(t, opts)
		cookie := b.cookie
		wantStatus(t, b.do(http.MethodPost, "/api/auth/logout", map[string]any{}), http.StatusNoContent)
		b.cookie = cookie
		wantError(t, b.do(http.MethodPost, "/api/auth/stepup/finish", map[string]any{"credential": answer}),
			http.StatusUnauthorized, "no_session")
	})

	for _, method := range []string{"Passkeys.ListByPerson", "Passkeys.Update", "Sessions.SetStepUp"} {
		t.Run("the store fails: "+method, func(t *testing.T) {
			e := newEnv(t)
			phone := newDevice()
			b, _ := e.superadmin(phone)
			opts := b.begin("/api/auth/stepup/begin", map[string]any{})
			e.st.setFail(method, assert.AnError)
			wantError(t, b.do(http.MethodPost, "/api/auth/stepup/finish", map[string]any{"credential": phone.get(t, opts)}),
				http.StatusInternalServerError, "internal")
		})
	}
	t.Run("the store fails at begin", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.superadmin(newDevice())
		e.st.setFail("Passkeys.ListByPerson", assert.AnError)
		wantError(t, b.do(http.MethodPost, "/api/auth/stepup/begin", map[string]any{}), http.StatusInternalServerError, "internal")
	})
}

func TestSessionLifetime(t *testing.T) {
	ctx := context.Background()

	t.Run("idle", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.superadmin(newDevice())
		e.clock.Add(IdleTimeout - time.Millisecond)
		wantStatus(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusOK) // touches
		e.clock.Add(IdleTimeout - time.Millisecond)
		wantStatus(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusOK)
		e.clock.Add(IdleTimeout)
		wantError(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusUnauthorized, "no_session")
		assert.Empty(t, e.st.Sessions().(fakeSessions).all(), "an expired session is deleted")
	})

	t.Run("absolute", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.superadmin(newDevice())
		for elapsed := time.Duration(0); elapsed+11*time.Hour < AbsoluteTimeout; elapsed += 11 * time.Hour {
			e.clock.Add(11 * time.Hour)
			wantStatus(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusOK)
		}
		e.clock.Add(11 * time.Hour)
		wantError(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusUnauthorized, "no_session")
	})

	t.Run("touched at most once a minute", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.superadmin(newDevice())
		start := e.clock.Now()
		lastSeen := func() time.Time {
			s := e.st.Sessions().(fakeSessions).all()
			require.Len(t, s, 1)
			return s[0].LastSeenAt
		}
		e.clock.Add(59 * time.Second)
		wantStatus(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusOK)
		assert.Equal(t, start, lastSeen())
		e.clock.Add(time.Second)
		wantStatus(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusOK)
		assert.Equal(t, e.clock.Now(), lastSeen())
		// A failing touch does not fail the request.
		e.clock.Add(time.Minute)
		e.st.setFail("Sessions.Touch", assert.AnError)
		wantStatus(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusOK)
		assert.True(t, e.logged("auth: cannot touch a session"))
	})

	t.Run("bad cookies", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.superadmin(newDevice())
		tampered := []byte(b.cookie)
		if tampered[0] == 'A' {
			tampered[0] = 'B'
		} else {
			tampered[0] = 'A'
		}
		for _, c := range []string{"", "nope", newToken(), string(tampered), b.cookie + "x"} {
			x := e.browser()
			x.cookie = c
			wantError(t, x.do(http.MethodGet, "/test/viewer", nil), http.StatusUnauthorized, "no_session")
		}
		wantStatus(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusOK)
	})

	for _, tc := range []struct {
		name string
		gone func(e *env, admin signedIn) error
	}{
		{"the person is deleted", func(e *env, admin signedIn) error {
			return e.st.People().Delete(ctx, core.PersonID(admin.Person.ID))
		}},
		{"the person is disabled", func(e *env, admin signedIn) error {
			return e.st.People().Disable(ctx, core.PersonID(admin.Person.ID), e.clock.Now())
		}},
		{"the account is deleted", func(e *env, admin signedIn) error {
			return e.st.Accounts().Delete(ctx, core.AccountID(admin.Account.ID))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			b, admin := e.superadmin(newDevice())
			require.NoError(t, tc.gone(e, admin))
			wantError(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusUnauthorized, "no_session")
			assert.Empty(t, e.st.Sessions().(fakeSessions).all())
		})
	}

	t.Run("a person whose account vanished alone", func(t *testing.T) {
		e := newEnv(t)
		b, admin := e.superadmin(newDevice())
		// No cascade in this fake path: the account row goes, the person stays.
		e.st.mu.Lock()
		delete(e.st.d.accounts, core.AccountID(admin.Account.ID))
		e.st.mu.Unlock()
		wantError(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusUnauthorized, "no_session")
	})

	t.Run("the store fails", func(t *testing.T) {
		for _, method := range []string{"Sessions.Get", "People.Get", "Accounts.Get"} {
			e := newEnv(t)
			b, _ := e.superadmin(newDevice())
			e.st.setFail(method, assert.AnError)
			wantError(t, b.do(http.MethodGet, "/test/viewer", nil), http.StatusInternalServerError, "internal")
			req := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/", nil)
			req.Header.Set("Cookie", cookieName+"="+b.cookie)
			_, err := e.a.Viewer(req)
			require.ErrorIs(t, err, assert.AnError, method)
			require.False(t, errors.Is(err, core.ErrNoSession))
		}
	})

	t.Run("sweep", func(t *testing.T) {
		e := newEnv(t)
		phone := newDevice()
		e.superadmin(phone)
		e.clock.Add(IdleTimeout - time.Minute)
		fresh := e.browser()
		wantStatus(t, fresh.login(phone), http.StatusOK)
		e.clock.Add(time.Minute + time.Millisecond)
		e.a.sweep(ctx)
		left := e.st.Sessions().(fakeSessions).all()
		require.Len(t, left, 1)
		assert.Equal(t, hashToken(fresh.cookie), left[0].IDHash)
		e.st.setFail("Sessions.DeleteExpired", assert.AnError)
		e.a.sweep(ctx)
		assert.True(t, e.logged("auth: cannot delete expired sessions"))
	})
}

func TestViewer(t *testing.T) {
	e := newEnv(t)
	b, admin := e.superadmin(newDevice())
	req := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/", nil)
	_, err := e.a.Viewer(req)
	require.ErrorIs(t, err, core.ErrNoSession)
	req.Header.Set("Cookie", cookieName+"="+b.cookie)
	v, err := e.a.Viewer(req)
	require.NoError(t, err)
	assert.Equal(t, core.PersonID(admin.Person.ID), v.Person.ID)
	assert.Equal(t, core.AccountID(admin.Account.ID), v.Account.ID)
	assert.Equal(t, hashToken(b.cookie), v.Session.IDHash)

	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

	// RequireStepUp without RequireViewer in front refuses.
	rec := httptest.NewRecorder()
	e.a.RequireStepUp(next).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://"+testHost+"/", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"no_session","message":"sign in first"}`, rec.Body.String())
	assert.False(t, reached)

	// RequireViewer twice looks the session up once.
	req = httptest.NewRequest(http.MethodGet, "https://"+testHost+"/", nil)
	req = req.WithContext(core.WithViewer(req.Context(), v))
	e.st.setFail("Sessions.Get", assert.AnError)
	e.a.RequireViewer(next).ServeHTTP(httptest.NewRecorder(), req)
	assert.True(t, reached)
}

func TestCSRF(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.superadmin(newDevice())
	for _, tc := range []struct {
		name   string
		mutate func(b *browser)
		ok     bool
	}{
		{"same origin", func(*browser) {}, true},
		{"no Origin header", func(b *browser) { b.origin = "" }, true},
		{"a same-origin fetch", func(b *browser) { b.header.Set("Sec-Fetch-Site", "same-origin") }, true},
		{"no X-Family-Hub", func(b *browser) { b.csrf = false }, false},
		{"X-Family-Hub: 0", func(b *browser) { b.csrf = false; b.header.Set(csrfHeader, "0") }, false},
		{"a foreign Origin", func(b *browser) { b.origin = "https://evil.example.com" }, false},
		{"Origin null", func(b *browser) { b.origin = "null" }, false},
		{"an http Origin", func(b *browser) { b.origin = "http://" + testHost }, false},
		{"two Origins", func(b *browser) {
			b.origin = ""
			b.header["Origin"] = []string{testOrigin, "https://evil.example.com"}
		}, false},
		{"a cross-site fetch", func(b *browser) { b.header.Set("Sec-Fetch-Site", "cross-site") }, false},
		{"a same-site fetch", func(b *browser) { b.header.Set("Sec-Fetch-Site", "same-site") }, false},
		{"a fetch with no site", func(b *browser) { b.header.Set("Sec-Fetch-Site", "none") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []string{"/api/auth/login/begin", "/test/public", "/test/write", "/api/auth/logout"} {
				b := e.browser()
				if path != "/api/auth/logout" { // a logout that passes would end the session the other cases use
					b.cookie = owner.cookie
				}
				tc.mutate(b)
				rec := b.do(http.MethodPost, path, map[string]any{})
				if tc.ok {
					assert.Less(t, rec.Code, 300, "%s: %s", path, rec.Body)
					continue
				}
				wantError(t, rec, http.StatusForbidden, "forbidden")
			}
		})
	}
	// Reads need no header.
	b := e.browser()
	b.cookie, b.origin = owner.cookie, "https://evil.example.com"
	wantStatus(t, b.do(http.MethodGet, "/api/me", nil), http.StatusOK)
	// A cross-site logout with the session's cookie is refused and does nothing.
	wantError(t, b.do(http.MethodPost, "/api/auth/logout", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, owner.do(http.MethodGet, "/api/me", nil), http.StatusOK)
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	b, _ := e.superadmin(newDevice())
	other := e.browser()
	rec := other.do(http.MethodPost, "/api/auth/logout", nil)
	wantStatus(t, rec, http.StatusNoContent)
	assert.Contains(t, rec.Header().Get("Set-Cookie"), cookieName+"=;", "the cookie is cleared without a session too")
	assert.Len(t, e.st.Sessions().(fakeSessions).all(), 1, "somebody else's session stays")

	e.st.setFail("Sessions.Delete", assert.AnError)
	wantError(t, b.do(http.MethodPost, "/api/auth/logout", nil), http.StatusInternalServerError, "internal")
	e.st.setFail("Sessions.Delete", nil)
	e.st.setFail("Sessions.Get", assert.AnError)
	wantError(t, b.do(http.MethodPost, "/api/auth/logout", nil), http.StatusInternalServerError, "internal")
	e.st.setFail("Sessions.Get", nil)
	wantStatus(t, b.do(http.MethodPost, "/api/auth/logout", nil), http.StatusNoContent)
	assert.Equal(t, "auth.logout", e.lastAudit().Action)
}

// Every endpoint refuses a body that is not a JSON object, before it does anything.
func TestBadBodies(t *testing.T) {
	e := newEnv(t)
	b, _ := e.superadmin(newDevice())
	for _, ep := range []struct{ method, path string }{
		{http.MethodPost, "/api/auth/token"},
		{http.MethodPost, "/api/auth/register/begin"},
		{http.MethodPost, "/api/auth/register/finish"},
		{http.MethodPost, "/api/auth/login/begin"},
		{http.MethodPost, "/api/auth/login/finish"},
		{http.MethodPost, "/api/auth/stepup/begin"},
		{http.MethodPost, "/api/auth/stepup/finish"},
		{http.MethodPost, "/api/me/passkeys/begin"},
		{http.MethodPost, "/api/me/passkeys/finish"},
		{http.MethodPatch, "/api/me/passkeys/pk_aaaaaaaaaaaaaaaa"},
	} {
		body := wantError(t, b.do(ep.method, ep.path, "[1]"), http.StatusBadRequest, "invalid")
		assert.Contains(t, body.Message, "JSON object", ep.path)
	}
}

// The store's failures in the begins and in token info are 500 internal, logged without detail for the client.
func TestBeginStoreFailures(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, method string
		prepare      func(e *env) (b *browser, path string, body any)
	}{
		{"token info: the invite", "Invites.Peek", func(e *env) (*browser, string, any) {
			return e.browser(), "/api/auth/token", map[string]string{"token": e.setupLink()}
		}},
		{"token info: the superadmins", "Accounts.List", func(e *env) (*browser, string, any) {
			return e.browser(), "/api/auth/token", map[string]string{"token": e.setupLink()}
		}},
		{"token info: the superadmin's account", "Accounts.Get", func(e *env) (*browser, string, any) {
			e.superadmin(newDevice())
			out, err := e.command("reset-access")
			require.NoError(t, err)
			return e.browser(), "/api/auth/token", map[string]string{"token": tokenOf(t, out, testOrigin+"/setup#t=")}
		}},
		{"token info: the invite's account", "Accounts.Get", func(e *env) (*browser, string, any) {
			_, admin := e.superadmin(newDevice())
			inv, err := e.a.IssueInvite(ctx, core.InviteMember, core.AccountID(admin.Account.ID), "Белла", core.PersonID(admin.Person.ID))
			require.NoError(t, err)
			return e.browser(), "/api/auth/token", map[string]string{"token": tokenOf(t, inv.URL, testOrigin+"/join#t=")}
		}},
		{"register: the superadmins", "Accounts.List", func(e *env) (*browser, string, any) {
			return e.browser(), "/api/auth/register/begin", map[string]string{"token": e.setupLink(), "name": "Алиса", "account_name": "Семья"}
		}},
		{"register: the superadmin's passkeys", "Passkeys.ListByPerson", func(e *env) (*browser, string, any) {
			e.superadmin(newDevice())
			out, err := e.command("reset-access")
			require.NoError(t, err)
			return e.browser(), "/api/auth/register/begin", map[string]string{"token": tokenOf(t, out, testOrigin+"/setup#t=")}
		}},
		{"register: the invite's account", "Accounts.Get", func(e *env) (*browser, string, any) {
			_, admin := e.superadmin(newDevice())
			inv, err := e.a.IssueInvite(ctx, core.InviteMember, core.AccountID(admin.Account.ID), "Белла", core.PersonID(admin.Person.ID))
			require.NoError(t, err)
			return e.browser(), "/api/auth/register/begin", map[string]string{"token": tokenOf(t, inv.URL, testOrigin+"/join#t=")}
		}},
		{"a new passkey: the person's passkeys", "Passkeys.ListByPerson", func(e *env) (*browser, string, any) {
			b, _ := e.superadmin(newDevice())
			return b, "/api/me/passkeys/begin", map[string]any{}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			b, path, body := tc.prepare(e)
			e.st.setFail(tc.method, assert.AnError)
			wantError(t, b.do(http.MethodPost, path, body), http.StatusInternalServerError, "internal")
			assert.True(t, e.logged("auth: request failed"))
		})
	}
}

// An audit entry that cannot be written, or a dead session that cannot be deleted, is logged and changes nothing
// for the client.
func TestSideWritesFail(t *testing.T) {
	e := newEnv(t)
	phone := newDevice()
	b, _ := e.superadmin(phone)
	e.st.setFail("Audit.Append", assert.AnError)
	wantStatus(t, e.browser().login(phone), http.StatusOK)
	assert.True(t, e.logged("auth: cannot write an audit entry"))
	e.st.setFail("Audit.Append", nil)

	e.clock.Add(IdleTimeout)
	e.st.setFail("Sessions.Delete", assert.AnError)
	wantError(t, b.do(http.MethodGet, "/api/me", nil), http.StatusUnauthorized, "no_session")
	assert.True(t, e.logged("auth: cannot delete a session"))
}

// A full pool of session ceremonies refuses another one with 429 instead of growing.
func TestCeremonyPoolFull(t *testing.T) {
	e := newEnv(t)
	b, _ := e.superadmin(newDevice())
	now := e.clock.Now()
	for i := range maxCeremonies {
		c := &ceremony{kind: kindStepUp, expires: now.Add(CeremonyTTL)}
		c.data.Challenge = "filler-" + strconv.Itoa(i)
		require.True(t, e.a.ceremonies.add(c, now))
	}
	wantError(t, b.do(http.MethodPost, "/api/auth/stepup/begin", map[string]any{}), http.StatusTooManyRequests, "rate_limited")
	wantError(t, b.do(http.MethodPost, "/api/me/passkeys/begin", map[string]any{}), http.StatusTooManyRequests, "rate_limited")
	// The public pool is apart: sign-in still begins.
	wantStatus(t, e.browser().do(http.MethodPost, "/api/auth/login/begin", map[string]any{}), http.StatusOK)
}
