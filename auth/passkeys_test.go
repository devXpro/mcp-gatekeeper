package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestAddPasskey(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	phone := newDevice()
	b, admin := e.superadmin(phone)
	pid := core.PersonID(admin.Person.ID)
	mac := newDevice()

	// The begin excludes the person's passkeys.
	e.clock.Add(2 * time.Minute)
	opts := b.begin("/api/me/passkeys/begin", map[string]any{})
	var o struct {
		Exclude []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
		User struct {
			Name string `json:"name"`
		} `json:"user"`
	}
	require.NoError(t, json.Unmarshal(opts, &o))
	require.Len(t, o.Exclude, 1)
	assert.Equal(t, "Алиса", o.User.Name)
	answer := mac.create(t, opts)

	// Step-up ran out between begin and finish: 403, and the ceremony survives for the retry after a step-up.
	e.clock.Add(StepUpWindow - 2*time.Minute)
	finish := map[string]any{"credential": answer, "name": " Mac mini "}
	wantError(t, b.do(http.MethodPost, "/api/me/passkeys/finish", finish), http.StatusForbidden, "step_up_required")
	wantError(t, b.do(http.MethodPost, "/api/me/passkeys/begin", map[string]any{}), http.StatusForbidden, "step_up_required")
	wantStatus(t, b.stepUp(phone), http.StatusOK)
	rec := b.do(http.MethodPost, "/api/me/passkeys/finish", finish)
	wantStatus(t, rec, http.StatusCreated)
	pk := decodeAs[passkeyBody](t, rec)
	assert.Equal(t, "Mac mini", pk.Name)
	assert.Nil(t, pk.LastUsedAt)
	assert.Equal(t, rfc3339(e.clock.Now()), pk.CreatedAt)
	last := e.lastAudit()
	assert.Equal(t, "auth.passkey.add", last.Action)
	assert.Equal(t, pk.ID, last.Target)
	assert.Equal(t, map[string]string{"name": "Mac mini"}, last.Detail)
	assert.Equal(t, core.AccountID(admin.Account.ID), last.AccountID)

	// The new passkey signs in; the list shows both, oldest first, in the §5.9 shape.
	wantStatus(t, e.browser().login(mac), http.StatusOK)
	rec = b.do(http.MethodGet, "/api/me/passkeys", nil)
	wantStatus(t, rec, http.StatusOK)
	list := decodeAs[[]passkeyBody](t, rec)
	require.Len(t, list, 2)
	assert.Equal(t, "Mac", list[0].Name)
	assert.Equal(t, "Mac mini", list[1].Name)
	require.NotNil(t, list[1].LastUsedAt)
	var raw []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.ElementsMatch(t, []string{"id", "name", "created_at", "last_used_at"}, keys(raw[0]))

	// The same authenticator again, and a name that breaks the rule.
	opts = b.begin("/api/me/passkeys/begin", map[string]any{})
	wantError(t, b.do(http.MethodPost, "/api/me/passkeys/finish", map[string]any{"credential": mac.create(t, opts)}),
		http.StatusConflict, "conflict")
	opts = b.begin("/api/me/passkeys/begin", map[string]any{})
	tablet := newDevice()
	answer = tablet.create(t, opts)
	wantError(t, b.do(http.MethodPost, "/api/me/passkeys/finish", map[string]any{"credential": answer, "name": "a\tb"}),
		http.StatusBadRequest, "invalid")
	// The bad name did not burn the ceremony; with no name the passkey is named after the device.
	b.ua = safariIOS
	rec = b.do(http.MethodPost, "/api/me/passkeys/finish", map[string]any{"credential": answer})
	wantStatus(t, rec, http.StatusCreated)
	assert.Equal(t, "iPhone", decodeAs[passkeyBody](t, rec).Name)
	pks, err := e.st.Passkeys().ListByPerson(ctx, pid)
	require.NoError(t, err)
	assert.Len(t, pks, 3)

	// A ceremony of another session or person does not finish here.
	other := e.browser()
	wantStatus(t, other.login(phone), http.StatusOK)
	opts = b.begin("/api/me/passkeys/begin", map[string]any{})
	wantError(t, other.do(http.MethodPost, "/api/me/passkeys/finish", map[string]any{"credential": newDevice().create(t, opts)}),
		http.StatusBadRequest, "invalid")

	// Without a session.
	wantError(t, e.browser().do(http.MethodPost, "/api/me/passkeys/begin", map[string]any{}), http.StatusUnauthorized, "no_session")
}

func TestAddPasskeyRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(d *device)
	}{
		{"wrong RP ID", func(d *device) { d.rp.ID = "evil.example.com" }},
		{"wrong origin", func(d *device) { d.rp.Origin = "https://evil.example.com" }},
		{"user not verified", func(d *device) { d.auth.Options.UserNotVerified = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			b, _ := e.superadmin(newDevice())
			d := newDevice()
			tc.spoil(d)
			wantError(t, b.addPasskey(d, "Evil"), http.StatusBadRequest, "invalid")
			assert.Equal(t, "auth.register", e.lastAudit().Action, "nothing new was audited")
		})
	}

	for _, method := range []string{"Passkeys.GetByCredentialID", "Passkeys.Add"} {
		t.Run("the store fails: "+method, func(t *testing.T) {
			e := newEnv(t)
			b, _ := e.superadmin(newDevice())
			opts := b.begin("/api/me/passkeys/begin", map[string]any{})
			e.st.setFail(method, assert.AnError)
			wantError(t, b.do(http.MethodPost, "/api/me/passkeys/finish", map[string]any{"credential": newDevice().create(t, opts)}),
				http.StatusInternalServerError, "internal")
		})
	}

	t.Run("the store refuses a repeated credential id", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.superadmin(newDevice())
		opts := b.begin("/api/me/passkeys/begin", map[string]any{})
		e.st.setFail("Passkeys.Add", core.ErrConflict)
		wantError(t, b.do(http.MethodPost, "/api/me/passkeys/finish", map[string]any{"credential": newDevice().create(t, opts)}),
			http.StatusConflict, "conflict")
	})
}

func TestRenamePasskey(t *testing.T) {
	e := newEnv(t)
	b, admin := e.superadmin(newDevice())
	bella := e.invited(newDevice(), core.InviteMember, core.AccountID(admin.Account.ID), "Белла", core.PersonID(admin.Person.ID))
	own := decodeAs[[]passkeyBody](t, b.do(http.MethodGet, "/api/me/passkeys", nil))[0]
	hers := decodeAs[[]passkeyBody](t, bella.do(http.MethodGet, "/api/me/passkeys", nil))[0]

	rec := b.do(http.MethodPatch, "/api/me/passkeys/"+own.ID, map[string]string{"name": "  Рабочий Mac "})
	wantStatus(t, rec, http.StatusOK)
	got := decodeAs[passkeyBody](t, rec)
	assert.Equal(t, "Рабочий Mac", got.Name)
	assert.Equal(t, own.ID, got.ID)
	assert.Equal(t, "auth.passkey.rename", e.lastAudit().Action)
	n := len(e.actions())
	wantStatus(t, b.do(http.MethodPatch, "/api/me/passkeys/"+own.ID, map[string]string{"name": "Рабочий Mac"}), http.StatusOK)
	assert.Len(t, e.actions(), n, "no change, no audit entry")

	// Somebody else's passkey and an unknown one look the same; a bad name is refused.
	wantError(t, b.do(http.MethodPatch, "/api/me/passkeys/"+hers.ID, map[string]string{"name": "Мой"}), http.StatusNotFound, "not_found")
	wantError(t, b.do(http.MethodPatch, "/api/me/passkeys/pk_nonenonenonenone", map[string]string{"name": "Мой"}),
		http.StatusNotFound, "not_found")
	wantError(t, b.do(http.MethodPatch, "/api/me/passkeys/"+own.ID, map[string]string{"name": ""}), http.StatusBadRequest, "invalid")
	assert.Equal(t, hers.Name, decodeAs[[]passkeyBody](t, bella.do(http.MethodGet, "/api/me/passkeys", nil))[0].Name)

	e.st.setFail("Passkeys.Get", assert.AnError)
	wantError(t, b.do(http.MethodPatch, "/api/me/passkeys/"+own.ID, map[string]string{"name": "X"}),
		http.StatusInternalServerError, "internal")
	e.st.setFail("Passkeys.Get", nil)
	e.st.setFail("Passkeys.Rename", core.ErrNotFound)
	wantError(t, b.do(http.MethodPatch, "/api/me/passkeys/"+own.ID, map[string]string{"name": "X"}), http.StatusNotFound, "not_found")
	e.st.setFail("Passkeys.Rename", assert.AnError)
	wantError(t, b.do(http.MethodPatch, "/api/me/passkeys/"+own.ID, map[string]string{"name": "X"}),
		http.StatusInternalServerError, "internal")
}

func TestDeletePasskey(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	phone := newDevice()
	b, admin := e.superadmin(phone)
	pid := core.PersonID(admin.Person.ID)
	e.clock.Add(time.Second)
	wantStatus(t, b.addPasskey(newDevice(), "Mac mini"), http.StatusCreated)
	list := decodeAs[[]passkeyBody](t, b.do(http.MethodGet, "/api/me/passkeys", nil))
	require.Len(t, list, 2)
	require.Equal(t, "Mac mini", list[1].Name)

	// It needs step-up.
	e.clock.Add(StepUpWindow)
	wantError(t, b.do(http.MethodDelete, "/api/me/passkeys/"+list[1].ID, nil), http.StatusForbidden, "step_up_required")
	wantStatus(t, b.stepUp(phone), http.StatusOK)

	wantStatus(t, b.do(http.MethodDelete, "/api/me/passkeys/"+list[1].ID, nil), http.StatusNoContent)
	last := e.lastAudit()
	assert.Equal(t, "auth.passkey.delete", last.Action)
	assert.Equal(t, list[1].ID, last.Target)
	assert.Equal(t, map[string]string{"name": "Mac mini"}, last.Detail)
	wantError(t, b.do(http.MethodDelete, "/api/me/passkeys/"+list[1].ID, nil), http.StatusNotFound, "not_found")

	// Never the last passkey that can sign in.
	wantError(t, b.do(http.MethodDelete, "/api/me/passkeys/"+list[0].ID, nil), http.StatusConflict, "conflict")

	// A passkey of another domain does not count and can always go.
	_, cred, err := decodeCredential(mustPasskey(t, e, list[0].ID).Data)
	require.NoError(t, err)
	cred.ID = []byte("old-domain-credential")
	blob, err := encodeCredential("old.example.com", &cred)
	require.NoError(t, err)
	require.NoError(t, e.st.Passkeys().Add(ctx, core.Passkey{ID: "pk_oldoldoldoldoldol", PersonID: pid,
		CredentialID: cred.ID, Data: blob, Name: "Старый домен", CreatedAt: e.clock.Now()}))
	wantError(t, b.do(http.MethodDelete, "/api/me/passkeys/"+list[0].ID, nil), http.StatusConflict, "conflict")
	wantStatus(t, b.do(http.MethodDelete, "/api/me/passkeys/pk_oldoldoldoldoldol", nil), http.StatusNoContent)

	// Somebody else's passkey is not found.
	bella := e.invited(newDevice(), core.InviteMember, core.AccountID(admin.Account.ID), "Белла", pid)
	hers := decodeAs[[]passkeyBody](t, bella.do(http.MethodGet, "/api/me/passkeys", nil))[0]
	wantError(t, b.do(http.MethodDelete, "/api/me/passkeys/"+hers.ID, nil), http.StatusNotFound, "not_found")

	// The store's failures, with a second passkey so the last-passkey rule does not answer first.
	wantStatus(t, bella.addPasskey(newDevice(), "Второй"), http.StatusCreated)
	for _, method := range []string{"Passkeys.Get", "Passkeys.ListByPerson", "Passkeys.Delete"} {
		e.st.setFail(method, assert.AnError)
		wantError(t, bella.do(http.MethodDelete, "/api/me/passkeys/"+hers.ID, nil), http.StatusInternalServerError, "internal")
		e.st.setFail(method, nil)
	}
	e.st.setFail("Passkeys.Delete", core.ErrNotFound)
	wantError(t, bella.do(http.MethodDelete, "/api/me/passkeys/"+hers.ID, nil), http.StatusNotFound, "not_found")
}

// Two deletions at once cannot both pass the last-passkey check.
func TestDeletePasskeysConcurrently(t *testing.T) {
	e := newEnv(t)
	b, _ := e.superadmin(newDevice())
	wantStatus(t, b.addPasskey(newDevice(), "Второй"), http.StatusCreated)
	list := decodeAs[[]passkeyBody](t, b.do(http.MethodGet, "/api/me/passkeys", nil))
	require.Len(t, list, 2)
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		codes []int
	)
	for _, pk := range list {
		tab := *b // the same session; each copy keeps the cookie a deletion sends back
		wg.Go(func() {
			rec := tab.do(http.MethodDelete, "/api/me/passkeys/"+pk.ID, nil)
			mu.Lock()
			defer mu.Unlock()
			codes = append(codes, rec.Code)
		})
	}
	wg.Wait()
	// One deletion wins. The other must fail either way: 409 when it is checked before the winner commits (the
	// last passkey stays), or 401 when the winner has already replaced the session both copies started from.
	require.Len(t, codes, 2)
	slices.Sort(codes)
	assert.Equal(t, http.StatusNoContent, codes[0], "one deletion succeeds")
	assert.Contains(t, []int{http.StatusUnauthorized, http.StatusConflict}, codes[1], "the other never does")
	sessions := e.st.Sessions().(fakeSessions).all()
	require.Len(t, sessions, 1, "the deletion replaced the session")
	pks, err := e.st.Passkeys().ListByPerson(context.Background(), sessions[0].PersonID)
	require.NoError(t, err)
	assert.Len(t, pks, 1)
}

func TestListPasskeys(t *testing.T) {
	e := newEnv(t)
	b, admin := e.superadmin(newDevice())
	require.NoError(t, e.st.Passkeys().DeleteByPerson(context.Background(), core.PersonID(admin.Person.ID)))
	rec := b.do(http.MethodGet, "/api/me/passkeys", nil)
	wantStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `[]`, rec.Body.String(), "an empty list, not null")
	e.st.setFail("Passkeys.ListByPerson", assert.AnError)
	wantError(t, b.do(http.MethodGet, "/api/me/passkeys", nil), http.StatusInternalServerError, "internal")
	wantError(t, e.browser().do(http.MethodGet, "/api/me/passkeys", nil), http.StatusUnauthorized, "no_session")
}

func mustPasskey(t *testing.T, e *env, id string) core.Passkey {
	t.Helper()
	pk, err := e.st.Passkeys().Get(context.Background(), id)
	require.NoError(t, err)
	return pk
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
