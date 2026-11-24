package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/adminsock"
	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestSetupLinkCommand(t *testing.T) {
	e := newEnv(t)

	// A fresh hub: a newer link revokes the older one.
	older := e.setupLink()
	newer := e.setupLink()
	b := e.browser()
	wantError(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": older}), http.StatusNotFound, "not_found")
	wantStatus(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": newer}), http.StatusOK)

	out, err := e.command("setup-link")
	require.NoError(t, err)
	assert.Contains(t, out, "The setup link works once, until 2026-11-20T12:15:00.000Z (15m0s):\n\n  "+testOrigin+"/setup#t=")
	assert.Contains(t, out, "do not share it")
	token := tokenOf(t, out, testOrigin+"/setup#t=")
	last := e.lastAudit()
	assert.Equal(t, core.AuditEntry{ID: last.ID, At: e.clock.Now(), Action: "admin.setup-link",
		Detail: map[string]string{"expires_at": "2026-11-20T12:15:00.000Z"}}, last, "a system entry without the link")

	_, err = e.command("setup-link", "--force")
	require.ErrorIs(t, err, adminsock.ErrUsage)

	// A link lives 15 minutes.
	e.clock.Add(SetupLinkTTL)
	wantError(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token}), http.StatusNotFound, "not_found")

	// Once the superadmin has a passkey, there are no more setup links.
	e.superadmin(newDevice())
	_, err = e.command("setup-link")
	require.ErrorIs(t, err, core.ErrConflict)
	assert.Contains(t, err.Error(), "reset-access")

	e.st.setFail("Tx", assert.AnError)
	_, err = e.command("setup-link")
	require.ErrorIs(t, err, assert.AnError)
}

func TestSetupLinkStoreFailures(t *testing.T) {
	for _, method := range []string{"Accounts.List", "People.ListByAccount", "Invites.RevokeKind", "Invites.Create"} {
		t.Run(method, func(t *testing.T) {
			e := newEnv(t)
			e.superadmin(newDevice())
			ctx := context.Background()
			require.NoError(t, e.st.Passkeys().DeleteByPerson(ctx, superadminOf(t, e).ID)) // links are allowed again
			e.st.setFail(method, assert.AnError)
			_, err := e.command("setup-link")
			require.ErrorIs(t, err, assert.AnError)
		})
	}
	t.Run("Passkeys.ListByPerson", func(t *testing.T) {
		e := newEnv(t)
		e.superadmin(newDevice())
		e.st.setFail("Passkeys.ListByPerson", assert.AnError)
		_, err := e.command("setup-link")
		require.ErrorIs(t, err, assert.AnError)
	})
}

func superadminOf(t *testing.T, e *env) core.Person {
	t.Helper()
	sas, err := superadmins(context.Background(), e.st)
	require.NoError(t, err)
	require.NotEmpty(t, sas)
	return sas[0]
}

func TestResetAccess(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	phone := newDevice()
	owner, admin := e.superadmin(phone)
	second := e.browser()
	wantStatus(t, second.login(phone), http.StatusOK)
	// Another family keeps its passkeys and sessions.
	friends := core.Account{ID: "acc_friendsfriendsfr", Name: "Друзья", CreatedAt: e.clock.Now()}
	require.NoError(t, e.st.Accounts().Create(ctx, friends))
	iraPhone := newDevice()
	ira := e.invited(iraPhone, core.InviteOwner, friends.ID, "Ира", core.PersonID(admin.Person.ID))

	out, err := e.command("reset-access")
	require.NoError(t, err)
	assert.Contains(t, out, "Wiped the passkeys and sessions of Алиса ("+admin.Person.ID+").\n")
	token := tokenOf(t, out, testOrigin+"/setup#t=")

	// The superadmin is out everywhere, Ira is not.
	wantError(t, owner.do(http.MethodGet, "/api/me", nil), http.StatusUnauthorized, "no_session")
	wantError(t, second.do(http.MethodGet, "/api/me", nil), http.StatusUnauthorized, "no_session")
	wantError(t, e.browser().login(phone), http.StatusBadRequest, "invalid")
	wantStatus(t, ira.do(http.MethodGet, "/api/me", nil), http.StatusOK)
	wantStatus(t, e.browser().login(iraPhone), http.StatusOK)
	pks, err := e.st.Passkeys().ListByPerson(ctx, core.PersonID(admin.Person.ID))
	require.NoError(t, err)
	assert.Empty(t, pks)
	var reset core.AuditEntry
	for _, a := range e.st.Audit().(fakeAudit).entries() {
		if a.Action == "admin.reset-access" {
			reset = a
		}
	}
	assert.Equal(t, map[string]string{"people": "1", "passkeys": "1", "grants": "0", "legacy_keys": "0", "invites": "0"},
		reset.Detail)
	assert.Empty(t, reset.AccountID)

	// The new link names the superadmin and their family.
	b := e.browser()
	rec := b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token})
	wantStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"kind":"setup","name":"Алиса","account_name":"Семья"}`, rec.Body.String())

	// It adds a passkey to the same superadmin; the names may change, the people and accounts stay.
	laptop := newDevice()
	rec = b.register(laptop, token, "Аля", "")
	wantStatus(t, rec, http.StatusOK)
	got := decodeAs[signedIn](t, rec)
	assert.Equal(t, personBody{ID: admin.Person.ID, Name: "Аля", Role: "owner", Superadmin: true}, got.Person)
	assert.Equal(t, admin.Account, got.Account)
	accounts, err := e.st.Accounts().List(ctx)
	require.NoError(t, err)
	assert.Len(t, accounts, 2)
	assert.Equal(t, "auth.register", e.lastAudit().Action)
	wantStatus(t, e.browser().login(laptop), http.StatusOK)

	// And the links stop again.
	_, err = e.command("setup-link")
	require.ErrorIs(t, err, core.ErrConflict)
	_, err = e.command("reset-access", "now")
	require.ErrorIs(t, err, adminsock.ErrUsage)
}

func TestResetAccessRenamesTheFamily(t *testing.T) {
	e := newEnv(t)
	_, admin := e.superadmin(newDevice())
	out, err := e.command("reset-access")
	require.NoError(t, err)
	token := tokenOf(t, out, testOrigin+"/setup#t=")
	rec := e.browser().register(newDevice(), token, "", "Наша семья")
	wantStatus(t, rec, http.StatusOK)
	got := decodeAs[signedIn](t, rec)
	assert.Equal(t, "Алиса", got.Person.Name, "no name keeps the name")
	assert.Equal(t, accountBody{ID: admin.Account.ID, Name: "Наша семья"}, got.Account)
}

func TestResetAccessOnAFreshHub(t *testing.T) {
	e := newEnv(t)
	out, err := e.command("reset-access")
	require.NoError(t, err)
	assert.Contains(t, out, "The hub has no superadmin yet: nothing to wipe.")
	token := tokenOf(t, out, testOrigin+"/setup#t=")
	wantStatus(t, e.browser().register(newDevice(), token, "Алиса", "Семья"), http.StatusOK)

	for _, method := range []string{"Passkeys.ListByPerson", "Passkeys.DeleteByPerson", "Sessions.DeleteByPerson",
		"OAuth.ListGrantsByAccount", "Modules.List", "Accounts.List", "Invites.ListByAccount"} {
		e.st.setFail(method, assert.AnError)
		_, err := e.command("reset-access")
		require.ErrorIs(t, err, assert.AnError, method)
		e.st.setFail(method, nil)
	}
	pks, err := e.st.Passkeys().ListByPerson(context.Background(), superadminOf(t, e).ID)
	require.NoError(t, err)
	assert.Len(t, pks, 1, "a failed reset changed nothing")
}

// A disabled superadmin is still the superadmin: no setup link replaces them, and reset-access changes nothing.
func TestDisabledSuperadmin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, admin := e.superadmin(newDevice())
	require.NoError(t, e.st.People().Disable(ctx, core.PersonID(admin.Person.ID), e.clock.Now()))
	_, err := e.command("setup-link")
	require.ErrorIs(t, err, core.ErrConflict)
	assert.Contains(t, err.Error(), "disabled")
	_, err = e.command("reset-access")
	require.ErrorIs(t, err, core.ErrConflict)
	pks, err := e.st.Passkeys().ListByPerson(ctx, core.PersonID(admin.Person.ID))
	require.NoError(t, err)
	assert.Len(t, pks, 1, "rolled back")

	// A setup link made before the superadmin was disabled cannot be used either.
	e2 := newEnv(t)
	_, admin2 := e2.superadmin(newDevice())
	out, err := e2.command("reset-access")
	require.NoError(t, err)
	token := tokenOf(t, out, testOrigin+"/setup#t=")
	b := e2.browser()
	opts := b.begin("/api/auth/register/begin", map[string]string{"token": token})
	require.NoError(t, e2.st.People().Disable(ctx, core.PersonID(admin2.Person.ID), e2.clock.Now()))
	wantError(t, b.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": newDevice().create(t, opts)}),
		http.StatusNotFound, "not_found")
	wantError(t, b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": token}), http.StatusConflict, "conflict")
	wantError(t, b.do(http.MethodPost, "/api/auth/register/begin", map[string]string{"token": token}), http.StatusConflict, "conflict")
}

// An application without reset steps (Homie): the summary and the audit name only auth's own counts.
func TestResetAccessWithoutSteps(t *testing.T) {
	e := newEnv(t)
	e.a.steps = nil
	_, admin := e.superadmin(newDevice())
	out, err := e.command("reset-access")
	require.NoError(t, err)
	assert.Contains(t, out, "Wiped the passkeys and sessions of Алиса ("+admin.Person.ID+").\n"+
		"Ended 1 passkeys, 0 connectors (OAuth grants) and 0 open invites.\n")
	assert.Equal(t, map[string]string{"people": "1", "passkeys": "1", "grants": "0", "invites": "0"}, e.lastAudit().Detail)
}

// A reset step sees every superadmin inside the transaction, and its failure rolls the whole reset back.
func TestResetStepRunsInTheTransaction(t *testing.T) {
	e := newEnv(t)
	_, admin := e.superadmin(newDevice())
	var seen []core.PersonID
	e.a.steps = []ResetStep{{Key: "things", Phrase: "things", Run: func(ctx context.Context, p core.Person, _ time.Time) (int, error) {
		require.True(t, e.st.inTx(ctx), "the step runs in reset-access's transaction")
		pks, err := e.st.Passkeys().ListByPerson(ctx, p.ID)
		require.NoError(t, err)
		assert.Empty(t, pks, "the passkeys are already gone inside the transaction")
		seen = append(seen, p.ID)
		return 3, nil
	}}}
	out, err := e.command("reset-access")
	require.NoError(t, err)
	assert.Equal(t, []core.PersonID{core.PersonID(admin.Person.ID)}, seen)
	assert.Contains(t, out, "Ended 1 passkeys, 0 connectors (OAuth grants), 3 things and 0 open invites.\n")
	assert.Equal(t, "3", e.lastAudit().Detail["things"])

	// The superadmin registers again; a failing step then changes nothing.
	wantStatus(t, e.browser().register(newDevice(), tokenOf(t, out, testOrigin+"/setup#t="), "", ""), http.StatusOK)
	e.a.steps[0].Run = func(context.Context, core.Person, time.Time) (int, error) { return 0, assert.AnError }
	_, err = e.command("reset-access")
	require.ErrorIs(t, err, assert.AnError)
	pks, err := e.st.Passkeys().ListByPerson(context.Background(), core.PersonID(admin.Person.ID))
	require.NoError(t, err)
	assert.Len(t, pks, 1, "rolled back")
}
