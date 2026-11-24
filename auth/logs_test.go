package auth

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// No secret reaches a log line or an audit entry. A full run (failures included) is captured at every level, each
// record with all its attributes, and every cookie, link token and challenge the run saw is looked for,
// raw and as the hex of its sha256.
func TestNoSecretInLogsOrAudit(t *testing.T) {
	e := newEnv(t)
	phone := newDevice()

	// A registration that fails, then the real one.
	token := e.setupLink()
	bad := newDevice()
	bad.rp.Origin = "https://evil.example.com"
	wantError(t, e.browser().register(bad, token, "Алиса", "Семья"), http.StatusBadRequest, "invalid")
	owner := e.browser()
	rec := owner.register(phone, token, "Алиса", "Семья")
	wantStatus(t, rec, http.StatusOK)
	admin := decodeAs[signedIn](t, rec)

	// Sign-ins that fail and succeed, step-ups, passkeys, an invite, store failures, logout, reset-access.
	wantError(t, e.browser().login(newDevice()), http.StatusBadRequest, "invalid")
	wantStatus(t, e.browser().login(phone), http.StatusOK)
	wantStatus(t, owner.stepUp(phone), http.StatusOK)
	wantError(t, owner.stepUp(newDevice()), http.StatusBadRequest, "invalid")
	wantStatus(t, owner.addPasskey(newDevice(), "Mac mini"), http.StatusCreated)
	e.invited(newDevice(), core.InviteMember, core.AccountID(admin.Account.ID), "Белла", core.PersonID(admin.Person.ID))
	e.st.setFail("Sessions.Create", assert.AnError)
	wantError(t, e.browser().login(phone), http.StatusInternalServerError, "internal")
	e.st.setFail("Sessions.Create", nil)
	e.st.setFail("Sessions.Touch", assert.AnError)
	e.clock.Add(touchEvery)
	wantStatus(t, owner.do(http.MethodGet, "/api/me", nil), http.StatusOK)
	e.st.setFail("Sessions.Touch", nil)
	wantStatus(t, owner.do(http.MethodPost, "/api/auth/logout", nil), http.StatusNoContent)
	out, err := e.command("reset-access")
	require.NoError(t, err)
	wantStatus(t, e.browser().register(newDevice(), tokenOf(t, out, testOrigin+"/setup#t="), "", ""), http.StatusOK)

	e.secretsMu.Lock()
	secrets := append([]string(nil), e.secrets...)
	e.secretsMu.Unlock()
	require.Greater(t, len(secrets), 10)

	var lines []string
	for _, rec := range e.logs.Records() {
		lines = append(lines, fmt.Sprintf("%s %s %v", rec.Level, rec.Message, rec.Attrs))
	}
	require.NotEmpty(t, lines)
	audit := e.st.Audit().(fakeAudit).entries()
	for _, s := range secrets {
		hashed := hex.EncodeToString(hashToken(s))
		for _, line := range lines {
			require.NotContains(t, line, s)
			require.NotContains(t, line, hashed)
		}
		for _, a := range audit {
			require.NotContains(t, fmt.Sprintf("%+v", a), s)
		}
	}

	// What the log does say: which check failed and where from, not the values.
	assert.True(t, e.logged("auth: passkey rejected", "ceremony", "sign-in"))
	assert.True(t, e.logged("auth: request failed"))
}
