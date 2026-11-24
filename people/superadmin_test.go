package people_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/people"
)

func TestAdminAccounts(t *testing.T) {
	e := newEnv(t)
	mine, root := e.account("Admins", "Root", true)
	acc, owner := e.account("Kowalscy", "Alice", false)
	e.person(acc, "Bella", core.RoleMember, false)
	e.app.setModules(acc.ID, "notes")
	tok := e.session(root, true)

	type row struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Members   int    `json:"members"`
		Modules   int    `json:"modules"`
		CreatedAt string `json:"created_at"`
	}
	w := e.do(http.MethodGet, "/api/admin/accounts", nil, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	rows := decodeJSON[[]row](t, w)
	require.Len(t, rows, 2)
	k := rows[1]
	assert.Equal(t, row{ID: string(acc.ID), Name: "Kowalscy", Members: 2, Modules: 1, CreatedAt: k.CreatedAt}, k)
	_, err := time.Parse(time.RFC3339, k.CreatedAt)
	require.NoError(t, err)
	assert.NotContains(t, w.Body.String(), "Bella", "counts only, never the members")
	assert.NotContains(t, w.Body.String(), "Alice")

	// Create an account: the superadmin gets the owner's invite and does not join it.
	w = e.do(http.MethodPost, "/api/admin/accounts", map[string]string{"name": "Nowakowie", "owner_name": "Jan"}, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	created := decodeJSON[struct {
		Account struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"account"`
		Invite struct {
			URL       string `json:"url"`
			ExpiresAt string `json:"expires_at"`
		} `json:"invite"`
	}](t, w)
	assert.Equal(t, "Nowakowie", created.Account.Name)
	assert.True(t, strings.HasPrefix(created.Invite.URL, publicURL+"/join#t="))
	invs, err := e.st.Invites().ListByAccount(t.Context(), core.AccountID(created.Account.ID))
	require.NoError(t, err)
	require.Len(t, invs, 1)
	assert.Equal(t, core.InviteOwner, invs[0].Kind)
	assert.Equal(t, "Jan", invs[0].Name)
	ps, err := e.st.People().ListByAccount(t.Context(), core.AccountID(created.Account.ID))
	require.NoError(t, err)
	assert.Empty(t, ps)
	assert.Contains(t, e.auditActions(""), "account.create")

	for _, body := range []map[string]string{{"name": "", "owner_name": "Jan"}, {"name": "X", "owner_name": ""},
		{"name": "a\tb", "owner_name": "Jan"}} {
		w = e.do(http.MethodPost, "/api/admin/accounts", body, tok)
		assert.Equal(t, http.StatusBadRequest, w.Code, body)
		assert.Equal(t, "invalid", errCode(t, w))
	}

	// A failing invite rolls the account back.
	before, err := e.st.Accounts().List(t.Context())
	require.NoError(t, err)
	e.st.Fail("Invites.Create", errors.New("disk full"))
	w = e.do(http.MethodPost, "/api/admin/accounts", map[string]string{"name": "Ghost", "owner_name": "Jan"}, tok)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "internal", errCode(t, w))
	assert.NotContains(t, w.Body.String(), "disk full")
	assert.True(t, e.logs.Contains("disk full"), "the cause is logged")
	e.st.Fail("Invites.Create", nil)
	after, err := e.st.Accounts().List(t.Context())
	require.NoError(t, err)
	assert.Len(t, after, len(before))

	// Delete: not your own, the confirm must match, then everything goes.
	w = e.do(http.MethodDelete, "/api/admin/accounts/"+string(mine.ID), map[string]string{"confirm": "Admins"}, tok)
	assert.Equal(t, http.StatusConflict, w.Code)
	w = e.do(http.MethodDelete, "/api/admin/accounts/acc_unknown", map[string]string{"confirm": "x"}, tok)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "no such account")
	w = e.do(http.MethodDelete, "/api/admin/accounts/"+string(acc.ID), map[string]string{"confirm": "Nowakowie"}, tok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	e.app.setEraseErr(moduleFailure("notes"))
	w = e.do(http.MethodDelete, "/api/admin/accounts/"+string(acc.ID), map[string]string{"confirm": "Kowalscy"}, tok)
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), `"module":"notes"`)
	e.app.setEraseErr(nil)
	w = e.do(http.MethodDelete, "/api/admin/accounts/"+string(acc.ID), map[string]string{"confirm": "Kowalscy"}, tok)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	assert.Empty(t, w.Header().Get("Set-Cookie"), "the superadmin stays signed in")
	_, err = e.st.Accounts().Get(t.Context(), acc.ID)
	require.ErrorIs(t, err, core.ErrNotFound)
	_, err = e.st.People().Get(t.Context(), owner.ID)
	require.ErrorIs(t, err, core.ErrNotFound)
	erased := e.app.erasures()
	assert.Equal(t, erasure{Account: acc.ID, Actor: root.ID}, erased[len(erased)-1], "the superadmin is the actor")
	for _, en := range e.st.AuditEntries() {
		if en.Action == "account.delete" {
			assert.Equal(t, "superadmin", en.Detail["by"])
			assert.Equal(t, "198.51.100.7", en.IP)
			assert.Empty(t, en.AccountID)
		}
	}
}

// Without SummaryFields the rows are this package's alone.
func TestAdminAccountsWithoutFields(t *testing.T) {
	e := newEnv(t, func(o *people.Options) { o.Summaries = nil })
	_, root := e.account("Admins", "Root", true)
	w := e.do(http.MethodGet, "/api/admin/accounts", nil, e.session(root, false))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "modules")
	assert.Contains(t, w.Body.String(), `"members":1`)
}

func TestSystemAudit(t *testing.T) {
	e := newEnv(t)
	_, root := e.account("Admins", "Root", true)
	acc, _ := e.account("Kowalscy", "Alice", false)
	require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), AccountID: acc.ID,
		Action: "test.account", Detail: map[string]string{"x": "private"}}))
	require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), Actor: root.ID,
		Action: "test.system"}))
	w := e.do(http.MethodGet, "/api/admin/audit", nil, e.session(root, false))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "test.system")
	assert.Contains(t, w.Body.String(), `"actor_name":"Root"`)
	assert.NotContains(t, w.Body.String(), "test.account")
	assert.NotContains(t, w.Body.String(), "private")
	for _, q := range []string{"?before=xyz", "?limit=-1"} {
		w = e.do(http.MethodGet, "/api/admin/audit"+q, nil, e.session(root, false))
		assert.Equal(t, http.StatusBadRequest, w.Code, q)
	}
}

// L9: the superadmin's audit view shows failed sign-ins without their address (they may be any account's); other
// system entries keep theirs.
func TestSystemAuditDropsFailedSignInAddresses(t *testing.T) {
	e := newEnv(t)
	_, root := e.account("Admins", "Root", true)
	require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), Action: "auth.login.fail",
		IP: "198.51.100.9"}))
	require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), Actor: root.ID,
		Action: "module.visibility", Target: "notes", IP: "198.51.100.1"}))
	rows := decodeJSON[[]auditIPRow](t, e.do(http.MethodGet, "/api/admin/audit", nil, e.session(root, false)))
	require.Len(t, rows, 2)
	assert.Equal(t, "module.visibility", rows[0].Action)
	assert.Equal(t, "198.51.100.1", rows[0].IP)
	assert.Equal(t, "auth.login.fail", rows[1].Action)
	assert.Empty(t, rows[1].IP)
	assert.Nil(t, rows[1].Actor, "no actor is null")
	assert.NotContains(t, e.do(http.MethodGet, "/api/admin/audit", nil, e.session(root, false)).Body.String(),
		"198.51.100.9")
}

// TestNoDataPath proves the isolation rule: the superadmin, whose own account works like anyone else's, never gets
// another account's members, invites, connections or audit from any route.
func TestNoDataPath(t *testing.T) {
	e := newEnv(t)
	mine, root := e.account("Admins", "Root", true)
	acc, owner := e.account("Kowalscy", "Alice", false)
	bella := e.person(acc, "Bella-Secret-Name", core.RoleMember, false)
	e.app.setModules(acc.ID, "module-secret")
	g := e.grant(bella, core.AssistantClaude)
	e.app.addKey(people.Connection{ID: "lk_00000000000000aa", ResourceID: "notes", Assistant: "site",
		ClientName: "Key-Secret", PersonID: bella.ID, CreatedAt: time.Now()})
	_, err := fakeInviter{st: e.st}.IssueInvite(t.Context(), core.InviteMember, acc.ID, "Invitee-Secret", owner.ID)
	require.NoError(t, err)
	require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), AccountID: acc.ID,
		Actor: bella.ID, Action: "test.private", Target: "audit-secret"}))
	tok := e.session(root, true)

	secrets := []string{"Bella-Secret-Name", "Invitee-Secret", "audit-secret", "test.private", "module-secret",
		"Key-Secret", string(bella.ID), string(g.ID)}
	gets := []string{"/api/account", "/api/account/connections", "/api/account/audit", "/api/admin/accounts",
		"/api/admin/audit"}
	for _, path := range gets {
		w := e.do(http.MethodGet, path, nil, tok)
		require.Equal(t, http.StatusOK, w.Code, path+": "+w.Body.String())
		for _, s := range secrets {
			assert.NotContains(t, w.Body.String(), s, path)
		}
	}
	// The account routes take no account id: a query or body naming the other account changes nothing.
	w := e.do(http.MethodGet, "/api/account?account="+string(acc.ID)+"&id="+string(acc.ID), nil, tok)
	assert.Equal(t, string(mine.ID), decodeJSON[accountResp](t, w).ID)
	// Writes cannot reach the other account's things either.
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodDelete, "/api/account/connections/"+string(g.ID), nil, tok).Code)
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodDelete, "/api/account/connections/lk_00000000000000aa", nil,
		tok).Code)
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodDelete, "/api/account/members/"+string(bella.ID), nil, tok).Code)
	invs, err := e.st.Invites().ListByAccount(t.Context(), acc.ID)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodDelete, "/api/account/invites/"+invs[0].ID, nil, tok).Code)
}
