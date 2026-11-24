package people_test

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/people/actorname"
)

type auditRow struct {
	ID        string            `json:"id"`
	Action    string            `json:"action"`
	Actor     *string           `json:"actor"`
	ActorName string            `json:"actor_name"`
	Detail    map[string]string `json:"detail"`
}

func hasKey(m map[string]string, k string) bool { _, ok := m[k]; return ok }

func rowOf(t *testing.T, rows []auditRow, action string) auditRow {
	t.Helper()
	for _, r := range rows {
		if r.Action == action {
			return r
		}
	}
	require.Failf(t, "no audit row", "action %s", action)
	return auditRow{}
}

// Entries this package writes carry the actor's name as it was; the API shows the current name, falls back to the
// stored one when the person is gone, and never lists the reserved key among the details.
func TestAccountAuditActorName(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	member := e.person(acc, "Bella", core.RoleMember, false)
	ownerTok := e.session(owner, true)

	// Written here: an invite by the owner; an entry of a member who is then removed.
	require.Equal(t, http.StatusOK, e.do(http.MethodPost, "/api/account/invites", map[string]string{"name": "Babcia"},
		ownerTok).Code)
	require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), AccountID: acc.ID,
		Actor: member.ID, Action: "test.member", Detail: map[string]string{actorname.Key: "Bella", "k": "v"}}))
	require.Equal(t, http.StatusNoContent, e.do(http.MethodDelete, "/api/account/members/"+string(member.ID), nil,
		ownerTok).Code)

	for _, e1 := range e.st.AuditEntries() {
		if e1.Action == "account.invite.create" || e1.Action == "account.member.remove" {
			assert.Equal(t, "Alice", e1.Detail[actorname.Key], e1.Action+" is stamped when it is written")
		}
	}

	rows := decodeJSON[[]auditRow](t, e.do(http.MethodGet, "/api/account/audit", nil, ownerTok))
	for _, action := range []string{"account.invite.create", "account.member.remove"} {
		r := rowOf(t, rows, action)
		assert.Equal(t, "Alice", r.ActorName, action)
		assert.False(t, hasKey(r.Detail, actorname.Key), action)
	}
	gone := rowOf(t, rows, "test.member")
	assert.Equal(t, "Bella", gone.ActorName, "the person is gone: the stored name")
	assert.Equal(t, map[string]string{"k": "v"}, gone.Detail)
	require.NotNil(t, gone.Actor)
	assert.Equal(t, string(member.ID), *gone.Actor)

	// A rename shows at once, whatever the entry stored.
	require.NoError(t, e.st.People().Rename(t.Context(), owner.ID, "Roma"))
	rows = decodeJSON[[]auditRow](t, e.do(http.MethodGet, "/api/account/audit", nil, ownerTok))
	assert.Equal(t, "Roma", rowOf(t, rows, "account.invite.create").ActorName)

	// An entry nobody named (written by another package, person gone): no name, and no detail key.
	require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), AccountID: acc.ID,
		Actor: "per_ghost", Action: "test.ghost"}))
	w := e.do(http.MethodGet, "/api/account/audit", nil, ownerTok)
	ghost := rowOf(t, decodeJSON[[]auditRow](t, w), "test.ghost")
	assert.Empty(t, ghost.ActorName)
	assert.NotNil(t, ghost.Detail)
	assert.Contains(t, w.Body.String(), `"detail":{}`, "detail is an object, never null")
}

// A person of another account is never named from the live store in an account's audit; only the name written
// into the entry itself is shown.
func TestAccountAuditDoesNotResolveForeignPeople(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	_, foreign := e.account("Nowakowie", "Jan", false)
	require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), AccountID: acc.ID,
		Actor: foreign.ID, Action: "test.foreign"}))
	rows := decodeJSON[[]auditRow](t, e.do(http.MethodGet, "/api/account/audit", nil, e.session(owner, false)))
	assert.Empty(t, rowOf(t, rows, "test.foreign").ActorName)
}

// System entries show the superadmin's own name; an owner who deleted their account is not named (T2.R L9).
func TestSystemAuditActorName(t *testing.T) {
	e := newEnv(t)
	_, root := e.account("Admins", "Root", true)
	acc, owner := e.account("Kowalscy", "Alice", false)
	rootTok := e.session(root, true)

	// The superadmin creates an account: a system entry with the current name.
	require.Equal(t, http.StatusOK, e.do(http.MethodPost, "/api/admin/accounts",
		map[string]string{"name": "Nowakowie", "owner_name": "Jan"}, rootTok).Code)
	// An owner deletes their account: the person is gone when the entry is read.
	w := e.do(http.MethodDelete, "/api/account", map[string]string{"confirm": acc.Name}, e.session(owner, true))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	rows := decodeJSON[[]auditRow](t, e.do(http.MethodGet, "/api/admin/audit", nil, rootTok))
	create := rowOf(t, rows, "account.create")
	assert.Equal(t, "Root", create.ActorName)
	assert.False(t, hasKey(create.Detail, actorname.Key))
	assert.NotEmpty(t, create.Detail["invite"])
	del := rowOf(t, rows, "account.delete")
	assert.Empty(t, del.ActorName, "an owner of another account is not named in a system entry (T2.R L9)")
	assert.False(t, hasKey(del.Detail, actorname.Key))
	assert.Equal(t, "owner", del.Detail["by"])
}

type auditIPRow struct {
	ID     string            `json:"id"`
	Action string            `json:"action"`
	Actor  *string           `json:"actor"`
	Target string            `json:"target"`
	Detail map[string]string `json:"detail"`
	IP     string            `json:"ip"`
}

// L4: the owner reads the whole account audit; a member only entries where they are the actor or the target, and
// no other person's address. Paging works across the entries a member does not see.
func TestMemberAuditView(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	bella := e.person(acc, "Bella", core.RoleMember, false)
	babcia := e.person(acc, "Babcia", core.RoleMember, false)
	add := func(actor core.PersonID, action, target, ip string) {
		require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), AccountID: acc.ID,
			Actor: actor, Action: action, Target: target, IP: ip}))
	}
	add(bella.ID, "auth.login", string(bella.ID), "198.51.100.2")
	add(owner.ID, "auth.login", string(owner.ID), "198.51.100.1")
	add(babcia.ID, "auth.login", string(babcia.ID), "198.51.100.3")
	add(owner.ID, "account.legacy-key.revoke", string(bella.ID), "198.51.100.1")
	add("", "admin.legacy-key.import", string(bella.ID), "")
	add(owner.ID, "module.enable", "notes", "198.51.100.1")

	rows := decodeJSON[[]auditIPRow](t, e.do(http.MethodGet, "/api/account/audit", nil, e.session(owner, false)))
	require.Len(t, rows, 6, "the owner sees everything")
	ips := map[string]bool{}
	for _, r := range rows {
		ips[r.IP] = true
	}
	assert.True(t, ips["198.51.100.2"] && ips["198.51.100.3"], "with everybody's addresses")

	bellaTok := e.session(bella, false)
	rows = decodeJSON[[]auditIPRow](t, e.do(http.MethodGet, "/api/account/audit", nil, bellaTok))
	require.Len(t, rows, 3, "%+v", rows)
	assert.Equal(t, "admin.legacy-key.import", rows[0].Action)
	assert.Equal(t, "account.legacy-key.revoke", rows[1].Action)
	assert.Empty(t, rows[1].IP, "the owner's address is not shown to a member")
	assert.Equal(t, "auth.login", rows[2].Action)
	assert.Equal(t, "198.51.100.2", rows[2].IP, "her own address is")
	for _, r := range rows {
		assert.NotContains(t, []string{"198.51.100.1", "198.51.100.3"}, r.IP)
	}

	// Paging across more than one store batch of other people's entries.
	for i := range 450 {
		add(owner.ID, "test.owner", strconv.Itoa(i), "198.51.100.1")
	}
	add(bella.ID, "test.bella", "new1", "198.51.100.2")
	add(bella.ID, "test.bella", "new2", "198.51.100.2")
	var got []string
	before := ""
	for range 10 {
		q := "/api/account/audit?limit=2"
		if before != "" {
			q += "&before=" + before
		}
		page := decodeJSON[[]auditIPRow](t, e.do(http.MethodGet, q, nil, bellaTok))
		for _, r := range page {
			got = append(got, r.Action+":"+r.Target)
		}
		if len(page) < 2 {
			break
		}
		before = page[len(page)-1].ID
	}
	assert.Equal(t, []string{"test.bella:new2", "test.bella:new1", "admin.legacy-key.import:" + string(bella.ID),
		"account.legacy-key.revoke:" + string(bella.ID), "auth.login:" + string(bella.ID)}, got)
}
