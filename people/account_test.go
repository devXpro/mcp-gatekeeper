package people_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/people"
)

type accountResp struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Members []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Role     string `json:"role"`
		JoinedAt string `json:"joined_at"`
		You      bool   `json:"you"`
	} `json:"members"`
	Invites []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		ExpiresAt string `json:"expires_at"`
	} `json:"invites"`
	Modules []struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	} `json:"modules"`
}

func TestGetAccount(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	member := e.person(acc, "Bella", core.RoleMember, false)
	other, otherOwner := e.account("Nowakowie", "Jan", false)
	e.app.setModules(acc.ID, "notes", "photos")
	e.app.setModules(other.ID, "secret")
	inviter := fakeInviter{st: e.st}
	_, err := inviter.IssueInvite(t.Context(), core.InviteMember, acc.ID, "Babcia", owner.ID)
	require.NoError(t, err)
	_, err = inviter.IssueInvite(t.Context(), core.InviteMember, other.ID, "Stranger", otherOwner.ID)
	require.NoError(t, err)

	w := e.do(http.MethodGet, "/api/account", nil, e.session(owner, false))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.True(t, strings.HasPrefix(w.Body.String(), `{"id":"`+string(acc.ID)+`","name":"Kowalscy","members":[`),
		"the fields of this package come first: %s", w.Body.String())
	got := decodeJSON[accountResp](t, w)
	assert.Equal(t, string(acc.ID), got.ID)
	assert.Equal(t, "Kowalscy", got.Name)
	require.Len(t, got.Members, 2)
	assert.Equal(t, "Alice", got.Members[0].Name)
	assert.True(t, got.Members[0].You)
	assert.Equal(t, "owner", got.Members[0].Role)
	assert.False(t, got.Members[1].You)
	_, err = time.Parse(time.RFC3339, got.Members[0].JoinedAt)
	require.NoError(t, err)
	require.Len(t, got.Invites, 1)
	assert.Equal(t, "Babcia", got.Invites[0].Name)
	require.Len(t, got.Modules, 2, "the application's field")
	assert.Equal(t, "notes", got.Modules[0].ID)
	assert.NotContains(t, w.Body.String(), "Stranger")
	assert.NotContains(t, w.Body.String(), "secret")

	// A member sees the account, but not the pending invites.
	w = e.do(http.MethodGet, "/api/account", nil, e.session(member, false))
	got = decodeJSON[accountResp](t, w)
	assert.Empty(t, got.Invites)
	assert.NotNil(t, got.Invites)
	assert.Contains(t, w.Body.String(), `"invites":[]`)
	assert.True(t, got.Members[1].You)
}

// Without the application's fields the answer is this package's alone; a field that takes one of its names is a bug
// of the application, answered 500 without detail.
func TestGetAccountFields(t *testing.T) {
	e := newEnv(t, func(o *people.Options) { o.Fields = nil })
	_, owner := e.account("Kowalscy", "Alice", false)
	w := e.do(http.MethodGet, "/api/account", nil, e.session(owner, false))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "modules")

	e = newEnv(t)
	_, owner = e.account("Kowalscy", "Alice", false)
	e.app.fields = map[string]any{"members": "hijacked"}
	w = e.do(http.MethodGet, "/api/account", nil, e.session(owner, false))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "internal", errCode(t, w))
	assert.NotContains(t, w.Body.String(), "hijacked")
	assert.True(t, e.logs.Contains("members"), "the bug is logged")
}

func TestInvites(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	other, otherOwner := e.account("Nowakowie", "Jan", false)
	tok := e.session(owner, true)

	w := e.do(http.MethodPost, "/api/account/invites", map[string]string{"name": "  Bella "}, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	inv := decodeJSON[struct {
		ID        string `json:"id"`
		URL       string `json:"url"`
		ExpiresAt string `json:"expires_at"`
	}](t, w)
	assert.True(t, strings.HasPrefix(inv.URL, publicURL+"/join#t="), inv.URL)
	exp, err := time.Parse(time.RFC3339, inv.ExpiresAt)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(inviteTTL), exp, time.Minute)
	token := strings.TrimPrefix(inv.URL, publicURL+"/join#t=")

	// The invite is a member invite of the viewer's account, named as typed.
	stored, err := e.st.Invites().ListByAccount(t.Context(), acc.ID)
	require.NoError(t, err)
	require.Len(t, stored, 1)
	assert.Equal(t, core.InviteMember, stored[0].Kind)
	assert.Equal(t, "Bella", stored[0].Name)
	assert.Equal(t, owner.ID, stored[0].CreatedBy)

	// Bad names are refused, with the rule's words.
	for _, name := range []string{"", strings.Repeat("x", 41), "a\nb", `quo"te`} {
		w = e.do(http.MethodPost, "/api/account/invites", map[string]string{"name": name}, tok)
		assert.Equal(t, http.StatusBadRequest, w.Code, name)
		assert.Equal(t, "invalid", errCode(t, w))
		assert.Contains(t, w.Body.String(), `"message":"issue an invite: invalid name: it must`)
	}

	// Another account's owner cannot withdraw it; the owner can, once.
	w = e.do(http.MethodDelete, "/api/account/invites/"+inv.ID, nil, e.session(otherOwner, true))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "not_found", errCode(t, w))
	w = e.do(http.MethodDelete, "/api/account/invites/"+inv.ID, nil, tok)
	assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	w = e.do(http.MethodDelete, "/api/account/invites/"+inv.ID, nil, tok)
	assert.Equal(t, http.StatusNotFound, w.Code)

	assert.Equal(t, []string{"account.invite.create", "account.invite.revoke"}, e.auditActions(acc.ID))
	assert.Empty(t, e.auditActions(other.ID))
	for _, en := range e.st.AuditEntries() {
		assert.Equal(t, "198.51.100.7", en.IP, "the client's address")
		assert.NotContains(t, en.Target+strings.Join(mapValues(en.Detail), " "), token)
	}
	assert.False(t, e.logs.Contains(token), "the invite token never reaches a log")
}

func TestRemoveMember(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	member := e.person(acc, "Bella", core.RoleMember, false)
	memberTok := e.session(member, false)
	e.grant(member, core.AssistantClaude)
	other, _ := e.account("Nowakowie", "Jan", false)
	stranger := e.person(other, "Ania", core.RoleMember, false)
	sa := e.person(acc, "Root", core.RoleMember, true)
	tok := e.session(owner, true)

	cases := []struct {
		name   string
		target core.PersonID
		status int
		code   string
	}{
		{"yourself", owner.ID, http.StatusBadRequest, "invalid"},
		{"another account's member", stranger.ID, http.StatusNotFound, "not_found"},
		{"an unknown person", "per_unknown", http.StatusNotFound, "not_found"},
		{"a superadmin", sa.ID, http.StatusConflict, "conflict"},
	}
	for _, tc := range cases {
		w := e.do(http.MethodDelete, "/api/account/members/"+string(tc.target), nil, tok)
		assert.Equal(t, tc.status, w.Code, tc.name)
		assert.Equal(t, tc.code, errCode(t, w), tc.name)
	}
	_, err := e.st.People().Get(t.Context(), stranger.ID)
	require.NoError(t, err)

	w := e.do(http.MethodDelete, "/api/account/members/"+string(member.ID), nil, tok)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	_, err = e.st.People().Get(t.Context(), member.ID)
	require.ErrorIs(t, err, core.ErrNotFound)
	grants, err := e.st.OAuth().ListGrantsByAccount(t.Context(), acc.ID)
	require.NoError(t, err)
	assert.Empty(t, grants, "the member's grants went with them")
	assert.Equal(t, http.StatusUnauthorized, e.do(http.MethodGet, "/api/account", nil, memberTok).Code,
		"the member's sessions went with them")
	assert.Contains(t, e.auditActions(acc.ID), "account.member.remove")
}

type connResp struct {
	GrantID    string `json:"grant_id"`
	Resource   string `json:"resource"`
	Assistant  string `json:"assistant"`
	ClientName string `json:"client_name"`
	Label      string `json:"label"`
	Person     struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"person"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
}

func TestConnections(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	member := e.person(acc, "Bella", core.RoleMember, false)
	_, otherOwner := e.account("Nowakowie", "Jan", false)
	gOwner := e.grant(owner, core.AssistantChatGPT)
	gMember := e.grant(member, core.AssistantClaude)
	gOther := e.grant(otherOwner, core.AssistantClaude)
	ownerTok, memberTok := e.session(owner, false), e.session(member, false)

	w := e.do(http.MethodGet, "/api/account/connections", nil, ownerTok)
	list := decodeJSON[[]connResp](t, w)
	require.Len(t, list, 2, "the owner sees the whole account")
	assert.Equal(t, string(gOwner.ID), list[0].GrantID)
	assert.Equal(t, "notes", list[0].Resource)
	assert.Equal(t, "chatgpt", list[0].Assistant)
	assert.Equal(t, "chatgpt client", list[0].ClientName)
	assert.Equal(t, "Alice", list[0].Person.Name)
	assert.Nil(t, list[0].LastUsedAt)
	assert.NotContains(t, w.Body.String(), `"label"`, "a grant has no label")

	list = decodeJSON[[]connResp](t, e.do(http.MethodGet, "/api/account/connections", nil, memberTok))
	require.Len(t, list, 1, "a member sees only their own")
	assert.Equal(t, string(gMember.ID), list[0].GrantID)

	cases := []struct {
		name   string
		token  string
		grant  core.GrantID
		status int
	}{
		{"a member revoking the owner's", memberTok, gOwner.ID, http.StatusForbidden},
		{"another account's grant", ownerTok, gOther.ID, http.StatusNotFound},
		{"an unknown grant", ownerTok, "grt_unknown", http.StatusNotFound},
		{"a member revoking their own", memberTok, gMember.ID, http.StatusNoContent},
		{"the same again", memberTok, gMember.ID, http.StatusNotFound},
		{"the owner revoking any", ownerTok, gOwner.ID, http.StatusNoContent},
	}
	for _, tc := range cases {
		w := e.do(http.MethodDelete, "/api/account/connections/"+string(tc.grant), nil, tc.token)
		assert.Equal(t, tc.status, w.Code, tc.name+": "+w.Body.String())
	}
	assert.Equal(t, []core.GrantID{gMember.ID, gOwner.ID}, e.rev.Calls())
	g, err := e.st.OAuth().GetGrant(t.Context(), gOther.ID)
	require.NoError(t, err)
	assert.Nil(t, g.RevokedAt)
	assert.Equal(t, []string{"oauth.grant.revoke", "oauth.grant.revoke"}, e.auditActions(acc.ID))
}

// The application's own connections (Family Hub: legacy Site keys, T2.R L2) show among the grants: the owner sees
// all of them, a member only their own; revoking one goes to the application with its rules.
func TestApplicationConnections(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	bella := e.person(acc, "Bella", core.RoleMember, false)
	_, otherOwner := e.account("Nowakowie", "Jan", false)
	gOwner := e.grant(owner, core.AssistantChatGPT)
	used := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	key := func(id string, p core.Person, label string, at time.Time, last *time.Time) people.Connection {
		c := people.Connection{ID: id, ResourceID: "notes", Assistant: "site", ClientName: label, Label: label,
			PersonID: p.ID, CreatedAt: at, LastUsedAt: last}
		e.app.addKey(c)
		return c
	}
	kOwner := key("lk_0000000000000001", owner, "Alice's Site", t0, &used)
	kBella := key("lk_0000000000000002", bella, "Bella's Site", t0.Add(time.Hour), nil)
	kOther := key("lk_0000000000000003", otherOwner, "Jan's Site", t0, nil)
	ownerTok, bellaTok, otherTok := e.session(owner, false), e.session(bella, false), e.session(otherOwner, false)

	w := e.do(http.MethodGet, "/api/account/connections", nil, ownerTok)
	list := decodeJSON[[]connResp](t, w)
	require.Len(t, list, 3, "the grant and the account's two keys")
	assert.Equal(t, string(gOwner.ID), list[0].GrantID, "the grants first")
	assert.Empty(t, list[0].Label)
	for i, want := range []people.Connection{kOwner, kBella} {
		got := list[i+1]
		assert.Equal(t, want.ID, got.GrantID)
		assert.Equal(t, "site", got.Assistant)
		assert.Equal(t, "notes", got.Resource)
		assert.Equal(t, want.Label, got.Label)
		assert.Equal(t, want.Label, got.ClientName)
		assert.Equal(t, string(want.PersonID), got.Person.ID)
		assert.Equal(t, want.CreatedAt.Format("2006-01-02T15:04:05.000Z07:00"), got.CreatedAt)
	}
	assert.Equal(t, "Alice", list[1].Person.Name, "named by this package")
	require.NotNil(t, list[1].LastUsedAt)
	assert.Equal(t, "2026-11-19T08:00:00.000Z", *list[1].LastUsedAt)
	assert.Nil(t, list[2].LastUsedAt)
	assert.NotContains(t, w.Body.String(), "Jan's Site")

	list = decodeJSON[[]connResp](t, e.do(http.MethodGet, "/api/account/connections", nil, bellaTok))
	require.Len(t, list, 1, "a member sees only their own keys")
	assert.Equal(t, kBella.ID, list[0].GrantID)

	cases := []struct {
		name   string
		token  string
		id     string
		status int
	}{
		{"a member deleting their own key", bellaTok, kBella.ID, http.StatusForbidden},
		{"a member deleting the owner's key", bellaTok, kOwner.ID, http.StatusNotFound},
		{"another account's owner", otherTok, kBella.ID, http.StatusNotFound},
		{"the owner, another account's key", ownerTok, kOther.ID, http.StatusNotFound},
		{"an unknown id", ownerTok, "lk_zz", http.StatusNotFound},
		{"the owner", ownerTok, kBella.ID, http.StatusNoContent},
		{"the same again", ownerTok, kBella.ID, http.StatusNotFound},
	}
	for _, tc := range cases {
		w := e.do(http.MethodDelete, "/api/account/connections/"+tc.id, nil, tc.token)
		assert.Equal(t, tc.status, w.Code, tc.name+": "+w.Body.String())
		if tc.status == http.StatusNotFound {
			assert.Contains(t, w.Body.String(), `"message":"no such connection"`)
		}
	}
	assert.Empty(t, e.rev.Calls(), "no grant was revoked")
	assert.Equal(t, []string{"account.legacy-key.revoke"}, e.auditActions(acc.ID))
	_ = kOther
}

func TestDeleteAccount(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	member := e.person(acc, "Bella", core.RoleMember, false)
	other, otherOwner := e.account("Nowakowie", "Jan", false)
	e.app.setModules(acc.ID, "notes", "photos")
	e.grant(member, core.AssistantClaude)
	tok := e.session(owner, true)

	w := e.do(http.MethodDelete, "/api/account", map[string]string{"confirm": "kowalscy"}, tok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid", errCode(t, w))
	assert.Empty(t, e.app.erasures())

	// The application fails: 502 with its fields; the account stays.
	e.app.setEraseErr(moduleFailure("photos"))
	w = e.do(http.MethodDelete, "/api/account", map[string]string{"confirm": "Kowalscy"}, tok)
	require.Equal(t, http.StatusBadGateway, w.Code, w.Body.String())
	assert.Equal(t, `{"error":"upstream","message":"the module photos did not erase the account; try again `+
		`later","module":"photos"}`, w.Body.String(), "no trailing newline, as httpsec.WriteError")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Empty(t, w.Header().Get("Set-Cookie"))
	_, err := e.st.Accounts().Get(t.Context(), acc.ID)
	require.NoError(t, err)

	// The retry succeeds.
	e.app.setEraseErr(nil)
	w = e.do(http.MethodDelete, "/api/account", map[string]string{"confirm": "Kowalscy"}, tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{}`, w.Body.String())
	cookie := w.Header().Get("Set-Cookie")
	assert.True(t, strings.HasPrefix(cookie, cookieName+"=;"), cookie)
	for _, attr := range []string{"Path=/", "Max-Age=0", "HttpOnly", "Secure", "SameSite=Strict"} {
		assert.Contains(t, cookie, attr)
	}
	_, err = e.st.Accounts().Get(t.Context(), acc.ID)
	require.ErrorIs(t, err, core.ErrNotFound)
	_, err = e.st.People().Get(t.Context(), member.ID)
	require.ErrorIs(t, err, core.ErrNotFound)
	for _, er := range e.app.erasures() {
		assert.Equal(t, erasure{Account: acc.ID, Actor: owner.ID}, er, "only this account is erased")
	}

	// The other account is untouched; the deletion is a system audit entry.
	_, err = e.st.People().Get(t.Context(), otherOwner.ID)
	require.NoError(t, err)
	assert.Contains(t, e.auditActions(""), "account.delete")
	assert.Contains(t, e.auditActions(acc.ID), "account.delete.fail")
	for _, en := range e.st.AuditEntries() {
		if en.Action == "account.delete" {
			assert.Equal(t, "owner", en.Detail["by"])
			assert.Equal(t, "notes,photos", en.Detail["modules"], "sorted")
			assert.Empty(t, en.IP, "an owner's address stays out of the system audit")
		}
	}
	assert.Equal(t, http.StatusUnauthorized, e.do(http.MethodGet, "/api/account", nil, tok).Code)
	_ = other
}

func TestAccountAudit(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	other, _ := e.account("Nowakowie", "Jan", false)
	for i := range 5 {
		require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), AccountID: acc.ID,
			Actor: owner.ID, Action: "test.mine", Target: string(rune('a' + i))}))
	}
	require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), AccountID: other.ID,
		Action: "test.theirs"}))
	require.NoError(t, e.st.Audit().Append(t.Context(), core.AuditEntry{At: time.Now(), Action: "test.system"}))
	tok := e.session(owner, false)

	type entry struct {
		ID        string            `json:"id"`
		At        string            `json:"at"`
		Action    string            `json:"action"`
		Actor     *string           `json:"actor"`
		ActorName string            `json:"actor_name"`
		Target    string            `json:"target"`
		Detail    map[string]string `json:"detail"`
	}
	page := decodeJSON[[]entry](t, e.do(http.MethodGet, "/api/account/audit?limit=3", nil, tok))
	require.Len(t, page, 3)
	assert.Equal(t, "e", page[0].Target, "newest first")
	assert.Equal(t, "Alice", page[0].ActorName)
	next := decodeJSON[[]entry](t, e.do(http.MethodGet, "/api/account/audit?limit=3&before="+page[2].ID, nil, tok))
	require.Len(t, next, 2)
	assert.Equal(t, "b", next[0].Target)
	for _, en := range append(page, next...) {
		assert.Equal(t, "test.mine", en.Action)
	}
	for _, q := range []string{"?before=xyz", "?limit=0", "?limit=abc"} {
		w := e.do(http.MethodGet, "/api/account/audit"+q, nil, tok)
		assert.Equal(t, http.StatusBadRequest, w.Code, q)
		assert.Equal(t, "invalid", errCode(t, w))
	}
	// A limit above the cap is the cap.
	w := e.do(http.MethodGet, "/api/account/audit?limit=100000", nil, tok)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Len(t, decodeJSON[[]entry](t, w), 5)
}

// The body rules: JSON objects only, application/json, at most 256 KiB.
func TestBodyRules(t *testing.T) {
	e := newEnv(t)
	_, owner := e.account("Kowalscy", "Alice", false)
	tok := e.session(owner, true)
	send := func(body, contentType string) (int, string) {
		r := e.do(http.MethodPost, "/api/account/invites", nil, tok, func(r *http.Request) {
			r.Body = http.NoBody
			if body != "" {
				r.Body = readCloser(body)
				r.ContentLength = int64(len(body))
			}
			r.Header.Set("Content-Type", contentType)
		})
		return r.Code, r.Body.String()
	}
	cases := []struct {
		name, body, contentType string
		status                  int
	}{
		{"not JSON", `{"name":`, "application/json", http.StatusBadRequest},
		{"an array", `["x"]`, "application/json", http.StatusBadRequest},
		{"two values", `{"name":"a"}{"name":"b"}`, "application/json", http.StatusBadRequest},
		{"a wrong type", `{"name":1}`, "application/json", http.StatusBadRequest},
		{"another media type", `{"name":"a"}`, "text/plain", http.StatusUnsupportedMediaType},
		{"too large", `{"name":"` + strings.Repeat("x", 300<<10) + `"}`, "application/json",
			http.StatusRequestEntityTooLarge},
		{"empty: the name is missing", "", "application/json", http.StatusBadRequest},
	}
	for _, tc := range cases {
		status, body := send(tc.body, tc.contentType)
		assert.Equal(t, tc.status, status, tc.name+": "+body)
		assert.Contains(t, body, `"error":"invalid"`, tc.name)
	}
}

func readCloser(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
