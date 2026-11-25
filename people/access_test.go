package people_test

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/people"
	"github.com/devXpro/mcp-gatekeeper/people/actorname"
)

// ts is t as this package answers times.
func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z07:00") }

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (e *env) setAccess(p core.Person, until *time.Time, perms ...string) {
	e.t.Helper()
	require.NoError(e.t, e.st.People().SetAccess(e.t.Context(), p.ID, until, perms))
}

func (e *env) stored(p core.Person) core.Person {
	e.t.Helper()
	got, err := e.st.People().Get(e.t.Context(), p.ID)
	require.NoError(e.t, err)
	return got
}

// Family Hub runs with no catalog and no co-owners: every answer of the people API keeps its bytes, and the new
// fields are refused rather than ignored, so a term can never be silently dropped.
func TestFamilyHubBytes(t *testing.T) {
	e := newEnv(t, func(o *people.Options) { o.Fields = nil })
	acc, owner := e.account("Home", "Alice", false)
	member := e.person(acc, "Bob", core.RoleMember, false)
	tok := e.session(owner, true)

	w := e.do(http.MethodPost, "/api/account/invites", map[string]any{"name": "Carol", "role": nil,
		"access_until": nil, "permissions": nil}, tok)
	require.Equal(t, http.StatusOK, w.Code, "a null is a field left out: %s", w.Body.String())
	invs, err := e.st.Invites().ListByAccount(t.Context(), acc.ID)
	require.NoError(t, err)
	require.Len(t, invs, 1)
	inv := invs[0]
	assert.Nil(t, inv.AccessUntil)
	assert.Nil(t, inv.Permissions)

	w = e.do(http.MethodGet, "/api/account", nil, tok)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"id":"`+string(acc.ID)+`","name":"Home","members":[`+
		`{"id":"`+string(owner.ID)+`","name":"Alice","role":"owner","joined_at":"`+ts(owner.CreatedAt)+`","you":true},`+
		`{"id":"`+string(member.ID)+`","name":"Bob","role":"member","joined_at":"`+ts(member.CreatedAt)+`","you":false}],`+
		`"invites":[{"id":"`+inv.ID+`","name":"Carol","expires_at":"`+ts(inv.ExpiresAt)+`"}]}`, w.Body.String())

	future := rfc(time.Now().Add(time.Hour))
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"a term", map[string]any{"name": "Dan", "access_until": future},
			`{"error":"invalid","message":"this application offers no access terms"}`},
		{"permissions", map[string]any{"name": "Dan", "permissions": []string{"all"}},
			`{"error":"invalid_permission","message":"this application offers no permissions"}`},
		{"no permissions", map[string]any{"name": "Dan", "permissions": []string{}},
			`{"error":"invalid_permission","message":"this application offers no permissions"}`},
		{"a role", map[string]any{"name": "Dan", "role": "member"},
			`{"error":"invalid","message":"role is not offered here"}`},
		{"an owner", map[string]any{"name": "Dan", "role": "owner"},
			`{"error":"invalid","message":"role is not offered here"}`},
	}
	for _, tc := range cases {
		w := e.do(http.MethodPost, "/api/account/invites", tc.body, tok)
		assert.Equal(t, http.StatusBadRequest, w.Code, tc.name)
		assert.Equal(t, tc.want, w.Body.String(), tc.name)
	}
	invs, err = e.st.Invites().ListByAccount(t.Context(), acc.ID)
	require.NoError(t, err)
	assert.Len(t, invs, 1, "no refused invite was made")

	// The new routes are not there: the mux answers as it did.
	w = e.do(http.MethodPatch, "/api/account/members/"+string(member.ID), map[string]any{"access_until": nil}, tok)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Equal(t, "DELETE", w.Header().Get("Allow"))
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, "/api/account/permissions", nil, tok).Code)

	// The audit entries carry no new detail.
	require.Equal(t, http.StatusNoContent,
		e.do(http.MethodDelete, "/api/account/members/"+string(member.ID), nil, tok).Code)
	for _, en := range e.st.AuditEntries() {
		assert.Equal(t, map[string]string{actorname.Key: "Alice"}, en.Detail, en.Action)
	}
	assert.Equal(t, []string{people.ActionInviteCreate, people.ActionMemberRemove}, e.auditActions(acc.ID))
}

func TestNewChecksTheNewOptions(t *testing.T) {
	e := newEnv(t)
	base := func() people.Options {
		return people.Options{Site: coreSite(), Brand: brand, Sessions: fakeSessions{st: e.st}, Store: e.st,
			Inviter: fakeInviter{st: e.st}, Revoker: e.rev, NormalizeName: normalizeName}
	}
	o := base()
	o.Permissions = newCatalog()
	o.Inviter = plainInviter{fakeInviter{st: e.st}}
	_, err := people.New(o)
	require.ErrorContains(t, err, "AccessInviter", "a term must never be dropped on the way to the invite")

	o = base()
	o.Site.ClientIP = ""
	_, err = people.New(o)
	require.ErrorContains(t, err, "client address mode")

	o = base()
	o.Site.PublicURL = "http://hub.test"
	_, err = people.New(o)
	require.ErrorContains(t, err, "plain http")

	o = base()
	o.Permissions, o.CoOwners, o.SingleAccount = newCatalog(), true, true
	_, err = people.New(o)
	require.NoError(t, err)
}

func TestInviteTermsAndPermissions(t *testing.T) {
	cat := newCatalog()
	e := newEnv(t, withCatalog(cat))
	acc, owner := e.account("Home", "Alice", false)
	tok := e.session(owner, true)
	now := time.Now().UTC()

	cases := []struct {
		name   string
		body   map[string]any
		status int
		code   string
		msg    string
	}{
		{"an unknown permission", map[string]any{"name": "Bob", "permissions": []string{"plugin:tv", "plugin:oven"}},
			http.StatusBadRequest, "invalid_permission", "a permission is not one this application offers"},
		{"a term in the past", map[string]any{"name": "Bob", "access_until": rfc(now.Add(-time.Minute))},
			http.StatusBadRequest, "invalid", "access_until must be in the future"},
		{"a term over a year away", map[string]any{"name": "Bob", "access_until": rfc(now.AddDate(1, 0, 1))},
			http.StatusBadRequest, "invalid", "access_until must be at most one year away"},
		{"a term that is not RFC 3339", map[string]any{"name": "Bob", "access_until": "tomorrow"},
			http.StatusBadRequest, "invalid", "access_until must be an RFC 3339 time"},
		{"a term of the wrong type", map[string]any{"name": "Bob", "access_until": 1},
			http.StatusBadRequest, "invalid", "access_until has the wrong type"},
		{"permissions of the wrong type", map[string]any{"name": "Bob", "permissions": "plugin:tv"},
			http.StatusBadRequest, "invalid", "permissions has the wrong type"},
		{"a role without co-owners", map[string]any{"name": "Bob", "role": "owner"},
			http.StatusBadRequest, "invalid", "role is not offered here"},
		{"a bad name comes first", map[string]any{"name": "", "permissions": []string{"plugin:oven"}},
			http.StatusBadRequest, "invalid", "issue an invite: invalid name: it must be 1 to 40 characters"},
	}
	for _, tc := range cases {
		w := e.do(http.MethodPost, "/api/account/invites", tc.body, tok)
		assert.Equal(t, tc.status, w.Code, tc.name)
		assert.Equal(t, `{"error":"`+tc.code+`","message":"`+tc.msg+`"}`, w.Body.String(), tc.name)
	}
	invs, err := e.st.Invites().ListByAccount(t.Context(), acc.ID)
	require.NoError(t, err)
	assert.Empty(t, invs, "no refused invite was made")
	assert.Empty(t, e.auditActions(acc.ID))

	// A term almost a year away, permissions sorted without repeats; "all" alone stands for everything.
	until := now.AddDate(1, 0, 0).Add(-time.Minute)
	for _, body := range []map[string]any{
		{"name": "Bob", "access_until": rfc(until), "permissions": []string{"plugin:tv", "plugin:light", "plugin:tv"}},
		{"name": "Carol", "permissions": []string{"plugin:tv", "all"}},
		{"name": "Dan"},
	} {
		w := e.do(http.MethodPost, "/api/account/invites", body, tok)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
	invs, err = e.st.Invites().ListByAccount(t.Context(), acc.ID)
	require.NoError(t, err)
	require.Len(t, invs, 3)
	// Invites made within one millisecond sort by id: put them back in the order they were made.
	slices.SortFunc(invs, func(x, y core.Invite) int { return strings.Compare(x.Name, y.Name) })
	require.NotNil(t, invs[0].AccessUntil)
	assert.True(t, until.Truncate(time.Millisecond).Equal(*invs[0].AccessUntil), "kept to the millisecond")
	assert.Equal(t, []string{"plugin:light", "plugin:tv"}, invs[0].Permissions)
	assert.Nil(t, invs[1].AccessUntil)
	assert.Equal(t, []string{core.PermissionAll}, invs[1].Permissions)
	assert.Nil(t, invs[2].AccessUntil)
	assert.Empty(t, invs[2].Permissions)

	var details []map[string]string
	for _, en := range e.st.AuditEntries() {
		_, d := actorname.Split(en)
		details = append(details, d)
	}
	assert.Equal(t, []map[string]string{
		{"access_until": ts(until), "permissions": "plugin:light,plugin:tv"},
		{"permissions": "all"},
		{},
	}, details, "ids only")

	w := e.do(http.MethodGet, "/api/account", nil, tok)
	body := w.Body.String()
	assert.Contains(t, body, `"name":"Bob","expires_at":"`+ts(invs[0].ExpiresAt)+`","access_until":"`+ts(until)+
		`","permissions":["plugin:light","plugin:tv"]}`)
	assert.Contains(t, body, `"name":"Carol","expires_at":"`+ts(invs[1].ExpiresAt)+
		`","access_until":null,"permissions":["all"]}`)
	assert.Contains(t, body, `"name":"Dan","expires_at":"`+ts(invs[2].ExpiresAt)+`","access_until":null,"permissions":[]}`)
	assert.NotContains(t, body, `"role"`+`:"member","access`, "no role on invites without co-owners")

	// The catalog failing is the application's fault: 500, logged.
	cat.mu.Lock()
	cat.err = errors.New("catalog down")
	cat.mu.Unlock()
	w = e.do(http.MethodPost, "/api/account/invites", map[string]any{"name": "Eve", "permissions": []string{"all"}}, tok)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.True(t, e.logs.Contains("catalog down"))
}

func TestMembersListing(t *testing.T) {
	e := newEnv(t, withCatalog(newCatalog()), func(o *people.Options) { o.Fields = nil })
	acc, owner := e.account("Home", "Alice", false)
	bob := e.person(acc, "Bob", core.RoleMember, false)
	carol := e.person(acc, "Carol", core.RoleMember, false)
	dan := e.person(acc, "Dan", core.RoleMember, false)
	later := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	ended := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	e.setAccess(bob, &later, "plugin:tv")
	e.setAccess(carol, &ended, "plugin:tv", "plugin:light")

	access := map[core.PersonID]string{
		owner.ID: `"access_until":null,"permissions":["all"],"active":true`,
		bob.ID:   `"access_until":"` + ts(later) + `","permissions":["plugin:tv"],"active":true`,
		carol.ID: `"access_until":"` + ts(ended) + `","permissions":["plugin:tv","plugin:light"],"active":false`,
		dan.ID:   `"access_until":null,"permissions":[],"active":true`,
	}
	// row is p's member row as viewer sees it; shown says whether it carries p's access.
	row := func(p, viewer core.Person, shown bool) string {
		out := `{"id":"` + string(p.ID) + `","name":"` + p.Name + `","role":"` + string(p.Role) + `","joined_at":"` +
			ts(p.CreatedAt) + `","you":` + fmt.Sprint(p.ID == viewer.ID)
		if shown {
			out += `,` + access[p.ID]
		}
		return out + `}`
	}
	list := func(viewer core.Person) string {
		w := e.do(http.MethodGet, "/api/account", nil, e.session(viewer, false))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		return w.Body.String()
	}
	head := `{"id":"` + string(acc.ID) + `","name":"Home","members":[`

	// The owner sees everyone's access; an expired member stays listed, inactive, until removed.
	assert.Equal(t, head+row(owner, owner, true)+`,`+row(bob, owner, true)+`,`+row(carol, owner, true)+`,`+
		row(dan, owner, true)+`],"invites":[]}`, list(owner))

	// Anyone else sees who is in the account, and their own access only.
	assert.Equal(t, head+row(owner, bob, false)+`,`+row(bob, bob, true)+`,`+row(carol, bob, false)+`,`+
		row(dan, bob, false)+`],"invites":[]}`, list(bob))
	assert.Equal(t, head+row(owner, carol, false)+`,`+row(bob, carol, false)+`,`+row(carol, carol, true)+`,`+
		row(dan, carol, false)+`],"invites":[]}`, list(carol), "an expired guest sees their own end")

	// The bytes of a hidden row: the fields of a row without a catalog, nothing more.
	assert.Contains(t, list(bob), `{"id":"`+string(carol.ID)+`","name":"Carol","role":"member","joined_at":"`+
		ts(carol.CreatedAt)+`","you":false}`)
	for _, leak := range []string{ts(ended), "plugin:light", `"active":false`, `["all"]`} {
		assert.NotContains(t, list(bob), leak)
	}
}

// No other route shows a non-owner another member's term or permissions: the connections carry neither, the audit
// shows a member only their own entries (account.member.update of others included), and the invites and the
// catalog are the owner's.
func TestNoOtherRouteShowsOthersAccess(t *testing.T) {
	e := newEnv(t, withCatalog(newCatalog()))
	acc, owner := e.account("Home", "Alice", false)
	bob := e.person(acc, "Bob", core.RoleMember, false)
	carol := e.person(acc, "Carol", core.RoleMember, false)
	e.grant(carol, core.AssistantClaude)
	ownerTok, bobTok := e.session(owner, true), e.session(bob, false)
	secret := time.Now().Add(3 * time.Hour).UTC().Truncate(time.Millisecond)
	w := e.do(http.MethodPatch, "/api/account/members/"+string(carol.ID), map[string]any{
		"access_until": rfc(secret), "permissions": []string{"plugin:light"}}, ownerTok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = e.do(http.MethodPost, "/api/account/invites", map[string]any{"name": "Dan", "access_until": rfc(secret),
		"permissions": []string{"plugin:light"}}, ownerTok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	for _, path := range []string{"/api/account", "/api/account/connections", "/api/account/audit"} {
		w := e.do(http.MethodGet, path, nil, bobTok)
		require.Equal(t, http.StatusOK, w.Code, path)
		assert.NotContains(t, w.Body.String(), ts(secret), path)
		assert.NotContains(t, w.Body.String(), "plugin:light", path)
	}
	assert.Equal(t, http.StatusForbidden, e.do(http.MethodGet, "/api/account/permissions", nil, bobTok).Code)
	w = e.do(http.MethodPatch, "/api/account/members/"+string(carol.ID), map[string]any{"permissions": []string{}},
		e.session(bob, true))
	assert.Equal(t, http.StatusForbidden, w.Code, "a member cannot read others' access back through PATCH")

	// The owner reads all of it.
	w = e.do(http.MethodGet, "/api/account/audit", nil, ownerTok)
	assert.Contains(t, w.Body.String(), "plugin:light")
}

func TestUpdateMember(t *testing.T) {
	e := newEnv(t, withCatalog(newCatalog()))
	acc, owner := e.account("Home", "Alice", false)
	bob := e.person(acc, "Bob", core.RoleMember, false)
	root := e.person(acc, "Root", core.RoleMember, true)
	other, _ := e.account("Other", "Zed", false)
	stranger := e.person(other, "Yan", core.RoleMember, false)
	end := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	e.setAccess(bob, &end, "plugin:tv")
	plain, stepped := e.session(owner, false), e.session(owner, true)
	bobTok := e.session(bob, true)
	patch := func(id core.PersonID, body any, tok string) (int, string) {
		w := e.do(http.MethodPatch, "/api/account/members/"+string(id), body, tok)
		return w.Code, w.Body.String()
	}
	unchanged := func(msg string) {
		got := e.stored(bob)
		require.NotNil(t, got.AccessUntil, msg)
		assert.True(t, end.Equal(*got.AccessUntil), msg)
		assert.Equal(t, []string{"plugin:tv"}, got.Permissions, msg)
	}

	refusals := []struct {
		name   string
		target core.PersonID
		body   any
		tok    string
		status int
		code   string
	}{
		{"a member", owner.ID, map[string]any{"access_until": nil}, bobTok, http.StatusForbidden, "forbidden"},
		{"yourself", owner.ID, map[string]any{"access_until": nil}, stepped, http.StatusBadRequest, "invalid"},
		{"another account's person", stranger.ID, map[string]any{"permissions": []string{}}, stepped,
			http.StatusNotFound, "not_found"},
		{"an unknown person", "per_unknown", map[string]any{"permissions": []string{}}, stepped,
			http.StatusNotFound, "not_found"},
		{"the superadmin, by an owner", root.ID, map[string]any{"permissions": []string{}}, stepped,
			http.StatusForbidden, "forbidden"},
		{"nothing to change", bob.ID, map[string]any{}, stepped, http.StatusBadRequest, "invalid"},
		{"no body", bob.ID, nil, stepped, http.StatusBadRequest, "invalid"},
		{"null permissions", bob.ID, map[string]any{"permissions": nil}, stepped, http.StatusBadRequest, "invalid"},
		{"an unknown permission", bob.ID, map[string]any{"permissions": []string{"plugin:oven"}}, stepped,
			http.StatusBadRequest, "invalid_permission"},
		{"a term over a year away", bob.ID, map[string]any{"access_until": rfc(time.Now().AddDate(1, 0, 1))}, stepped,
			http.StatusBadRequest, "invalid"},
		{"a term that is not RFC 3339", bob.ID, map[string]any{"access_until": "soon"}, stepped,
			http.StatusBadRequest, "invalid"},
		{"a term of the wrong type", bob.ID, map[string]any{"access_until": true}, stepped,
			http.StatusBadRequest, "invalid"},
		// Widening without step-up: the answer of RequireStepUp, and nothing changes.
		{"a later end", bob.ID, map[string]any{"access_until": rfc(end.Add(time.Hour))}, plain,
			http.StatusForbidden, "step_up_required"},
		{"no end", bob.ID, map[string]any{"access_until": nil}, plain, http.StatusForbidden, "step_up_required"},
		{"one more permission", bob.ID, map[string]any{"permissions": []string{"plugin:tv", "plugin:light"}}, plain,
			http.StatusForbidden, "step_up_required"},
		{"all", bob.ID, map[string]any{"permissions": []string{"all"}}, plain, http.StatusForbidden,
			"step_up_required"},
		{"narrower term, wider permissions", bob.ID, map[string]any{"access_until": rfc(end.Add(-time.Minute)),
			"permissions": []string{"plugin:light"}}, plain, http.StatusForbidden, "step_up_required"},
	}
	for _, tc := range refusals {
		status, body := patch(tc.target, tc.body, tc.tok)
		assert.Equal(t, tc.status, status, tc.name+": "+body)
		assert.Contains(t, body, `"error":"`+tc.code+`"`, tc.name)
		unchanged(tc.name)
	}
	assert.Empty(t, e.auditActions(acc.ID), "no refusal is audited as a change")
	_, body := patch(bob.ID, map[string]any{"access_until": true}, stepped)
	assert.Equal(t, `{"error":"invalid","message":"access_until has the wrong type"}`, body)
	_, body = patch(bob.ID, map[string]any{"permissions": "plugin:tv"}, stepped)
	assert.Equal(t, `{"error":"invalid","message":"permissions has the wrong type"}`, body)

	// Narrowing needs no step-up: an earlier end, fewer permissions, and ending access now.
	sooner := end.Add(-30 * time.Minute)
	status, body := patch(bob.ID, map[string]any{"access_until": rfc(sooner)}, plain)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, `{"id":"`+string(bob.ID)+`","name":"Bob","role":"member","joined_at":"`+ts(bob.CreatedAt)+
		`","you":false,"access_until":"`+ts(sooner)+`","permissions":["plugin:tv"],"active":true}`, body)
	status, body = patch(bob.ID, map[string]any{"permissions": []string{}}, plain)
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, `"permissions":[],"active":true}`)
	before := time.Now().UTC().Truncate(time.Millisecond)
	status, body = patch(bob.ID, map[string]any{"access_until": rfc(time.Now().Add(-time.Hour))}, plain)
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, `"active":false}`, "ended now")
	got := e.stored(bob)
	require.NotNil(t, got.AccessUntil)
	assert.False(t, got.AccessUntil.Before(before), "a time in the past ends the access now, not in the past")
	assert.False(t, got.Active(time.Now()))

	// «Продлить»: widening with step-up re-enables the person.
	status, body = patch(bob.ID, map[string]any{"access_until": nil, "permissions": []string{"plugin:light",
		"plugin:tv"}}, stepped)
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, `"access_until":null,"permissions":["plugin:light","plugin:tv"],"active":true}`)
	got = e.stored(bob)
	assert.Nil(t, got.AccessUntil)
	assert.True(t, got.Active(time.Now()))

	var details []map[string]string
	for _, en := range e.st.AuditEntries() {
		require.Equal(t, people.ActionMemberUpdate, en.Action)
		assert.Equal(t, string(bob.ID), en.Target)
		assert.Equal(t, owner.ID, en.Actor)
		name, d := actorname.Split(en)
		assert.Equal(t, "Alice", name)
		details = append(details, d)
	}
	require.Len(t, details, 4)
	assert.Equal(t, map[string]string{"role": "member", "access_until": ts(sooner)}, details[0])
	assert.Equal(t, map[string]string{"role": "member", "permissions": ""}, details[1])
	assert.Equal(t, map[string]string{"role": "member", "access_until": "none", "permissions": "plugin:light,plugin:tv"},
		details[3])

	// The member reads their own changes in the account audit.
	w := e.do(http.MethodGet, "/api/account/audit", nil, bobTok)
	assert.Equal(t, 4, strings.Count(w.Body.String(), people.ActionMemberUpdate))
}

// The step-up rule is checked again inside the transaction, against the person as stored then: a change that was
// narrowing when it was sent but widens what another owner just set is refused, unchanged.
func TestUpdateMemberChecksWideningOnTheStoredPerson(t *testing.T) {
	e := newEnv(t, withCatalog(newCatalog()))
	acc, owner := e.account("Home", "Alice", false)
	bob := e.person(acc, "Bob", core.RoleMember, false)
	ended := time.Now().UTC().Truncate(time.Millisecond)
	e.setAccess(bob, &ended) // another owner just ended the access
	ctx := t.Context()

	tomorrow := time.Now().Add(24 * time.Hour)
	_, err := e.svc.UpdateMember(ctx, acc.ID, bob.ID, owner.ID, people.AccessChange{SetUntil: true, Until: &tomorrow},
		false, "ip")
	require.ErrorIs(t, err, people.ErrWidens)
	assert.True(t, ended.Equal(*e.stored(bob).AccessUntil), "unchanged")

	p, err := e.svc.UpdateMember(ctx, acc.ID, bob.ID, owner.ID, people.AccessChange{SetUntil: true, Until: &tomorrow},
		true, "ip")
	require.NoError(t, err)
	assert.True(t, p.Active(time.Now()))

	// Without a catalog nothing is changed through the service either.
	plain := newEnv(t)
	_, err = plain.svc.UpdateMember(ctx, acc.ID, bob.ID, owner.ID, people.AccessChange{SetPermissions: true}, true, "ip")
	var ae *people.APIError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, "invalid_permission", ae.Code)
}

func TestCoOwners(t *testing.T) {
	e := newEnv(t, withCatalog(newCatalog()), withCoOwners)
	acc, root := e.account("Home", "Root", true)
	carol := e.person(acc, "Carol", core.RoleOwner, false) // a co-owner
	bob := e.person(acc, "Bob", core.RoleMember, false)
	dan := e.person(acc, "Dan", core.RoleMember, false)
	other, otherOwner := e.account("Other", "Zed", false)
	rootTok, carolTok := e.session(root, true), e.session(carol, true)
	gRoot, gBob := e.grant(root, core.AssistantChatGPT), e.grant(bob, core.AssistantClaude)

	invite := func(tok string, body map[string]any) (int, string) {
		w := e.do(http.MethodPost, "/api/account/invites", body, tok)
		return w.Code, w.Body.String()
	}
	// Inviting an owner: the superadmin only, into their own account, with no term or permissions.
	status, body := invite(carolTok, map[string]any{"name": "Eve", "role": "owner"})
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, `{"error":"forbidden","message":"only the superadmin may do this"}`, body)
	for _, tc := range []struct {
		name string
		body map[string]any
		msg  string
	}{
		{"a term", map[string]any{"name": "Eve", "role": "owner", "access_until": rfc(time.Now().Add(time.Hour))},
			"an owner has every permission and no access term"},
		{"permissions", map[string]any{"name": "Eve", "role": "owner", "permissions": []string{"all"}},
			"an owner has every permission and no access term"},
		{"an unknown role", map[string]any{"name": "Eve", "role": "admin"}, `role must be \"member\" or \"owner\"`},
		{"an empty role", map[string]any{"name": "Eve", "role": ""}, `role must be \"member\" or \"owner\"`},
	} {
		status, body := invite(rootTok, tc.body)
		assert.Equal(t, http.StatusBadRequest, status, tc.name)
		assert.Equal(t, `{"error":"invalid","message":"`+tc.msg+`"}`, body, tc.name)
	}
	status, body = invite(rootTok, map[string]any{"name": "Eve", "role": "owner"})
	require.Equal(t, http.StatusOK, status, body)
	status, body = invite(carolTok, map[string]any{"name": "Fay", "role": "member", "permissions": []string{"plugin:tv"}})
	require.Equal(t, http.StatusOK, status, body)
	invs, err := e.st.Invites().ListByAccount(t.Context(), acc.ID)
	require.NoError(t, err)
	require.Len(t, invs, 2)
	slices.SortFunc(invs, func(x, y core.Invite) int { return strings.Compare(x.Name, y.Name) })
	assert.Equal(t, core.InviteOwner, invs[0].Kind, "a co-owner invite into the existing account")
	assert.Equal(t, root.ID, invs[0].CreatedBy)
	assert.Equal(t, core.InviteMember, invs[1].Kind)
	assert.Equal(t, "owner", lastDetail(e, people.ActionInviteCreate, 0)["role"])
	assert.Equal(t, "member", lastDetail(e, people.ActionInviteCreate, 1)["role"])

	// Every owner sees both invites, with their roles.
	w := e.do(http.MethodGet, "/api/account", nil, carolTok)
	assert.Contains(t, w.Body.String(), `"name":"Eve","expires_at":"`+ts(invs[0].ExpiresAt)+
		`","role":"owner","access_until":null,"permissions":["all"]}`)
	assert.Contains(t, w.Body.String(), `"name":"Fay","expires_at":"`+ts(invs[1].ExpiresAt)+
		`","role":"member","access_until":null,"permissions":["plugin:tv"]}`)

	// Withdrawing an owner invite is the superadmin's; a member invite any owner's.
	assert.Equal(t, http.StatusForbidden, e.do(http.MethodDelete, "/api/account/invites/"+invs[0].ID, nil, carolTok).Code)
	assert.Equal(t, http.StatusNoContent, e.do(http.MethodDelete, "/api/account/invites/"+invs[1].ID, nil, carolTok).Code)
	assert.Equal(t, http.StatusNoContent, e.do(http.MethodDelete, "/api/account/invites/"+invs[0].ID, nil, rootTok).Code)

	// Changing: the co-owner manages members, only the superadmin the owners.
	patch := func(id core.PersonID, body map[string]any, tok string) (int, string) {
		w := e.do(http.MethodPatch, "/api/account/members/"+string(id), body, tok)
		return w.Code, w.Body.String()
	}
	soon := rfc(time.Now().Add(time.Hour))
	status, body = patch(bob.ID, map[string]any{"access_until": soon}, carolTok)
	assert.Equal(t, http.StatusOK, status, body)
	status, body = patch(root.ID, map[string]any{"access_until": soon}, carolTok)
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Contains(t, body, "only the superadmin may do this")
	status, body = patch(carol.ID, map[string]any{"permissions": []string{"plugin:tv"}}, rootTok)
	assert.Equal(t, http.StatusBadRequest, status, "an owner has every permission: "+body)
	status, body = patch(carol.ID, map[string]any{"access_until": soon}, rootTok)
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, `"role":"owner"`)
	assert.Equal(t, "owner", lastDetail(e, people.ActionMemberUpdate, -1)["role"])
	status, body = patch(carol.ID, map[string]any{"access_until": nil}, rootTok)
	require.Equal(t, http.StatusOK, status, body)

	// Connections: the co-owner revokes a member's, not the superadmin's.
	w = e.do(http.MethodDelete, "/api/account/connections/"+string(gRoot.ID), nil, carolTok)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = e.do(http.MethodDelete, "/api/account/connections/"+string(gBob.ID), nil, carolTok)
	assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())

	// Deleting the account would remove the other owners: the superadmin's call.
	w = e.do(http.MethodDelete, "/api/account", map[string]string{"confirm": "Home"}, carolTok)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.Empty(t, e.app.erasures())

	// Removing: the co-owner removes a member, not the superadmin; the superadmin removes the co-owner.
	w = e.do(http.MethodDelete, "/api/account/members/"+string(root.ID), nil, carolTok)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = e.do(http.MethodDelete, "/api/account/members/"+string(dan.ID), nil, carolTok)
	assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	assert.Equal(t, "member", lastDetail(e, people.ActionMemberRemove, -1)["role"])
	w = e.do(http.MethodDelete, "/api/account/members/"+string(carol.ID), nil, rootTok)
	assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	assert.Equal(t, "owner", lastDetail(e, people.ActionMemberRemove, -1)["role"])
	w = e.do(http.MethodDelete, "/api/account/members/"+string(root.ID), nil, rootTok)
	assert.Equal(t, http.StatusBadRequest, w.Code, "nobody removes the last superadmin, themselves included")

	// Another account's single owner still deletes their own account.
	w = e.do(http.MethodDelete, "/api/account", map[string]string{"confirm": "Other"}, e.session(otherOwner, true))
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	_ = other
}

// lastDetail is the detail, without the actor's name, of the i-th entry of action (-1: the last).
func lastDetail(e *env, action string, i int) map[string]string {
	var list []core.AuditEntry
	for _, en := range e.st.AuditEntries() {
		if en.Action == action {
			list = append(list, en)
		}
	}
	if i < 0 {
		i = len(list) - 1
	}
	if i < 0 || i >= len(list) {
		return nil
	}
	_, d := actorname.Split(list[i])
	return d
}

// With co-owners a superadmin who is a member of the account (not its owner) is still refused to an owner.
func TestCoOwnersRefuseAnOwnerActingOnTheSuperadmin(t *testing.T) {
	e := newEnv(t, withCoOwners)
	acc, owner := e.account("Home", "Alice", false)
	sa := e.person(acc, "Root", core.RoleMember, true)
	w := e.do(http.MethodDelete, "/api/account/members/"+string(sa.ID), nil, e.session(owner, true))
	assert.Equal(t, http.StatusForbidden, w.Code, "without co-owners this is 409: %s", w.Body.String())
}

func TestSingleAccount(t *testing.T) {
	e := newEnv(t, func(o *people.Options) { o.SingleAccount = true })
	mine, root := e.account("Home", "Root", true)
	e.account("Leftover", "Zed", false)
	tok := e.session(root, true)

	w := e.do(http.MethodGet, "/api/admin/accounts", nil, tok)
	require.Equal(t, http.StatusOK, w.Code)
	rows := decodeJSON[[]struct {
		ID string `json:"id"`
	}](t, w)
	require.Len(t, rows, 1)
	assert.Equal(t, string(mine.ID), rows[0].ID)

	for _, tc := range []struct{ method, path, token string }{
		{http.MethodPost, "/api/admin/accounts", tok},
		{http.MethodDelete, "/api/admin/accounts/acc_x", tok},
		{http.MethodPost, "/api/admin/accounts", ""},
	} {
		w := e.do(tc.method, tc.path, map[string]string{"name": "New", "owner_name": "Bob"}, tc.token)
		assert.Equal(t, http.StatusNotFound, w.Code, tc.method)
		assert.Equal(t, `{"error":"not_found","message":"not found"}`, w.Body.String())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	}
	accounts, err := e.st.Accounts().List(t.Context())
	require.NoError(t, err)
	assert.Len(t, accounts, 2, "nothing made or deleted")
}

func TestListPermissions(t *testing.T) {
	e := newEnv(t, withCatalog(newCatalog()))
	acc, owner := e.account("Home", "Alice", false)
	bob := e.person(acc, "Bob", core.RoleMember, false)
	w := e.do(http.MethodGet, "/api/account/permissions", nil, e.session(owner, false))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `[{"id":"plugin:tv","title":"TV","group":"Devices"},{"id":"plugin:light","title":"Light",`+
		`"group":"Devices"},{"id":"plugin:notes","title":"Notes","group":"Other"}]`, w.Body.String())
	w = e.do(http.MethodGet, "/api/account/permissions", nil, e.session(bob, false))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestGuardsWithACatalog walks the routes a catalog adds through the refusals of TestGuards.
func TestGuardsWithACatalog(t *testing.T) {
	e := newEnv(t, withCatalog(newCatalog()))
	acc, owner := e.account("Home", "Alice", false)
	member := e.person(acc, "Bob", core.RoleMember, false)
	ownerTok, memberTok := e.session(owner, true), e.session(member, true)
	for _, rt := range []route{
		{http.MethodPatch, "/api/account/members/" + string(member.ID), true, false, false},
		{http.MethodGet, "/api/account/permissions", true, false, false},
	} {
		w := e.do(rt.method, rt.path, nil, "")
		assert.Equal(t, http.StatusUnauthorized, w.Code, rt.path)
		if rt.method != http.MethodGet {
			w = e.do(rt.method, rt.path, map[string]any{"access_until": nil}, ownerTok, noCSRF)
			assert.Equal(t, http.StatusForbidden, w.Code, rt.path)
		}
		w = e.do(rt.method, rt.path, map[string]any{"access_until": nil}, memberTok)
		assert.Equal(t, http.StatusForbidden, w.Code, rt.path)
		assert.Contains(t, w.Body.String(), "only the owner of the account may do this")
	}
	assert.Empty(t, e.st.AuditEntries())
	assert.Nil(t, e.stored(member).AccessUntil)
}
