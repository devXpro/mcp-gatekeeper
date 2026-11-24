package people_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/people"
	"github.com/devXpro/mcp-gatekeeper/people/actorname"
)

func TestNewValidatesOptions(t *testing.T) {
	_, err := people.New(people.Options{})
	require.Error(t, err)
	for _, name := range []string{"Brand.SessionCookie", "Inviter", "NormalizeName", "Revoker", "Sessions",
		"Site.PublicURL", "Store"} {
		assert.Contains(t, err.Error(), name)
	}

	e := newEnv(t)
	_, err = people.New(people.Options{Site: coreSite(), Brand: core.Brand{SessionCookie: "fh_session"},
		Sessions: fakeSessions{st: e.st}, Store: e.st, Inviter: fakeInviter{st: e.st}, Revoker: e.rev,
		NormalizeName: normalizeName})
	require.ErrorContains(t, err, "__Host-")
}

func lastEntry(e *env, action string) core.AuditEntry {
	var out core.AuditEntry
	for _, en := range e.st.AuditEntries() {
		if en.Action == action {
			out = en
		}
	}
	return out
}

func TestDeleteAccountErasesTheApplicationFirst(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("A", "Owner", false)
	other, _ := e.account("B", "Other", false)
	e.app.setModules(acc.ID, "on", "off", "configured")
	e.app.setModules(other.ID, "foreign")

	// The client hanging up does not stop the erasure.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.NoError(t, e.svc.DeleteAccount(ctx, acc.ID, owner.ID, "ip", "owner"))

	assert.Equal(t, []erasure{{Account: acc.ID, Actor: owner.ID}}, e.app.erasures(),
		"the application erases this account only, on a context the client cannot cancel")
	_, err := e.st.Accounts().Get(t.Context(), acc.ID)
	require.ErrorIs(t, err, core.ErrNotFound)
	_, err = e.st.People().Get(t.Context(), owner.ID)
	require.ErrorIs(t, err, core.ErrNotFound, "the people went with the account")
	_, err = e.st.Accounts().Get(t.Context(), other.ID)
	require.NoError(t, err)

	entry := lastEntry(e, people.ActionDelete)
	assert.Empty(t, entry.AccountID, "a system entry")
	assert.Equal(t, string(acc.ID), entry.Target)
	assert.Equal(t, "configured,off,on", entry.Detail["modules"], "the application's detail")
	assert.Equal(t, "owner", entry.Detail["by"])
	assert.NotContains(t, entry.Detail, actorname.Key, "an owner's name stays out of the system entry (L9)")
	assert.Empty(t, entry.IP)

	// Deleting it again: not found.
	require.ErrorIs(t, e.svc.DeleteAccount(t.Context(), acc.ID, owner.ID, "ip", "owner"), core.ErrNotFound)
	assert.Len(t, e.app.erasures(), 1, "an unknown account never reaches the application")
}

func TestDeleteAccountKeepsTheAccountWhenTheApplicationFails(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("A", "Owner", false)
	e.app.setModules(acc.ID, "alpha", "beta")
	e.app.setEraseErr(moduleFailure("beta"))

	err := e.svc.DeleteAccount(t.Context(), acc.ID, owner.ID, "203.0.113.5", "owner")
	ee, ok := errors.AsType[*people.EraseError](err)
	require.True(t, ok, err)
	assert.Equal(t, "beta", ee.Detail["module"])
	_, err = e.st.Accounts().Get(t.Context(), acc.ID)
	require.NoError(t, err)
	_, err = e.st.People().Get(t.Context(), owner.ID)
	require.NoError(t, err)
	fail := lastEntry(e, people.ActionDeleteFail)
	assert.Equal(t, acc.ID, fail.AccountID, "the failure is audited in the account")
	assert.Equal(t, owner.ID, fail.Actor)
	assert.Equal(t, string(acc.ID), fail.Target)
	assert.Equal(t, "beta", fail.Detail["module"])
	assert.Equal(t, "Owner", fail.Detail[actorname.Key])
	assert.Equal(t, "203.0.113.5", fail.IP)
	assert.Empty(t, e.auditActions(""), "no account.delete")

	// A plain error is audited without detail.
	e.app.setEraseErr(errors.New("timeout"))
	require.Error(t, e.svc.DeleteAccount(t.Context(), acc.ID, owner.ID, "ip", "owner"))
	assert.Equal(t, map[string]string{actorname.Key: "Owner"}, lastEntry(e, people.ActionDeleteFail).Detail)

	// A store failure at the end keeps the account too; the next try finishes it.
	e.app.setEraseErr(nil)
	e.st.Fail("Accounts.Delete", errors.New("primary stepped down"))
	require.Error(t, e.svc.DeleteAccount(t.Context(), acc.ID, owner.ID, "ip", "owner"))
	_, err = e.st.Accounts().Get(t.Context(), acc.ID)
	require.NoError(t, err)
	assert.Empty(t, e.auditActions(""), "the delete entry rolled back with the rows")
	e.st.Fail("Accounts.Delete", nil)
	require.NoError(t, e.svc.DeleteAccount(t.Context(), acc.ID, owner.ID, "ip", "owner"))
	assert.Len(t, e.app.erasures(), 4, "every try asks the application again")
}

func TestDeleteAccountWithoutAnEraser(t *testing.T) {
	e := newEnv(t, func(o *people.Options) { o.Eraser = nil })
	acc, owner := e.account("A", "Owner", false)
	require.NoError(t, e.svc.DeleteAccount(t.Context(), acc.ID, owner.ID, "ip", "owner"))
	assert.Equal(t, map[string]string{"by": "owner"}, lastEntry(e, people.ActionDelete).Detail)
}

func TestInvitesAndMembers(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("A", "Owner", false)
	other, otherOwner := e.account("B", "Other", false)
	ctx := t.Context()

	inv, err := e.svc.CreateInvite(ctx, acc.ID, "Bella", owner.ID, "ip")
	require.NoError(t, err)
	_, err = e.svc.CreateInvite(ctx, acc.ID, "", owner.ID, "ip")
	require.ErrorIs(t, err, people.ErrInvalidName)
	require.ErrorIs(t, err, errInvalidName, "the rule's own error stays in the chain")
	assert.Equal(t, "people: issue an invite: invalid name: it must be 1 to 40 characters", err.Error())
	list, err := e.svc.Invites(ctx, acc.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, inv.ID, list[0].ID)
	require.ErrorIs(t, e.svc.RevokeInvite(ctx, other.ID, inv.ID, otherOwner.ID, "ip"), core.ErrNotFound)
	require.NoError(t, e.svc.RevokeInvite(ctx, acc.ID, inv.ID, owner.ID, "ip"))
	list, err = e.svc.Invites(ctx, acc.ID)
	require.NoError(t, err)
	assert.Empty(t, list)

	require.ErrorIs(t, e.svc.RemoveMember(ctx, acc.ID, owner.ID, owner.ID, "ip"), people.ErrSelf)
	require.ErrorIs(t, e.svc.RemoveMember(ctx, acc.ID, otherOwner.ID, owner.ID, "ip"), core.ErrNotFound)

	sums, err := e.svc.Summaries(ctx)
	require.NoError(t, err)
	require.Len(t, sums, 2)
	assert.Equal(t, 1, sums[0].Members)
	assert.Equal(t, acc.ID, sums[0].Account.ID, "oldest first")
}

// Every audit entry of this package carries the actor's name as it was when the entry was written. The system
// entry of "delete everything" keeps the owner's name out although the owner's row goes with the account.
func TestAuditEntriesCarryTheActorName(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("A", "Owner", false)
	member := e.person(acc, "Kid", core.RoleMember, false)
	ctx := t.Context()

	inv, err := e.svc.CreateInvite(ctx, acc.ID, "Bella", owner.ID, "ip")
	require.NoError(t, err)
	require.NoError(t, e.svc.RevokeInvite(ctx, acc.ID, inv.ID, owner.ID, "ip"))
	require.NoError(t, e.svc.RemoveMember(ctx, acc.ID, member.ID, owner.ID, "ip"))
	_, _, err = e.svc.CreateAccount(ctx, "New", "Newbie", owner.ID, "ip")
	require.NoError(t, err)
	require.NoError(t, e.svc.DeleteAccount(ctx, acc.ID, owner.ID, "ip", "owner"))

	var seen []string
	for _, en := range e.st.AuditEntries() {
		seen = append(seen, en.Action)
		if en.Action == people.ActionDelete {
			assert.NotContains(t, en.Detail, actorname.Key, "an owner's name stays out of a system entry (L9)")
			continue
		}
		assert.Equal(t, "Owner", en.Detail[actorname.Key], en.Action)
	}
	assert.ElementsMatch(t, []string{people.ActionInviteCreate, people.ActionInviteRevoke, people.ActionMemberRemove,
		people.ActionCreate, people.ActionDelete}, seen)
	_, err = e.st.People().Get(ctx, owner.ID)
	require.ErrorIs(t, err, core.ErrNotFound, "the owner is gone, the account's entries still name them")
}

// The superadmin's deletion of another account names the superadmin and keeps their address; an owner's keeps
// neither (T2.R L9).
func TestDeleteAccountSystemEntry(t *testing.T) {
	e := newEnv(t)
	acc, _ := e.account("A", "Owner", false)
	root := e.person(acc, "Root", core.RoleOwner, true)
	victim, _ := e.account("B", "Victim", false)
	require.NoError(t, e.svc.DeleteAccount(t.Context(), victim.ID, root.ID, "203.0.113.9", "superadmin"))
	en := lastEntry(e, people.ActionDelete)
	assert.Equal(t, "Root", en.Detail[actorname.Key])
	assert.Equal(t, "203.0.113.9", en.IP)
	assert.Equal(t, "superadmin", en.Detail["by"])
}

// CreateAccount makes the account and its owner's invite in one transaction, and the account's name is trimmed.
func TestCreateAccount(t *testing.T) {
	e := newEnv(t)
	_, root := e.account("Admins", "Root", true)
	acc, inv, err := e.svc.CreateAccount(t.Context(), "  Nowakowie ", "Jan", root.ID, "ip")
	require.NoError(t, err)
	assert.Equal(t, "Nowakowie", acc.Name)
	invs, err := e.st.Invites().ListByAccount(t.Context(), acc.ID)
	require.NoError(t, err)
	require.Len(t, invs, 1)
	assert.Equal(t, inv.ID, invs[0].ID)
	assert.Equal(t, core.InviteOwner, invs[0].Kind)
	assert.Equal(t, map[string]string{"invite": inv.ID, actorname.Key: "Root"}, lastEntry(e, people.ActionCreate).Detail)

	_, _, err = e.svc.CreateAccount(t.Context(), "X", "a\tb", root.ID, "ip")
	require.ErrorIs(t, err, people.ErrInvalidName)
	assert.Equal(t, "people: the owner's name: invalid name: it must not contain control characters, line breaks, "+
		"quotes, backslashes or backticks", err.Error())
}
