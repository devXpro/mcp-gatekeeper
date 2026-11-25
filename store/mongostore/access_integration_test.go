//go:build integration

package mongostore_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// keys returns the field names of a document, in order.
func keys(d bson.D) []string {
	out := make([]string, len(d))
	for i, e := range d {
		out[i] = e.Key
	}
	return out
}

// TestAccessFieldsAreOptional proves the access term and permissions are stored only when set: a person or an invite
// without them is the document Family Hub's store writes, and a person that has them cleared goes back to it.
func TestAccessFieldsAreOptional(t *testing.T) {
	ctx := t.Context()
	s, dbName := newStoreDB(t)
	db := rawDB(t, dbName)
	raw := func(coll, id string) bson.D {
		t.Helper()
		var d bson.D
		require.NoError(t, db.Collection(coll).FindOne(ctx, bson.D{{Key: "_id", Value: id}}).Decode(&d))
		return d
	}
	plainKeys := []string{"_id", "account_id", "name", "role", "superadmin", "created_at"}
	until := t0.Add(48 * time.Hour)

	require.NoError(t, s.Accounts().Create(ctx, core.Account{ID: "acc_1", Name: "Home", CreatedAt: t0}))
	person := core.Person{ID: "per_1", AccountID: "acc_1", Name: "Alice", Role: core.RoleMember, CreatedAt: t0,
		Permissions: []string{}}
	require.NoError(t, s.People().Create(ctx, person))
	assert.Equal(t, plainKeys, keys(raw("people", "per_1")), "an empty list of permissions is not written")

	// A term and permissions are stored as a date and an array under their names.
	require.NoError(t, s.People().SetAccess(ctx, "per_1", &until, []string{"plugin:tv", core.PermissionAll}))
	doc := raw("people", "per_1")
	assert.Equal(t, append(append([]string{}, plainKeys...), "access_until", "permissions"), keys(doc))
	assert.Equal(t, bson.NewDateTimeFromTime(until), doc[len(doc)-2].Value)
	assert.Equal(t, bson.A{"plugin:tv", "all"}, doc[len(doc)-1].Value)

	// Clearing each removes the field, so the document is Family Hub's again.
	require.NoError(t, s.People().SetAccess(ctx, "per_1", nil, []string{"plugin:tv"}))
	assert.Equal(t, append(append([]string{}, plainKeys...), "permissions"), keys(raw("people", "per_1")))
	require.NoError(t, s.People().SetAccess(ctx, "per_1", &until, nil))
	assert.Equal(t, append(append([]string{}, plainKeys...), "access_until"), keys(raw("people", "per_1")))
	require.NoError(t, s.People().SetAccess(ctx, "per_1", nil, []string{}))
	assert.Equal(t, plainKeys, keys(raw("people", "per_1")))
	got, err := s.People().Get(ctx, "per_1")
	require.NoError(t, err)
	assert.Equal(t, core.Person{ID: "per_1", AccountID: "acc_1", Name: "Alice", Role: core.RoleMember, CreatedAt: t0}, got)

	// A person created with them keeps them, and a disabled mark stays where it is.
	off := t0.Add(time.Hour)
	require.NoError(t, s.People().Create(ctx, core.Person{ID: "per_2", AccountID: "acc_1", Name: "Bob", Role: core.RoleMember,
		CreatedAt: t0, DisabledAt: &off, AccessUntil: &until, Permissions: []string{"x"}}))
	assert.Equal(t, append(append([]string{}, plainKeys...), "disabled_at", "access_until", "permissions"), keys(raw("people", "per_2")))
	require.NoError(t, s.People().SetAccess(ctx, "per_2", nil, nil))
	assert.Equal(t, append(append([]string{}, plainKeys...), "disabled_at"), keys(raw("people", "per_2")))

	// Invites: the same two optional fields.
	inviteKeys := []string{"_id", "token_hash", "kind", "account_id", "name", "created_by", "created_at", "expires_at"}
	require.NoError(t, s.Invites().Create(ctx, core.Invite{ID: "inv_1", TokenHash: []byte("a"), Kind: core.InviteMember,
		AccountID: "acc_1", Name: "Carol", CreatedBy: "per_1", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour), Permissions: []string{}}))
	assert.Equal(t, inviteKeys, keys(raw("invites", "inv_1")))
	require.NoError(t, s.Invites().Create(ctx, core.Invite{ID: "inv_2", TokenHash: []byte("b"), Kind: core.InviteMember,
		AccountID: "acc_1", Name: "Carol", CreatedBy: "per_1", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour), AccessUntil: &until,
		Permissions: []string{"plugin:tv"}}))
	assert.Equal(t, append(append([]string{}, inviteKeys...), "access_until", "permissions"), keys(raw("invites", "inv_2")))
	inv, err := s.Invites().Consume(ctx, []byte("b"), t0)
	require.NoError(t, err)
	assert.True(t, until.Equal(*inv.AccessUntil))
	assert.Equal(t, []string{"plugin:tv"}, inv.Permissions)
}

// TestSetAccessOnAFamilyHubDocument sets a term on a person document as Family Hub wrote it (from the fixtures): only
// the two fields appear, and everything else is byte for byte what it was.
func TestSetAccessOnAFamilyHubDocument(t *testing.T) {
	ctx := t.Context()
	s, dbName := newStoreDB(t)
	db := rawDB(t, dbName)
	people := loadDocs(t, "people.json")
	_, err := db.Collection("people").InsertMany(ctx, people)
	require.NoError(t, err)

	until := t0.Add(24 * time.Hour)
	require.NoError(t, s.People().SetAccess(ctx, "per_member", &until, []string{"plugin:tv"}))
	got := dumpDocs(t, db, "people")
	require.Len(t, got, 2)
	var member bson.D
	for _, d := range got {
		if d[0].Value == "per_member" {
			member = d
		}
	}
	var want bson.D
	for _, d := range people {
		if d[0].Value == "per_member" {
			want = d
		}
	}
	require.Equal(t, append(append(bson.D{}, want...), bson.E{Key: "access_until", Value: bson.NewDateTimeFromTime(until)},
		bson.E{Key: "permissions", Value: bson.A{"plugin:tv"}}), member)

	require.NoError(t, s.People().SetAccess(ctx, "per_member", nil, nil))
	for _, d := range dumpDocs(t, db, "people") {
		if d[0].Value == "per_member" {
			assert.Equal(t, want, d, "cleared, the document is the one Family Hub wrote")
		}
	}
}
