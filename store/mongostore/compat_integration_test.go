//go:build integration

package mongostore_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// The fixtures in testdata/familyhub were written by Family Hub's own store code (commit b0fc38b) from the values
// below; testdata/familyhub/generate/dump_integration_test.go is the generator. These tests prove the adapter reads
// Family Hub's live documents as they are, writes documents identical to Family Hub's, and builds the same indexes.

const fixtureDir = "testdata/familyhub"

// t0 is far ahead, so the TTL monitor never removes a fixture during a test.
var t0 = time.Date(2036, 1, 2, 10, 11, 12, 345_000_000, time.UTC)

func after(d time.Duration) *time.Time { v := t0.Add(d); return &v }

// familyHubOnly are Family Hub's own collections: they stay in Family Hub (card G9).
var familyHubOnly = map[string]bool{"modules": true, "account_modules": true, "legacy_keys": true}

// dataCollections are the gatekeeper's collections that hold the fixtures' documents.
var dataCollections = []string{"accounts", "people", "passkeys", "sessions", "invites", "oauth_clients", "oauth_codes",
	"oauth_grants", "oauth_tokens", "audit"}

type fixtureSet struct {
	accounts []core.Account
	people   []core.Person
	passkeys []core.Passkey
	sessions []core.Session
	invites  []core.Invite
	clients  []core.OAuthClient
	codes    []core.AuthCode
	grants   []core.Grant
	tokens   []core.Token
	audit    []core.AuditEntry
}

// fixtures returns the values the generator wrote, in the gatekeeper's types (a grant's module is its resource).
func fixtures() fixtureSet {
	return fixtureSet{
		accounts: []core.Account{{ID: "acc_fixture1", Name: "Kowalscy", CreatedAt: t0}},
		people: []core.Person{
			{ID: "per_owner", AccountID: "acc_fixture1", Name: "Alice", Role: core.RoleOwner, Superadmin: true, CreatedAt: t0},
			{ID: "per_member", AccountID: "acc_fixture1", Name: "Bella", Role: core.RoleMember, CreatedAt: t0.Add(time.Minute),
				DisabledAt: after(time.Hour)},
		},
		passkeys: []core.Passkey{
			{ID: "pk_1", PersonID: "per_owner", CredentialID: []byte{1, 2, 3}, Data: []byte(`{"id":"AQID"}`), Name: "iPhone",
				CreatedAt: t0, LastUsedAt: after(2 * time.Hour)},
			{ID: "pk_2", PersonID: "per_member", CredentialID: []byte{4, 5}, Data: []byte(`{}`), CreatedAt: t0},
		},
		sessions: []core.Session{
			{IDHash: []byte("sess-1"), PersonID: "per_owner", CreatedAt: t0, LastSeenAt: t0.Add(time.Minute),
				ExpiresAt: t0.Add(30 * 24 * time.Hour), StepUpUntil: t0.Add(5 * time.Minute), UserAgent: "Mozilla/5.0"},
			{IDHash: []byte("sess-2"), PersonID: "per_member", CreatedAt: t0, LastSeenAt: t0, ExpiresAt: t0.Add(24 * time.Hour)},
		},
		invites: []core.Invite{
			{ID: "inv_setup", TokenHash: []byte("tok-setup"), Kind: core.InviteSetup, CreatedAt: t0, ExpiresAt: t0.Add(15 * time.Minute)},
			{ID: "inv_member", TokenHash: []byte("tok-member"), Kind: core.InviteMember, AccountID: "acc_fixture1", Name: "Bella",
				CreatedBy: "per_owner", CreatedAt: t0, ExpiresAt: t0.Add(72 * time.Hour), UsedAt: after(time.Hour)},
			{ID: "inv_owner", TokenHash: []byte("tok-owner"), Kind: core.InviteOwner, AccountID: "acc_fixture1", Name: "Owner",
				CreatedBy: "per_owner", CreatedAt: t0, ExpiresAt: t0.Add(72 * time.Hour), RevokedAt: after(time.Hour)},
		},
		clients: []core.OAuthClient{
			{ID: "cli_dcr", Kind: core.ClientDCR, Assistant: core.AssistantChatGPT, Name: "ChatGPT",
				RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"}, AuthMethod: "client_secret_post",
				SecretHash: []byte("secret-hash"), FetchedAt: t0, CreatedAt: t0, LastUsedAt: after(time.Hour)},
			{ID: "https://claude.ai/oauth/claude-code-client-metadata", Kind: core.ClientCIMD, Assistant: core.AssistantClaude,
				Name: "Claude", AuthMethod: "none", FetchedAt: t0, CreatedAt: t0},
		},
		codes: []core.AuthCode{{CodeHash: []byte("code-1"), GrantID: "grt_active", ClientID: "cli_dcr",
			RedirectURI: "https://chatgpt.com/connector_platform_oauth_redirect", Resource: "https://family.example.com/mcp/notes",
			Scope: "mcp", CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CreatedAt: t0, ExpiresAt: t0.Add(5 * time.Minute)}},
		grants: []core.Grant{
			{ID: "grt_active", PersonID: "per_owner", AccountID: "acc_fixture1", ClientID: "cli_dcr", ResourceID: "notes",
				Scope: "mcp", CreatedAt: t0},
			{ID: "grt_revoked", PersonID: "per_member", AccountID: "acc_fixture1",
				ClientID: "https://claude.ai/oauth/claude-code-client-metadata", ResourceID: "photos", Scope: "mcp offline_access",
				CreatedAt: t0, LastUsedAt: after(time.Minute), RevokedAt: after(time.Hour)},
		},
		tokens: []core.Token{
			{Hash: []byte("access-1"), GrantID: "grt_active", Kind: core.TokenAccess, Family: "fam-1", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)},
			{Hash: []byte("refresh-1"), GrantID: "grt_active", Kind: core.TokenRefresh, Family: "fam-1", CreatedAt: t0,
				ExpiresAt: t0.Add(30 * 24 * time.Hour), UsedAt: after(time.Minute)},
			{Hash: []byte("refresh-2"), GrantID: "grt_revoked", Kind: core.TokenRefresh, Family: "fam-2", CreatedAt: t0,
				ExpiresAt: t0.Add(30 * 24 * time.Hour), RevokedAt: after(time.Hour)},
		},
		audit: []core.AuditEntry{
			{At: t0, AccountID: "acc_fixture1", Actor: "per_owner", Action: "oauth.consent", Target: "notes",
				Detail: map[string]string{"client": "ChatGPT", "scope": "mcp"}, IP: "203.0.113.5"},
			{At: t0, Action: "setup.link"},
		},
	}
}

// loadDocs reads a fixture file: an array of documents in canonical extended JSON.
func loadDocs(t *testing.T, file string) []bson.D {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, file)) //nolint:gosec // a fixture path of the test
	require.NoError(t, err)
	var w struct {
		Docs []bson.D `bson:"docs"`
	}
	require.NoError(t, bson.UnmarshalExtJSON([]byte(`{"docs":`+string(b)+`}`), true, &w))
	require.NotEmpty(t, w.Docs, file)
	return w.Docs
}

// dumpDocs returns every document of a collection, sorted by _id.
func dumpDocs(t *testing.T, db *mongo.Database, name string) []bson.D {
	t.Helper()
	cur, err := db.Collection(name).Find(t.Context(), bson.D{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	require.NoError(t, err)
	var docs []bson.D
	require.NoError(t, cur.All(t.Context(), &docs))
	return docs
}

// TestCompatIndexes checks that a fresh database gets Family Hub's collections and indexes: names, keys, options
// and TTLs, field for field.
func TestCompatIndexes(t *testing.T) {
	ctx := t.Context()
	_, dbName := newStoreDB(t)
	db := rawDB(t, dbName)

	files, err := filepath.Glob(filepath.Join(fixtureDir, "indexes.*.json"))
	require.NoError(t, err)
	var want []string
	for _, f := range files {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "indexes."), ".json")
		if !familyHubOnly[name] {
			want = append(want, name)
		}
	}
	require.Len(t, want, 11)
	names, err := db.ListCollectionNames(ctx, bson.D{})
	require.NoError(t, err)
	assert.ElementsMatch(t, want, names)

	for _, name := range want {
		cur, err := db.Collection(name).Indexes().List(ctx)
		require.NoError(t, err)
		var got []bson.D
		require.NoError(t, cur.All(ctx, &got))
		assert.ElementsMatch(t, loadDocs(t, "indexes."+name+".json"), got, name)
	}

	// The migrations are recorded under Family Hub's versions and names, so its live database migrates nothing.
	project := func(docs []bson.D) []bson.D {
		var out []bson.D
		for _, d := range docs {
			var p bson.D
			for _, e := range d {
				if e.Key != "applied_at" {
					p = append(p, e)
				}
			}
			out = append(out, p)
		}
		return out
	}
	assert.Equal(t, project(loadDocs(t, "schema_migrations.json")), project(dumpDocs(t, db, "schema_migrations")))
}

// TestCompatRead stores Family Hub's documents as they are and reads them through the adapter.
func TestCompatRead(t *testing.T) {
	ctx := t.Context()
	s, dbName := newStoreDB(t)
	db := rawDB(t, dbName)
	for _, name := range dataCollections {
		docs := loadDocs(t, name+".json")
		_, err := db.Collection(name).InsertMany(ctx, docs)
		require.NoError(t, err, name)
	}
	f := fixtures()

	for _, want := range f.accounts {
		got, err := s.Accounts().Get(ctx, want.ID)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	list, err := s.People().ListByAccount(ctx, "acc_fixture1")
	require.NoError(t, err)
	assert.Equal(t, f.people, list)
	for _, want := range f.passkeys {
		got, err := s.Passkeys().GetByCredentialID(ctx, want.CredentialID)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	for _, want := range f.sessions {
		got, err := s.Sessions().Get(ctx, want.IDHash)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}

	setup, err := s.Invites().Peek(ctx, []byte("tok-setup"), t0)
	require.NoError(t, err)
	assert.Equal(t, f.invites[0], setup)
	_, err = s.Invites().Peek(ctx, []byte("tok-member"), t0)
	assert.ErrorIs(t, err, core.ErrUsed)
	_, err = s.Invites().Peek(ctx, []byte("tok-owner"), t0)
	assert.ErrorIs(t, err, core.ErrNotFound, "revoked")
	pending, err := s.Invites().ListByAccount(ctx, "acc_fixture1")
	require.NoError(t, err)
	assert.Empty(t, pending)

	for _, want := range f.clients {
		got, err := s.OAuth().GetClient(ctx, want.ID)
		require.NoError(t, err)
		if want.RedirectURIs == nil {
			want.RedirectURIs = []string{} // Family Hub stores an empty array for none
		}
		assert.Equal(t, want, got)
	}
	code, err := s.OAuth().ConsumeCode(ctx, []byte("code-1"), t0)
	require.NoError(t, err)
	assert.Equal(t, f.codes[0], code)
	for _, want := range f.grants {
		got, err := s.OAuth().GetGrant(ctx, want.ID)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	active, err := s.OAuth().FindGrant(ctx, "per_owner", "cli_dcr", "notes")
	require.NoError(t, err)
	assert.Equal(t, f.grants[0], active)
	for _, want := range f.tokens {
		got, err := s.OAuth().GetToken(ctx, want.Hash)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}

	ids := loadDocs(t, "audit.json")
	acc, err := s.Audit().ListByAccount(ctx, "acc_fixture1", "", 10)
	require.NoError(t, err)
	require.Len(t, acc, 1)
	want := f.audit[0]
	want.ID = ids[0][0].Value.(bson.ObjectID).Hex()
	assert.Equal(t, want, acc[0])
	sys, err := s.Audit().ListSystem(ctx, "", 10)
	require.NoError(t, err)
	require.Len(t, sys, 1)
	want = f.audit[1]
	want.ID = ids[1][0].Value.(bson.ObjectID).Hex()
	assert.Equal(t, want, sys[0])
}

// TestCompatWrite writes the same values through the adapter: every document must equal Family Hub's, field for
// field and in the same field order (the audit's ObjectID aside).
func TestCompatWrite(t *testing.T) {
	ctx := t.Context()
	s, dbName := newStoreDB(t)
	db := rawDB(t, dbName)
	f := fixtures()
	for _, v := range f.accounts {
		require.NoError(t, s.Accounts().Create(ctx, v))
	}
	for _, v := range f.people {
		require.NoError(t, s.People().Create(ctx, v))
	}
	for _, v := range f.passkeys {
		require.NoError(t, s.Passkeys().Add(ctx, v))
	}
	for _, v := range f.sessions {
		require.NoError(t, s.Sessions().Create(ctx, v))
	}
	for _, v := range f.invites {
		require.NoError(t, s.Invites().Create(ctx, v))
	}
	for _, v := range f.clients {
		require.NoError(t, s.OAuth().PutClient(ctx, v))
	}
	for _, v := range f.codes {
		require.NoError(t, s.OAuth().PutCode(ctx, v))
	}
	for _, v := range f.grants {
		require.NoError(t, s.OAuth().PutGrant(ctx, v))
	}
	for _, v := range f.tokens {
		require.NoError(t, s.OAuth().PutToken(ctx, v))
	}
	for _, v := range f.audit {
		require.NoError(t, s.Audit().Append(ctx, v))
	}

	for _, name := range dataCollections {
		want, got := loadDocs(t, name+".json"), dumpDocs(t, db, name)
		require.Len(t, got, len(want), name)
		if name == "audit" {
			for i := range got {
				require.Equal(t, "_id", got[i][0].Key)
				assert.IsType(t, bson.ObjectID{}, got[i][0].Value)
				got[i], want[i] = got[i][1:], want[i][1:]
				sortDetail(got[i])
				sortDetail(want[i])
			}
		}
		assert.Equal(t, want, got, name)
	}
}

// sortDetail orders the keys of an audit entry's detail. It is a Go map, which BSON writes in random order (in Family
// Hub too), so only its contents can be compared.
func sortDetail(d bson.D) {
	for _, e := range d {
		if sub, ok := e.Value.(bson.D); ok && e.Key == "detail" {
			slices.SortFunc(sub, func(a, b bson.E) int { return strings.Compare(a.Key, b.Key) })
		}
	}
}
