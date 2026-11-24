//go:build integration

// This file is not built here (the go tool skips testdata). It generated the fixtures of this directory's parent from
// Family Hub's own store code, on a throwaway copy of the Family Hub repository:
//
//	rsync -a --exclude node_modules --exclude .git --exclude web <family-hub>/ /tmp/g1-fh/
//	cp dump_integration_test.go /tmp/g1-fh/internal/store/
//	G1_FIXTURES_OUT=<this testdata/familyhub dir> go -C /tmp/g1-fh test -tags integration -count=1 \
//	    -run TestDumpFixtures ./internal/store/
//
// It writes known values through Family Hub's store.Store into a fresh database and dumps every collection the
// gatekeeper owns (canonical extended JSON, sorted by _id) and every collection's index specifications. The values
// must stay equal to the ones in compat_integration_test.go.

package store_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/devXpro/family-hub/internal/core"
)

func TestDumpFixtures(t *testing.T) {
	out := os.Getenv("G1_FIXTURES_OUT")
	if out == "" {
		t.Skip("G1_FIXTURES_OUT is not set")
	}
	s, dbName := newStoreDB(t)
	t0 := time.Date(2036, 1, 2, 10, 11, 12, 345_000_000, time.UTC) // far ahead: the TTL monitor must not touch the fixtures
	at := func(d time.Duration) *time.Time { v := t0.Add(d); return &v }

	require.NoError(t, s.Accounts().Create(ctx, core.Account{ID: "acc_fixture1", Name: "Kowalscy", CreatedAt: t0}))
	require.NoError(t, s.People().Create(ctx, core.Person{ID: "per_owner", AccountID: "acc_fixture1", Name: "Alice",
		Role: core.RoleOwner, Superadmin: true, CreatedAt: t0}))
	require.NoError(t, s.People().Create(ctx, core.Person{ID: "per_member", AccountID: "acc_fixture1", Name: "Bella",
		Role: core.RoleMember, CreatedAt: t0.Add(time.Minute), DisabledAt: at(time.Hour)}))
	require.NoError(t, s.Passkeys().Add(ctx, core.Passkey{ID: "pk_1", PersonID: "per_owner", CredentialID: []byte{1, 2, 3},
		Data: []byte(`{"id":"AQID"}`), Name: "iPhone", CreatedAt: t0, LastUsedAt: at(2 * time.Hour)}))
	require.NoError(t, s.Passkeys().Add(ctx, core.Passkey{ID: "pk_2", PersonID: "per_member", CredentialID: []byte{4, 5},
		Data: []byte(`{}`), Name: "", CreatedAt: t0}))
	require.NoError(t, s.Sessions().Create(ctx, core.Session{IDHash: []byte("sess-1"), PersonID: "per_owner", CreatedAt: t0,
		LastSeenAt: t0.Add(time.Minute), ExpiresAt: t0.Add(30 * 24 * time.Hour), StepUpUntil: t0.Add(5 * time.Minute),
		UserAgent: "Mozilla/5.0"}))
	require.NoError(t, s.Sessions().Create(ctx, core.Session{IDHash: []byte("sess-2"), PersonID: "per_member", CreatedAt: t0,
		LastSeenAt: t0, ExpiresAt: t0.Add(24 * time.Hour)}))
	require.NoError(t, s.Invites().Create(ctx, core.Invite{ID: "inv_setup", TokenHash: []byte("tok-setup"), Kind: core.InviteSetup,
		CreatedAt: t0, ExpiresAt: t0.Add(15 * time.Minute)}))
	require.NoError(t, s.Invites().Create(ctx, core.Invite{ID: "inv_member", TokenHash: []byte("tok-member"), Kind: core.InviteMember,
		AccountID: "acc_fixture1", Name: "Bella", CreatedBy: "per_owner", CreatedAt: t0, ExpiresAt: t0.Add(72 * time.Hour),
		UsedAt: at(time.Hour)}))
	require.NoError(t, s.Invites().Create(ctx, core.Invite{ID: "inv_owner", TokenHash: []byte("tok-owner"), Kind: core.InviteOwner,
		AccountID: "acc_fixture1", Name: "Owner", CreatedBy: "per_owner", CreatedAt: t0, ExpiresAt: t0.Add(72 * time.Hour),
		RevokedAt: at(time.Hour)}))
	require.NoError(t, s.OAuth().PutClient(ctx, core.OAuthClient{ID: "cli_dcr", Kind: core.ClientDCR, Assistant: core.AssistantChatGPT,
		Name: "ChatGPT", RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
		AuthMethod: "client_secret_post", SecretHash: []byte("secret-hash"), FetchedAt: t0, CreatedAt: t0, LastUsedAt: at(time.Hour)}))
	require.NoError(t, s.OAuth().PutClient(ctx, core.OAuthClient{ID: "https://claude.ai/oauth/claude-code-client-metadata",
		Kind: core.ClientCIMD, Assistant: core.AssistantClaude, Name: "Claude", AuthMethod: "none", FetchedAt: t0, CreatedAt: t0}))
	require.NoError(t, s.OAuth().PutCode(ctx, core.AuthCode{CodeHash: []byte("code-1"), GrantID: "grt_active", ClientID: "cli_dcr",
		RedirectURI: "https://chatgpt.com/connector_platform_oauth_redirect", Resource: "https://family.example.com/mcp/notes",
		Scope: "mcp", CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CreatedAt: t0, ExpiresAt: t0.Add(5 * time.Minute)}))
	require.NoError(t, s.OAuth().PutGrant(ctx, core.Grant{ID: "grt_active", PersonID: "per_owner", AccountID: "acc_fixture1",
		ClientID: "cli_dcr", ModuleID: "notes", Scope: "mcp", CreatedAt: t0}))
	require.NoError(t, s.OAuth().PutGrant(ctx, core.Grant{ID: "grt_revoked", PersonID: "per_member", AccountID: "acc_fixture1",
		ClientID: "https://claude.ai/oauth/claude-code-client-metadata", ModuleID: "photos", Scope: "mcp offline_access",
		CreatedAt: t0, LastUsedAt: at(time.Minute), RevokedAt: at(time.Hour)}))
	require.NoError(t, s.OAuth().PutToken(ctx, core.Token{Hash: []byte("access-1"), GrantID: "grt_active", Kind: core.TokenAccess,
		Family: "fam-1", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}))
	require.NoError(t, s.OAuth().PutToken(ctx, core.Token{Hash: []byte("refresh-1"), GrantID: "grt_active", Kind: core.TokenRefresh,
		Family: "fam-1", CreatedAt: t0, ExpiresAt: t0.Add(30 * 24 * time.Hour), UsedAt: at(time.Minute)}))
	require.NoError(t, s.OAuth().PutToken(ctx, core.Token{Hash: []byte("refresh-2"), GrantID: "grt_revoked", Kind: core.TokenRefresh,
		Family: "fam-2", CreatedAt: t0, ExpiresAt: t0.Add(30 * 24 * time.Hour), RevokedAt: at(time.Hour)}))
	require.NoError(t, s.Audit().Append(ctx, core.AuditEntry{At: t0, AccountID: "acc_fixture1", Actor: "per_owner",
		Action: "oauth.consent", Target: "notes", Detail: map[string]string{"client": "ChatGPT", "scope": "mcp"}, IP: "203.0.113.5"}))
	require.NoError(t, s.Audit().Append(ctx, core.AuditEntry{At: t0, Action: "setup.link"}))

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(ctx) })
	db := client.Database(dbName)

	dump := func(file string, docs []bson.Raw) {
		var buf []byte
		buf = append(buf, "[\n"...)
		for i, d := range docs {
			j, err := bson.MarshalExtJSONIndent(d, true, false, "  ", "  ")
			require.NoError(t, err)
			buf = append(buf, "  "...)
			buf = append(buf, j...)
			if i < len(docs)-1 {
				buf = append(buf, ',')
			}
			buf = append(buf, '\n')
		}
		buf = append(buf, "]\n"...)
		require.NoError(t, os.WriteFile(filepath.Join(out, file), buf, 0o600))
	}
	names, err := db.ListCollectionNames(ctx, bson.D{})
	require.NoError(t, err)
	for _, name := range names {
		cur, err := db.Collection(name).Indexes().List(ctx)
		require.NoError(t, err)
		var specs []bson.Raw
		require.NoError(t, cur.All(ctx, &specs))
		dump("indexes."+name+".json", specs)
		switch name {
		case "modules", "account_modules", "legacy_keys":
			continue // Family Hub's own collections
		}
		cur, err = db.Collection(name).Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
		require.NoError(t, err)
		var docs []bson.Raw
		require.NoError(t, cur.All(ctx, &docs))
		dump(name+".json", docs)
	}
}
