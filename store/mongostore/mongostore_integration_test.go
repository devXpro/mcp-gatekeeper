//go:build integration

package mongostore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/internal/testlog"
	"github.com/devXpro/mcp-gatekeeper/store"
	"github.com/devXpro/mcp-gatekeeper/store/mongostore"
	"github.com/devXpro/mcp-gatekeeper/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T, cascades ...store.Cascade) store.Store {
		return newStore(t, cascades...)
	})
}

func TestMigrationsAndIndexes(t *testing.T) {
	ctx := t.Context()
	_, dbName := newStoreDB(t)
	db := rawDB(t, dbName)

	var rec []bson.M
	cur, err := db.Collection("schema_migrations").Find(ctx, bson.D{})
	require.NoError(t, err)
	require.NoError(t, cur.All(ctx, &rec))
	require.Len(t, rec, 2)

	// Opening again applies nothing new, and logs nothing.
	log, logs := testlog.New()
	s2, err := mongostore.Open(ctx, mongostore.Options{URI: mongoURI, Database: dbName, Logger: log})
	require.NoError(t, err)
	require.NoError(t, s2.Close())
	n, err := db.Collection("schema_migrations").CountDocuments(ctx, bson.D{})
	require.NoError(t, err)
	assert.EqualValues(t, 2, n)
	assert.Empty(t, logs.Records())

	names, err := db.ListCollectionNames(ctx, bson.D{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"accounts", "people", "passkeys", "sessions", "invites", "oauth_clients",
		"oauth_codes", "oauth_grants", "oauth_tokens", "audit", "schema_migrations"}, names)

	// TTL indexes: codes, tokens and sessions by expires_at, invites 7 days after it.
	wantTTL := map[string]int32{"oauth_codes": 0, "oauth_tokens": 0, "sessions": 0, "invites": 7 * 24 * 3600}
	for coll, want := range wantTTL {
		specs, err := db.Collection(coll).Indexes().ListSpecifications(ctx)
		require.NoError(t, err)
		var found bool
		for _, sp := range specs {
			if sp.ExpireAfterSeconds != nil {
				found = true
				assert.Equal(t, want, *sp.ExpireAfterSeconds, coll)
			}
		}
		assert.True(t, found, "no TTL index on %s", coll)
	}
}

func TestMigrationsAreLogged(t *testing.T) {
	log, logs := testlog.New()
	dbName := "t_log_" + core.NewID("x")
	raw := rawDB(t, dbName)
	s, err := mongostore.Open(t.Context(), mongostore.Options{URI: mongoURI, Database: dbName, Logger: log})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = raw.Drop(context.Background())
		_ = s.Close()
	})
	recs := logs.Records()
	require.Len(t, recs, 2)
	assert.Equal(t, "migration applied", recs[0].Message)
	assert.Equal(t, "1", recs[0].Attrs["version"])
	assert.Equal(t, "audit retention", recs[1].Attrs["name"])
	assert.False(t, logs.Contains(mongoURI), "the URI is never logged")
}

func TestAuditTTLIndex(t *testing.T) {
	ctx := t.Context()
	_, dbName := newStoreDB(t)
	audit := rawDB(t, dbName).Collection("audit")

	check := func() {
		specs, err := audit.Indexes().ListSpecifications(ctx)
		require.NoError(t, err)
		var found bool
		for _, sp := range specs {
			if sp.ExpireAfterSeconds != nil {
				found = true
				assert.Equal(t, int32(34560000), *sp.ExpireAfterSeconds)
				var keys bson.D
				require.NoError(t, bson.Unmarshal(sp.KeysDocument, &keys))
				require.Len(t, keys, 1)
				assert.Equal(t, "at", keys[0].Key)
			}
		}
		assert.True(t, found, "no TTL index on audit")
	}
	check()

	// A second Open on a database that already has audit documents keeps the index and the documents.
	_, err := audit.InsertOne(ctx, bson.D{{Key: "at", Value: time.Now().UTC()}, {Key: "action", Value: "x"}})
	require.NoError(t, err)
	s2, err := mongostore.Open(ctx, mongostore.Options{URI: mongoURI, Database: dbName})
	require.NoError(t, err)
	require.NoError(t, s2.Close())
	check()
	n, err := audit.CountDocuments(ctx, bson.D{})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
}

func TestAuditIDsAreObjectIDs(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	require.NoError(t, s.Audit().Append(ctx, core.AuditEntry{At: time.Now().UTC(), Action: "test.x"}))
	list, err := s.Audit().ListSystem(ctx, "", 1)
	require.NoError(t, err)
	require.Len(t, list, 1)
	_, err = bson.ObjectIDFromHex(list[0].ID)
	assert.NoError(t, err, "an ObjectID in hex, as Family Hub's audit cursors")
}

// TestSharedDatabase opens the store on an application's own client (Family Hub's way): Close leaves the client
// alone, and the application's own collection joins the store's transactions through the context.
func TestSharedDatabase(t *testing.T) {
	ctx := t.Context()
	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database("t_shared_" + core.NewID("x"))
	t.Cleanup(func() { _ = db.Drop(context.Background()) })

	s, err := mongostore.Open(ctx, mongostore.Options{DB: db})
	require.NoError(t, err)
	assert.Same(t, db, s.Database())

	// The application's collection, made the way Family Hub makes its own; a second call is a no-op.
	modules := mongo.IndexModel{Keys: bson.D{{Key: "module_id", Value: 1}}}
	require.NoError(t, mongostore.EnsureCollection(ctx, db, "account_modules", modules,
		mongo.IndexModel{Keys: bson.D{{Key: "account_id", Value: 1}}}))
	require.NoError(t, mongostore.EnsureCollection(ctx, db, "account_modules", modules))
	require.NoError(t, mongostore.EnsureCollection(ctx, db, "modules"))
	specs, err := db.Collection("account_modules").Indexes().ListSpecifications(ctx)
	require.NoError(t, err)
	assert.Len(t, specs, 3, "_id, module_id and account_id")
	appCol := db.Collection("account_modules")

	boom := errors.New("boom")
	err = s.Tx(ctx, func(ctx context.Context) error {
		assert.True(t, mongostore.InTx(ctx))
		if err := s.Accounts().Create(ctx, core.Account{ID: "acc_1", Name: "A", CreatedAt: time.Now().UTC()}); err != nil {
			return err
		}
		if _, err := appCol.InsertOne(ctx, bson.D{{Key: "_id", Value: "acc_1|notes"}, {Key: "account_id", Value: "acc_1"}}); err != nil {
			return err
		}
		return boom
	})
	require.ErrorIs(t, err, boom)
	n, err := appCol.CountDocuments(ctx, bson.D{})
	require.NoError(t, err)
	assert.Zero(t, n, "the application's write rolled back with the store's")
	_, err = s.Accounts().Get(ctx, "acc_1")
	assert.ErrorIs(t, err, core.ErrNotFound)

	// A cascade deletes the application's rows of an account inside the account delete.
	require.NoError(t, s.Close())
	s, err = mongostore.Open(ctx, mongostore.Options{DB: db, Cascades: []store.Cascade{appCascade{appCol}}})
	require.NoError(t, err)
	require.NoError(t, s.Accounts().Create(ctx, core.Account{ID: "acc_2", Name: "B", CreatedAt: time.Now().UTC()}))
	_, err = appCol.InsertOne(ctx, bson.D{{Key: "_id", Value: "acc_2|notes"}, {Key: "account_id", Value: "acc_2"}})
	require.NoError(t, err)
	require.NoError(t, s.Accounts().Delete(ctx, "acc_2"))
	n, err = appCol.CountDocuments(ctx, bson.D{})
	require.NoError(t, err)
	assert.Zero(t, n)

	require.NoError(t, s.Close())
	require.NoError(t, client.Ping(ctx, nil), "Close leaves a shared client connected")
	assert.False(t, mongostore.InTx(ctx))
}

type appCascade struct{ c *mongo.Collection }

func (a appCascade) DeleteAccount(ctx context.Context, id core.AccountID) error {
	if !mongostore.InTx(ctx) {
		return errors.New("cascade outside a transaction")
	}
	_, err := a.c.DeleteMany(ctx, bson.D{{Key: "account_id", Value: string(id)}})
	return err
}

func (a appCascade) DeletePerson(context.Context, core.PersonID) error { return nil }

func TestOpenFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	const uri = "mongodb://user:s3cret@127.0.0.1:1/?directConnection=true" //nolint:gosec // a fake URI that must not leak
	_, err := mongostore.Open(ctx, mongostore.Options{URI: uri,
		Database: "x", ConnectTimeout: 200 * time.Millisecond})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cret")
}
