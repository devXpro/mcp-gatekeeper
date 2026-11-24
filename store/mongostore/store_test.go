package mongostore

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

func TestMigrationsAreNumberedInOrder(t *testing.T) {
	require.NotEmpty(t, migrations)
	for i, m := range migrations {
		assert.Equal(t, i+1, m.version, "migration %q must have the next version", m.name)
		assert.NotEmpty(t, m.name)
		assert.NotNil(t, m.up)
	}
	// Family Hub recorded these two on its live database; renaming or renumbering them re-runs nothing but misleads.
	assert.Equal(t, "collections and indexes", migrations[0].name)
	assert.Equal(t, "audit retention", migrations[1].name)
}

func TestCollectionsAreTheGatekeepers(t *testing.T) {
	var names []string
	for name := range collections() {
		names = append(names, name)
	}
	assert.ElementsMatch(t, []string{"accounts", "people", "passkeys", "sessions", "invites", "oauth_clients",
		"oauth_codes", "oauth_grants", "oauth_tokens", "audit"}, names)
}

func TestNewOptions(t *testing.T) {
	db := &mongo.Database{}
	tests := []struct {
		name    string
		o       Options
		wantErr string
	}{
		{"nothing", Options{}, "a URI or a DB is required"},
		{"both", Options{URI: "mongodb://localhost", Database: "x", DB: db}, "either a URI or a DB"},
		{"no database", Options{URI: "mongodb://localhost"}, "a database name is required"},
		{"nil cascade", Options{URI: "mongodb://localhost", Database: "x", Cascades: []store.Cascade{nil}}, "cascade 0 is nil"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.o)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}

	s, err := New(Options{URI: "mongodb://localhost:27017", Database: "gk"})
	require.NoError(t, err)
	assert.Equal(t, "gk", s.Database().Name())
	assert.True(t, s.ownsClient)
	require.NoError(t, s.Close())
}

func TestRedactURI(t *testing.T) {
	const uri = "mongodb://user:s3cret@mongo:27017" //nolint:gosec // a fake URI that the test must see redacted
	got := redactURI(errors.New("cannot parse "+uri+": bad option"), uri)
	assert.NotContains(t, got.Error(), "s3cret")
	assert.Contains(t, got.Error(), "<uri>")

	plain := errors.New("no uri here")
	assert.Equal(t, plain, redactURI(plain, uri))
}

func TestNewDoesNotLeakURI(t *testing.T) {
	const uri = "http://user:s3cret@host:27017" //nolint:gosec // a fake URI that must not leak
	_, err := New(Options{URI: uri, Database: "x"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cret")
}

func TestInTxWithoutSession(t *testing.T) {
	assert.False(t, InTx(t.Context()))
}

func TestAuditRejectsBadCursor(t *testing.T) {
	// The cursor is checked before the database is touched, so no Store is needed.
	_, err := auditStore{}.ListByAccount(t.Context(), "acc_a", "not-an-object-id", 10)
	require.Error(t, err)
	_, err = auditStore{}.ListSystem(t.Context(), "zz", 10)
	require.Error(t, err)
}

// The conversions must be lossless for everything Mongo can hold: UTC times to the millisecond, nil optionals.
func TestDocRoundTrips(t *testing.T) {
	at := time.Date(2026, 11, 20, 10, 11, 12, 345_000_000, time.UTC)
	later := at.Add(time.Hour)

	t.Run("session without step-up", func(t *testing.T) {
		s := core.Session{IDHash: []byte{1}, PersonID: "per_a", CreatedAt: at, LastSeenAt: at, ExpiresAt: later}
		d := sessionDoc{IDHash: s.IDHash, PersonID: "per_a", CreatedAt: at, LastSeenAt: at, ExpiresAt: later}
		assert.Equal(t, s, d.toCore())
		d.StepUpUntil = &later
		assert.Equal(t, later, d.toCore().StepUpUntil)
	})
	t.Run("grant", func(t *testing.T) {
		d := grantDoc{ID: "grt_1", PersonID: "per_a", AccountID: "acc_a", ClientID: "cli_a", ResourceID: "m", CreatedAt: at, RevokedAt: &later}
		g := d.toCore()
		assert.Equal(t, core.ResourceID("m"), g.ResourceID)
		require.NotNil(t, g.RevokedAt)
		assert.Equal(t, later, *g.RevokedAt)
		assert.Nil(t, g.LastUsedAt)
	})
	t.Run("a grant's resource is stored as module_id, and an active grant has revoked_at null", func(t *testing.T) {
		raw, err := bson.Marshal(grantDoc{ID: "grt_1", ResourceID: "notes"})
		require.NoError(t, err)
		assert.Equal(t, "notes", bson.Raw(raw).Lookup("module_id").StringValue())
		v, err := bson.Raw(raw).LookupErr("revoked_at")
		require.NoError(t, err)
		assert.Equal(t, bson.TypeNull, v.Type)
		_, err = bson.Raw(raw).LookupErr("resource_id")
		assert.Error(t, err)
	})
	t.Run("times come back in UTC", func(t *testing.T) {
		local := at.In(time.FixedZone("X", 3*3600))
		assert.Equal(t, time.UTC, accountDoc{CreatedAt: local}.toCore().CreatedAt.Location())
	})
}
