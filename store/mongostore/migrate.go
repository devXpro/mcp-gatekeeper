package mongostore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// A migration is applied once and recorded in schema_migrations. Append new ones with the next version; never edit
// or reorder one that has shipped.
//
// Versions 1 and 2 are the ones Family Hub recorded on its live database, so that database migrates nothing. Family
// Hub's version 1 also created its own collections (modules, account_modules, legacy_keys); the gatekeeper's does
// not know them, and Family Hub creates them with EnsureCollection. schema_migrations belongs to the gatekeeper: an
// application records its own migrations elsewhere.
type migration struct {
	version int
	name    string
	up      func(ctx context.Context, db *mongo.Database) error
}

var migrations = []migration{
	{version: 1, name: "collections and indexes", up: migrateCollectionsAndIndexes},
	{version: 2, name: "audit retention", up: migrateAuditRetention},
}

const (
	secondsPerDay   = 24 * 60 * 60
	inviteKeepAfter = 7 * secondsPerDay   // invites are kept 7 days past expires_at, so Peek can tell used from unknown
	auditKeepAfter  = 400 * secondsPerDay // the audit is kept 400 days (Family Hub T2.R decision 3)
	nsExistsCode    = 48
)

type migrationRecord struct {
	Version   int       `bson:"_id"`
	Name      string    `bson:"name"`
	AppliedAt time.Time `bson:"applied_at"`
}

// migrate applies the migrations that schema_migrations does not list, in order.
func migrate(ctx context.Context, db *mongo.Database, log *slog.Logger) error {
	cur, err := db.Collection(colMigrations).Find(ctx, bson.D{})
	if err != nil {
		return fmt.Errorf("mongostore: list migrations: %w", err)
	}
	var done []migrationRecord
	if err := cur.All(ctx, &done); err != nil {
		return fmt.Errorf("mongostore: list migrations: %w", err)
	}
	applied := make(map[int]bool, len(done))
	for _, r := range done {
		applied[r.Version] = true
	}
	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if err := m.up(ctx, db); err != nil {
			return fmt.Errorf("mongostore: migration %d (%s): %w", m.version, m.name, err)
		}
		_, err := db.Collection(colMigrations).InsertOne(ctx, migrationRecord{
			Version: m.version, Name: m.name, AppliedAt: time.Now().UTC(),
		})
		if err != nil && !mongo.IsDuplicateKeyError(err) { // a duplicate: another starter recorded it first
			return fmt.Errorf("mongostore: record migration %d: %w", m.version, err)
		}
		log.Info("migration applied", slog.Int("version", m.version), slog.String("name", m.name))
	}
	return nil
}

// EnsureCollection creates the collection name in db, if it does not exist, and the indexes. Creating an index that
// exists with the same keys and options is a no-op, so it is safe at every start; an index whose name exists with
// other options is an error. Collections must exist before a transaction writes to them.
func EnsureCollection(ctx context.Context, db *mongo.Database, name string, indexes ...mongo.IndexModel) error {
	if err := db.CreateCollection(ctx, name); err != nil {
		var ce mongo.CommandError
		if !errors.As(err, &ce) || ce.Code != nsExistsCode {
			return fmt.Errorf("mongostore: create collection %s: %w", name, err)
		}
	}
	if len(indexes) == 0 {
		return nil
	}
	if _, err := db.Collection(name).Indexes().CreateMany(ctx, indexes); err != nil {
		return fmt.Errorf("mongostore: create indexes of %s: %w", name, err)
	}
	return nil
}

func index(opts *options.IndexOptionsBuilder, keys ...bson.E) mongo.IndexModel {
	return mongo.IndexModel{Keys: bson.D(keys), Options: opts}
}

func asc(field string) bson.E  { return bson.E{Key: field, Value: 1} }
func desc(field string) bson.E { return bson.E{Key: field, Value: -1} }

// ttlOnExpiry is an index that removes a document afterSeconds after its expires_at.
func ttlOnExpiry(afterSeconds int32) mongo.IndexModel {
	return index(options.Index().SetExpireAfterSeconds(afterSeconds), asc("expires_at"))
}

// collections lists every collection of the gatekeeper with the indexes migration 1 creates. The names of the
// indexes are the server's defaults (e.g. "person_id_1_client_id_1_module_id_1"), as on Family Hub's database.
func collections() map[string][]mongo.IndexModel {
	return map[string][]mongo.IndexModel{
		colAccounts: nil,
		colPeople:   {index(nil, asc("account_id"))},
		colPasskeys: {
			index(nil, asc("person_id")),
			index(options.Index().SetUnique(true), asc("credential_id")),
		},
		colSessions: {
			index(nil, asc("person_id")),
			index(nil, asc("last_seen_at")),
			ttlOnExpiry(0),
		},
		colInvites: {
			index(options.Index().SetUnique(true), asc("token_hash")),
			index(nil, asc("account_id")),
			ttlOnExpiry(inviteKeepAfter),
		},
		colOAuthClients: {index(nil, asc("kind"), asc("created_at"))},
		colOAuthCodes: {
			index(nil, asc("grant_id")),
			ttlOnExpiry(0),
		},
		colOAuthGrants: {
			index(nil, asc("account_id")),
			index(nil, asc("person_id")),
			index(nil, asc("module_id")),
			index(nil, asc("client_id")),
			// One active grant per (person, client, resource); a revoked one has a revoked_at date and leaves the
			// index. The resource is stored as module_id, Family Hub's name for it.
			index(options.Index().SetUnique(true).SetPartialFilterExpression(bson.D{{Key: "revoked_at", Value: bson.D{{Key: "$type", Value: "null"}}}}),
				asc("person_id"), asc("client_id"), asc("module_id")),
		},
		colOAuthTokens: {
			index(nil, asc("grant_id")),
			index(nil, asc("family")),
			ttlOnExpiry(0),
		},
		colAudit: {index(nil, asc("account_id"), desc("_id"))},
	}
}

// migrateCollectionsAndIndexes creates every collection (so transactions find them) and its indexes.
func migrateCollectionsAndIndexes(ctx context.Context, db *mongo.Database) error {
	for name, models := range collections() {
		if err := EnsureCollection(ctx, db, name, models...); err != nil {
			return err
		}
	}
	return nil
}

// migrateAuditRetention adds a TTL index that removes an audit entry auditKeepAfter seconds after its at. Creating an
// index with the same spec is a no-op, so a re-run is safe; existing documents are simply aged by the TTL monitor.
func migrateAuditRetention(ctx context.Context, db *mongo.Database) error {
	_, err := db.Collection(colAudit).Indexes().CreateOne(ctx,
		index(options.Index().SetExpireAfterSeconds(auditKeepAfter), asc("at")))
	if err != nil {
		return fmt.Errorf("create audit ttl index: %w", err)
	}
	return nil
}
