package mongostore

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// Paging limits of the audit lists.
const (
	defaultAuditLimit = 50
	maxAuditLimit     = 1000
)

type auditDoc struct {
	ID        bson.ObjectID     `bson:"_id"`
	At        time.Time         `bson:"at"`
	AccountID string            `bson:"account_id,omitempty"` // absent for system events
	Actor     string            `bson:"actor,omitempty"`
	Action    string            `bson:"action"`
	Target    string            `bson:"target,omitempty"`
	Detail    map[string]string `bson:"detail,omitempty"`
	IP        string            `bson:"ip,omitempty"`
}

func (d auditDoc) toCore() core.AuditEntry {
	return core.AuditEntry{
		ID: d.ID.Hex(), At: utc(d.At), AccountID: core.AccountID(d.AccountID), Actor: core.PersonID(d.Actor),
		Action: d.Action, Target: d.Target, Detail: d.Detail, IP: d.IP,
	}
}

type auditStore struct{ s *Store }

// Append stores the entry under a new ObjectID; e.ID is ignored.
func (a auditStore) Append(ctx context.Context, e core.AuditEntry) error {
	return a.s.c(colAudit).insert(ctx, auditDoc{
		ID: bson.NewObjectID(), At: e.At, AccountID: string(e.AccountID), Actor: string(e.Actor), Action: e.Action,
		Target: e.Target, Detail: e.Detail, IP: e.IP,
	})
}

func (a auditStore) ListByAccount(ctx context.Context, acc core.AccountID, before string, limit int) ([]core.AuditEntry, error) {
	return a.list(ctx, kv("account_id", string(acc)), before, limit)
}

func (a auditStore) ListSystem(ctx context.Context, before string, limit int) ([]core.AuditEntry, error) {
	return a.list(ctx, kv("account_id", kv("$exists", false)), before, limit)
}

// list pages newest first by _id. A before that is not an audit id is an error, not a silent restart.
func (a auditStore) list(ctx context.Context, filter bson.D, before string, limit int) ([]core.AuditEntry, error) {
	if before != "" {
		oid, err := bson.ObjectIDFromHex(before)
		if err != nil {
			return nil, fmt.Errorf("mongostore: audit cursor %q is not an audit id: %w", before, err)
		}
		filter = append(filter, bson.E{Key: "_id", Value: kv("$lt", oid)})
	}
	switch {
	case limit <= 0:
		limit = defaultAuditLimit
	case limit > maxAuditLimit:
		limit = maxAuditLimit
	}
	docs, err := findAll[auditDoc](ctx, a.s.c(colAudit), filter, kv("_id", -1), int64(limit))
	if err != nil {
		return nil, err
	}
	out := make([]core.AuditEntry, len(docs))
	for i, d := range docs {
		out[i] = d.toCore()
	}
	return out, nil
}
