package sqlitestore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// Paging limits of the audit lists, as in the MongoDB adapter.
const (
	defaultAuditLimit = 50
	maxAuditLimit     = 1000
)

const (
	auditIDBytes = 12
	// auditIDAfterAll sorts after every audit id, so "no cursor" is the cursor "older than anything".
	auditIDAfterAll = "g"
)

// auditIDs makes the audit ids: 12 bytes in 24 lower-case hex characters, like a MongoDB ObjectID, so a page cursor
// looks the same on both adapters. The first 8 bytes are a big-endian counter that starts at the clock's milliseconds
// shifted left by 16 bits and rises by at least one for every id, so ids of one process sort by creation even inside a
// millisecond (or when the clock steps back); the last 4 are random, which keeps two processes on one file apart.
type auditIDs struct {
	mu   sync.Mutex
	last uint64
}

func (a *auditIDs) next(nowMS int64) string {
	a.mu.Lock()
	seq := uint64(nowMS) << 16 //nolint:gosec // milliseconds since the epoch are positive
	if seq <= a.last {
		seq = a.last + 1
	}
	a.last = seq
	a.mu.Unlock()
	var b [auditIDBytes]byte
	binary.BigEndian.PutUint64(b[:8], seq)
	_, _ = rand.Read(b[8:]) // crypto/rand.Read never returns an error since Go 1.24
	return hex.EncodeToString(b[:])
}

// validAuditID reports whether s could be an id made by next, and returns its canonical (lower-case) form.
func validAuditID(s string) (string, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != auditIDBytes {
		return "", false
	}
	return strings.ToLower(s), true
}

const auditCols = `id, at, account_id, actor, action, target, detail, ip`

func scanAudit(r scanner) (core.AuditEntry, error) {
	var (
		e       core.AuditEntry
		at      int64
		account sql.NullString
		actor   string
		detail  sql.NullString
	)
	if err := r.Scan(&e.ID, &at, &account, &actor, &e.Action, &e.Target, &detail, &e.IP); err != nil {
		return core.AuditEntry{}, err
	}
	e.At, e.AccountID, e.Actor = fromMS(at), core.AccountID(account.String), core.PersonID(actor)
	if detail.Valid {
		if err := json.Unmarshal([]byte(detail.String), &e.Detail); err != nil {
			return core.AuditEntry{}, fmt.Errorf("detail of audit entry %q: %w", e.ID, err)
		}
	}
	return e, nil
}

type audit struct{ s *Store }

// Append stores the entry under a new id; e.ID is ignored.
func (a audit) Append(ctx context.Context, e core.AuditEntry) error {
	var detail any
	if len(e.Detail) > 0 {
		raw, err := json.Marshal(e.Detail)
		if err != nil {
			return wrap("append audit", err)
		}
		detail = string(raw)
	}
	var account any
	if e.AccountID != "" {
		account = string(e.AccountID)
	}
	_, err := a.s.exec(ctx, "append audit", `INSERT INTO gk_audit (`+auditCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.s.audit.next(a.s.clock().UnixMilli()), ms(e.At), account, string(e.Actor), e.Action, e.Target, detail, e.IP)
	return err
}

const (
	auditSelect  = `SELECT ` + auditCols + ` FROM gk_audit WHERE `
	auditPage    = ` AND id < ? ORDER BY id DESC LIMIT ?`
	auditOfAcc   = auditSelect + `account_id = ?` + auditPage
	auditOfNoAcc = auditSelect + `account_id IS NULL` + auditPage
)

func (a audit) ListByAccount(ctx context.Context, acc core.AccountID, before string, limit int) ([]core.AuditEntry, error) {
	return a.list(ctx, auditOfAcc, before, limit, string(acc))
}

func (a audit) ListSystem(ctx context.Context, before string, limit int) ([]core.AuditEntry, error) {
	return a.list(ctx, auditOfNoAcc, before, limit)
}

// list pages newest first by id. A before that is not an audit id is an error, not a silent restart. query ends with
// the page condition (id < cursor, limit); args are the ones before it.
func (a audit) list(ctx context.Context, query, before string, limit int, args ...any) ([]core.AuditEntry, error) {
	cursor := auditIDAfterAll
	if before != "" {
		id, ok := validAuditID(before)
		if !ok {
			return nil, fmt.Errorf("sqlitestore: audit cursor %q is not an audit id", before)
		}
		cursor = id
	}
	switch {
	case limit <= 0:
		limit = defaultAuditLimit
	case limit > maxAuditLimit:
		limit = maxAuditLimit
	}
	list, err := queryAll(ctx, a.s.Conn(ctx), scanAudit, query, append(args, cursor, limit)...)
	return list, wrap("list audit", err)
}
