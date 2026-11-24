package mongostore

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/devXpro/mcp-gatekeeper/core"
)

type sessionDoc struct {
	IDHash      []byte     `bson:"_id"`
	PersonID    string     `bson:"person_id"`
	CreatedAt   time.Time  `bson:"created_at"`
	LastSeenAt  time.Time  `bson:"last_seen_at"`
	ExpiresAt   time.Time  `bson:"expires_at"`
	StepUpUntil *time.Time `bson:"step_up_until,omitempty"` // absent when there is no step-up
	UserAgent   string     `bson:"user_agent,omitempty"`
}

func (d sessionDoc) toCore() core.Session {
	s := core.Session{
		IDHash: d.IDHash, PersonID: core.PersonID(d.PersonID), CreatedAt: utc(d.CreatedAt),
		LastSeenAt: utc(d.LastSeenAt), ExpiresAt: utc(d.ExpiresAt), UserAgent: d.UserAgent,
	}
	if d.StepUpUntil != nil {
		s.StepUpUntil = utc(*d.StepUpUntil)
	}
	return s
}

type sessionStore struct{ s *Store }

func (st sessionStore) Create(ctx context.Context, s core.Session) error {
	d := sessionDoc{
		IDHash: s.IDHash, PersonID: string(s.PersonID), CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt,
		ExpiresAt: s.ExpiresAt, UserAgent: s.UserAgent,
	}
	if !s.StepUpUntil.IsZero() {
		d.StepUpUntil = &s.StepUpUntil
	}
	return st.s.c(colSessions).insert(ctx, d)
}

func (st sessionStore) Get(ctx context.Context, idHash []byte) (core.Session, error) {
	d, err := findOne[sessionDoc](ctx, st.s.c(colSessions), idIs(idHash))
	if err != nil {
		return core.Session{}, err
	}
	return d.toCore(), nil
}

func (st sessionStore) Touch(ctx context.Context, idHash []byte, at time.Time) error {
	return st.s.c(colSessions).update(ctx, idIs(idHash), set(kv("last_seen_at", at)))
}

func (st sessionStore) SetStepUp(ctx context.Context, idHash []byte, until time.Time) error {
	return st.s.c(colSessions).update(ctx, idIs(idHash), set(kv("step_up_until", until)))
}

// Delete removes a session. A session that is already gone is not an error: logging out twice is fine.
func (st sessionStore) Delete(ctx context.Context, idHash []byte) error {
	_, err := st.s.c(colSessions).deleteMany(ctx, idIs(idHash))
	return err
}

func (st sessionStore) DeleteByPerson(ctx context.Context, p core.PersonID) error {
	_, err := st.s.c(colSessions).deleteMany(ctx, kv("person_id", string(p)))
	return err
}

func (st sessionStore) DeleteExpired(ctx context.Context, now time.Time, idle time.Duration) (int, error) {
	return st.s.c(colSessions).deleteMany(ctx, bson.D{{Key: "$or", Value: bson.A{
		kv("expires_at", kv("$lte", now)),
		kv("last_seen_at", kv("$lt", now.Add(-idle))),
	}}})
}
