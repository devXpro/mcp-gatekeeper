package sqlitestore

import (
	"context"
	"database/sql"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

const sessionCols = `id_hash, person_id, created_at, last_seen_at, expires_at, step_up_until, user_agent`

func scanSession(r scanner) (core.Session, error) {
	var (
		s                      core.Session
		person                 string
		created, seen, expires int64
		stepUp                 sql.NullInt64
	)
	if err := r.Scan(&s.IDHash, &person, &created, &seen, &expires, &stepUp, &s.UserAgent); err != nil {
		return core.Session{}, err
	}
	s.PersonID, s.CreatedAt, s.LastSeenAt = core.PersonID(person), fromMS(created), fromMS(seen)
	s.ExpiresAt, s.StepUpUntil = fromMS(expires), zeroTime(stepUp)
	return s, nil
}

type sessions struct{ s *Store }

func (st sessions) Create(ctx context.Context, s core.Session) error {
	_, err := st.s.exec(ctx, "create session", `INSERT INTO gk_sessions (`+sessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		blob(s.IDHash), string(s.PersonID), ms(s.CreatedAt), ms(s.LastSeenAt), ms(s.ExpiresAt), zeroMS(s.StepUpUntil), s.UserAgent)
	return err
}

func (st sessions) Get(ctx context.Context, idHash []byte) (core.Session, error) {
	s, err := scanSession(st.s.Conn(ctx).QueryRowContext(ctx, `SELECT `+sessionCols+` FROM gk_sessions WHERE id_hash = ?`, blob(idHash)))
	return s, wrap("get session", err)
}

func (st sessions) Touch(ctx context.Context, idHash []byte, at time.Time) error {
	return st.s.execOne(ctx, "touch session", `UPDATE gk_sessions SET last_seen_at = ? WHERE id_hash = ?`, ms(at), blob(idHash))
}

func (st sessions) SetStepUp(ctx context.Context, idHash []byte, until time.Time) error {
	return st.s.execOne(ctx, "set step-up", `UPDATE gk_sessions SET step_up_until = ? WHERE id_hash = ?`, zeroMS(until), blob(idHash))
}

// Delete removes a session. A session that is already gone is not an error: logging out twice is fine.
func (st sessions) Delete(ctx context.Context, idHash []byte) error {
	_, err := st.s.exec(ctx, "delete session", `DELETE FROM gk_sessions WHERE id_hash = ?`, blob(idHash))
	return err
}

func (st sessions) DeleteByPerson(ctx context.Context, p core.PersonID) error {
	_, err := st.s.exec(ctx, "delete sessions", `DELETE FROM gk_sessions WHERE person_id = ?`, string(p))
	return err
}

// DeleteExpired removes sessions whose absolute end is reached (expires_at <= now) or that were last seen before
// now-idle.
func (st sessions) DeleteExpired(ctx context.Context, now time.Time, idle time.Duration) (int, error) {
	n, err := st.s.exec(ctx, "delete expired sessions", `DELETE FROM gk_sessions WHERE expires_at <= ? OR last_seen_at < ?`,
		ms(now), ms(now.Add(-idle)))
	return int(n), err
}
