package sqlitestore

import (
	"context"
	"time"

	"github.com/devXpro/mcp-gatekeeper/store"
)

// Retention of Purge. It follows the TTL indexes of the MongoDB adapter (and package oauth's idle client life), so
// the two adapters keep the same data for the same time.
const (
	inviteKeepAfter = 7 * 24 * time.Hour   // an invite stays this long past its expiry, so Peek can tell used from unknown
	auditKeep       = 400 * 24 * time.Hour // an audit entry is kept this long
	idleClientAfter = time.Hour            // a DCR client without a grant is deleted after this
)

var _ store.Purger = (*Store)(nil)

// Purge implements store.Purger. In one transaction it deletes:
//   - tokens and codes whose end has been reached (ExpiresAt <= now);
//   - invites 7 days after their expiry;
//   - audit entries older than 400 days;
//   - DCR clients older than an hour that no grant points at (DeleteIdleClients).
//
// Sessions are not here: the sign-in package sweeps them with SessionStore.DeleteExpired.
func (s *Store) Purge(ctx context.Context, now time.Time) (store.PurgeStats, error) {
	var st store.PurgeStats
	err := s.write(ctx, func(ctx context.Context, q Conn) error {
		st = store.PurgeStats{} // a transaction that ran again must not count twice
		for _, step := range []struct {
			n     *int
			query string
			arg   int64
		}{
			{&st.Tokens, `DELETE FROM gk_oauth_tokens WHERE expires_at <= ?`, ms(now)},
			{&st.Codes, `DELETE FROM gk_oauth_codes WHERE expires_at <= ?`, ms(now)},
			{&st.Invites, `DELETE FROM gk_invites WHERE expires_at <= ?`, ms(now.Add(-inviteKeepAfter))},
			{&st.Audit, `DELETE FROM gk_audit WHERE at <= ?`, ms(now.Add(-auditKeep))},
		} {
			res, err := q.ExecContext(ctx, step.query, step.arg)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			*step.n = int(n)
		}
		var err error
		st.Clients, err = oauth{s}.DeleteIdleClients(ctx, now.Add(-idleClientAfter))
		return err
	})
	if err != nil {
		return store.PurgeStats{}, wrap("purge", err)
	}
	return st, nil
}
