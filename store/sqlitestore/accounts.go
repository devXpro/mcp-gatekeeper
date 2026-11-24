package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

const accountCols = `id, name, created_at`

func scanAccount(r scanner) (core.Account, error) {
	var (
		a       core.Account
		id      string
		created int64
	)
	if err := r.Scan(&id, &a.Name, &created); err != nil {
		return core.Account{}, err
	}
	a.ID, a.CreatedAt = core.AccountID(id), fromMS(created)
	return a, nil
}

type accounts struct{ s *Store }

func (a accounts) Create(ctx context.Context, acc core.Account) error {
	_, err := a.s.exec(ctx, "create account", `INSERT INTO gk_accounts (id, name, created_at) VALUES (?, ?, ?)`,
		string(acc.ID), acc.Name, ms(acc.CreatedAt))
	return err
}

func (a accounts) Get(ctx context.Context, id core.AccountID) (core.Account, error) {
	acc, err := scanAccount(a.s.Conn(ctx).QueryRowContext(ctx, `SELECT `+accountCols+` FROM gk_accounts WHERE id = ?`, string(id)))
	return acc, wrap("get account", err)
}

func (a accounts) List(ctx context.Context) ([]core.Account, error) {
	list, err := queryAll(ctx, a.s.Conn(ctx), scanAccount, `SELECT `+accountCols+` FROM gk_accounts ORDER BY created_at, id`)
	return list, wrap("list accounts", err)
}

func (a accounts) Rename(ctx context.Context, id core.AccountID, name string) error {
	return a.s.execOne(ctx, "rename account", `UPDATE gk_accounts SET name = ? WHERE id = ?`, name, string(id))
}

// Delete removes the account and everything that hangs on it in one transaction: its people (each with their own
// rows, then the Cascades' DeletePerson), its grants with their tokens and codes, its invites, then the Cascades'
// DeleteAccount. Audit entries stay.
func (a accounts) Delete(ctx context.Context, id core.AccountID) error {
	const op = "delete account"
	return wrap(op, a.s.Tx(ctx, func(ctx context.Context) error {
		q := a.s.Conn(ctx)
		res, err := q.ExecContext(ctx, `DELETE FROM gk_accounts WHERE id = ?`, string(id))
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			if err != nil {
				return err
			}
			return sql.ErrNoRows
		}
		ids, err := queryAll(ctx, q, scanString, `SELECT id FROM gk_people WHERE account_id = ? ORDER BY created_at, id`, string(id))
		if err != nil {
			return err
		}
		for _, pid := range ids {
			if err := a.s.deletePerson(ctx, core.PersonID(pid)); err != nil {
				return err
			}
		}
		if err := deleteGrants(ctx, q, grantsOfAccount, string(id)); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx, `DELETE FROM gk_invites WHERE account_id = ?`, string(id)); err != nil {
			return err
		}
		for _, c := range a.s.cascades {
			if err := c.DeleteAccount(ctx, id); err != nil {
				return fmt.Errorf("cascade: %w", err)
			}
		}
		return nil
	}))
}

func scanString(r scanner) (string, error) {
	var v string
	err := r.Scan(&v)
	return v, err
}

const personCols = `id, account_id, name, role, superadmin, created_at, disabled_at`

func scanPerson(r scanner) (core.Person, error) {
	var (
		p                 core.Person
		id, account, role string
		superadmin        int
		created           int64
		disabled          sql.NullInt64
	)
	if err := r.Scan(&id, &account, &p.Name, &role, &superadmin, &created, &disabled); err != nil {
		return core.Person{}, err
	}
	p.ID, p.AccountID, p.Role = core.PersonID(id), core.AccountID(account), core.Role(role)
	p.Superadmin, p.CreatedAt, p.DisabledAt = superadmin != 0, fromMS(created), optTime(disabled)
	return p, nil
}

type people struct{ s *Store }

func (p people) Create(ctx context.Context, person core.Person) error {
	_, err := p.s.exec(ctx, "create person", `INSERT INTO gk_people (`+personCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		string(person.ID), string(person.AccountID), person.Name, string(person.Role), boolInt(person.Superadmin),
		ms(person.CreatedAt), optMS(person.DisabledAt))
	return err
}

func (p people) Get(ctx context.Context, id core.PersonID) (core.Person, error) {
	person, err := scanPerson(p.s.Conn(ctx).QueryRowContext(ctx, `SELECT `+personCols+` FROM gk_people WHERE id = ?`, string(id)))
	return person, wrap("get person", err)
}

func (p people) ListByAccount(ctx context.Context, a core.AccountID) ([]core.Person, error) {
	list, err := queryAll(ctx, p.s.Conn(ctx), scanPerson,
		`SELECT `+personCols+` FROM gk_people WHERE account_id = ? ORDER BY created_at, id`, string(a))
	return list, wrap("list people", err)
}

// CountSuperadmins counts every person flagged superadmin, disabled ones included: a disabled superadmin is still
// someone the setup link must not replace.
func (p people) CountSuperadmins(ctx context.Context) (int, error) {
	var n int
	err := p.s.Conn(ctx).QueryRowContext(ctx, `SELECT COUNT(*) FROM gk_people WHERE superadmin = 1`).Scan(&n)
	return n, wrap("count superadmins", err)
}

func (p people) Rename(ctx context.Context, id core.PersonID, name string) error {
	return p.s.execOne(ctx, "rename person", `UPDATE gk_people SET name = ? WHERE id = ?`, name, string(id))
}

func (p people) Disable(ctx context.Context, id core.PersonID, at time.Time) error {
	return p.s.execOne(ctx, "disable person", `UPDATE gk_people SET disabled_at = ? WHERE id = ?`, ms(at), string(id))
}

// Delete removes the person with their passkeys, sessions, grants (and the tokens and codes of those), then runs the
// Cascades' DeletePerson, in one transaction.
func (p people) Delete(ctx context.Context, id core.PersonID) error {
	const op = "delete person"
	return wrap(op, p.s.Tx(ctx, func(ctx context.Context) error {
		res, err := p.s.Conn(ctx).ExecContext(ctx, `DELETE FROM gk_people WHERE id = ?`, string(id))
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			if err != nil {
				return err
			}
			return sql.ErrNoRows
		}
		return p.s.deletePersonData(ctx, id)
	}))
}

// deletePerson removes a person's row and everything of theirs; the caller is inside a transaction.
func (s *Store) deletePerson(ctx context.Context, id core.PersonID) error {
	if _, err := s.Conn(ctx).ExecContext(ctx, `DELETE FROM gk_people WHERE id = ?`, string(id)); err != nil {
		return err
	}
	return s.deletePersonData(ctx, id)
}

// deletePersonData removes what hangs on a person whose row is already gone, then runs the Cascades.
func (s *Store) deletePersonData(ctx context.Context, id core.PersonID) error {
	q := s.Conn(ctx)
	for _, stmt := range []string{
		`DELETE FROM gk_passkeys WHERE person_id = ?`,
		`DELETE FROM gk_sessions WHERE person_id = ?`,
	} {
		if _, err := q.ExecContext(ctx, stmt, string(id)); err != nil {
			return err
		}
	}
	if err := deleteGrants(ctx, q, grantsOfPerson, string(id)); err != nil {
		return err
	}
	for _, c := range s.cascades {
		if err := c.DeletePerson(ctx, id); err != nil {
			return fmt.Errorf("cascade: %w", err)
		}
	}
	return nil
}
