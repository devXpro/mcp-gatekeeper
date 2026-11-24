package mongostore

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/devXpro/mcp-gatekeeper/core"
)

type accountDoc struct {
	ID        string    `bson:"_id"`
	Name      string    `bson:"name"`
	CreatedAt time.Time `bson:"created_at"`
}

func (d accountDoc) toCore() core.Account {
	return core.Account{ID: core.AccountID(d.ID), Name: d.Name, CreatedAt: utc(d.CreatedAt)}
}

type accountStore struct{ s *Store }

func (a accountStore) Create(ctx context.Context, acc core.Account) error {
	return a.s.c(colAccounts).insert(ctx, accountDoc{ID: string(acc.ID), Name: acc.Name, CreatedAt: acc.CreatedAt})
}

func (a accountStore) Get(ctx context.Context, id core.AccountID) (core.Account, error) {
	d, err := findOne[accountDoc](ctx, a.s.c(colAccounts), idIs(string(id)))
	if err != nil {
		return core.Account{}, err
	}
	return d.toCore(), nil
}

func (a accountStore) List(ctx context.Context) ([]core.Account, error) {
	docs, err := findAll[accountDoc](ctx, a.s.c(colAccounts), bson.D{}, bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, 0)
	if err != nil {
		return nil, err
	}
	out := make([]core.Account, len(docs))
	for i, d := range docs {
		out[i] = d.toCore()
	}
	return out, nil
}

func (a accountStore) Rename(ctx context.Context, id core.AccountID, name string) error {
	return a.s.c(colAccounts).update(ctx, idIs(string(id)), set(kv("name", name)))
}

// Delete removes the account and everything that hangs on it, in one transaction, then runs the Cascades:
// DeletePerson for each of its people, then DeleteAccount. Audit entries stay.
func (a accountStore) Delete(ctx context.Context, id core.AccountID) error {
	s := a.s
	return s.Tx(ctx, func(ctx context.Context) error {
		if err := s.c(colAccounts).deleteOne(ctx, idIs(string(id))); err != nil {
			return err
		}
		people, err := stringIDs(ctx, s.c(colPeople), kv("account_id", string(id)))
		if err != nil {
			return err
		}
		if err := s.deletePeopleData(ctx, people); err != nil {
			return err
		}
		if _, err := s.c(colPeople).deleteMany(ctx, kv("account_id", string(id))); err != nil {
			return err
		}
		if err := s.deleteGrants(ctx, kv("account_id", string(id))); err != nil {
			return err
		}
		if _, err := s.c(colInvites).deleteMany(ctx, kv("account_id", string(id))); err != nil {
			return err
		}
		return s.cascadeAccount(ctx, id, people)
	})
}

type personDoc struct {
	ID         string     `bson:"_id"`
	AccountID  string     `bson:"account_id"`
	Name       string     `bson:"name"`
	Role       string     `bson:"role"`
	Superadmin bool       `bson:"superadmin"`
	CreatedAt  time.Time  `bson:"created_at"`
	DisabledAt *time.Time `bson:"disabled_at,omitempty"`
}

func (d personDoc) toCore() core.Person {
	return core.Person{
		ID: core.PersonID(d.ID), AccountID: core.AccountID(d.AccountID), Name: d.Name, Role: core.Role(d.Role),
		Superadmin: d.Superadmin, CreatedAt: utc(d.CreatedAt), DisabledAt: optTime(d.DisabledAt),
	}
}

type personStore struct{ s *Store }

func (p personStore) Create(ctx context.Context, person core.Person) error {
	return p.s.c(colPeople).insert(ctx, personDoc{
		ID: string(person.ID), AccountID: string(person.AccountID), Name: person.Name, Role: string(person.Role),
		Superadmin: person.Superadmin, CreatedAt: person.CreatedAt, DisabledAt: optTime(person.DisabledAt),
	})
}

func (p personStore) Get(ctx context.Context, id core.PersonID) (core.Person, error) {
	d, err := findOne[personDoc](ctx, p.s.c(colPeople), idIs(string(id)))
	if err != nil {
		return core.Person{}, err
	}
	return d.toCore(), nil
}

func (p personStore) ListByAccount(ctx context.Context, a core.AccountID) ([]core.Person, error) {
	docs, err := findAll[personDoc](ctx, p.s.c(colPeople), kv("account_id", string(a)),
		bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, 0)
	if err != nil {
		return nil, err
	}
	out := make([]core.Person, len(docs))
	for i, d := range docs {
		out[i] = d.toCore()
	}
	return out, nil
}

// CountSuperadmins counts every person flagged superadmin, disabled ones included: a disabled superadmin is still
// someone the setup link must not replace.
func (p personStore) CountSuperadmins(ctx context.Context) (int, error) {
	n, err := p.s.c(colPeople).count(ctx, kv("superadmin", true))
	return int(n), err
}

func (p personStore) Rename(ctx context.Context, id core.PersonID, name string) error {
	return p.s.c(colPeople).update(ctx, idIs(string(id)), set(kv("name", name)))
}

func (p personStore) Disable(ctx context.Context, id core.PersonID, at time.Time) error {
	return p.s.c(colPeople).update(ctx, idIs(string(id)), set(kv("disabled_at", at)))
}

// Delete removes the person with their passkeys, sessions and grants (and the tokens and codes of those), in one
// transaction, then runs the Cascades' DeletePerson.
func (p personStore) Delete(ctx context.Context, id core.PersonID) error {
	s := p.s
	return s.Tx(ctx, func(ctx context.Context) error {
		if err := s.c(colPeople).deleteOne(ctx, idIs(string(id))); err != nil {
			return err
		}
		if err := s.deletePeopleData(ctx, []string{string(id)}); err != nil {
			return err
		}
		if err := s.deleteGrants(ctx, kv("person_id", string(id))); err != nil {
			return err
		}
		return s.cascadePerson(ctx, id)
	})
}

// deletePeopleData removes the passkeys and sessions of the people. Their grants go through deleteGrants, because
// the caller knows the better filter.
func (s *Store) deletePeopleData(ctx context.Context, people []string) error {
	if len(people) == 0 {
		return nil
	}
	for _, name := range []string{colPasskeys, colSessions} {
		if _, err := s.c(name).deleteMany(ctx, kv("person_id", bson.D{{Key: "$in", Value: people}})); err != nil {
			return err
		}
	}
	return nil
}

// deleteGrants removes the grants matching filter together with their tokens and codes.
func (s *Store) deleteGrants(ctx context.Context, filter bson.D) error {
	ids, err := stringIDs(ctx, s.c(colOAuthGrants), filter)
	if err != nil || len(ids) == 0 {
		return err
	}
	for _, name := range []string{colOAuthTokens, colOAuthCodes} {
		if _, err := s.c(name).deleteMany(ctx, kv("grant_id", bson.D{{Key: "$in", Value: ids}})); err != nil {
			return err
		}
	}
	_, err = s.c(colOAuthGrants).deleteMany(ctx, idIs(bson.D{{Key: "$in", Value: ids}}))
	return err
}
