package people

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
	"github.com/devXpro/mcp-gatekeeper/people/actorname"
)

// CodeInvalidPermission is the error code of a permission the application does not offer (400).
const CodeInvalidPermission = "invalid_permission"

// ErrWidens is Service.UpdateMember's refusal of a change that gives the person more access (a later or no end, or
// a permission they lacked) when the caller has not confirmed it with step-up. Nothing was changed.
var ErrWidens = errors.New("people: the change widens the person's access; confirm it with step-up")

// Refusals of terms, permissions and roles.
var (
	errNoTerms       = invalid("this application offers no access terms")
	errNoPermissions = NewError(http.StatusBadRequest, CodeInvalidPermission, "this application offers no permissions")
	errBadPermission = NewError(http.StatusBadRequest, CodeInvalidPermission,
		"a permission is not one this application offers")
	errBadUntil       = invalid("access_until must be an RFC 3339 time")
	errPastUntil      = invalid("access_until must be in the future")
	errFarUntil       = invalid("access_until must be at most one year away")
	errNoRole         = invalid("role is not offered here")
	errBadRole        = invalid(`role must be "member" or "owner"`)
	errOwnerAccess    = invalid("an owner has every permission and no access term")
	errNoChange       = invalid("send access_until or permissions")
	errSelfAccess     = invalid("you cannot change your own access")
	errSuperadminTerm = NewError(http.StatusConflict, httpsec.CodeConflict,
		"a superadmin's access cannot be limited")
)

// maxTerm is how far away an access term may end: one year from now.
func maxTerm(now time.Time) time.Time { return now.AddDate(1, 0, 0) }

// parseUntil reads an access_until value: RFC 3339, kept in UTC to the millisecond, as the stores keep it.
func parseUntil(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, errBadUntil
	}
	return t.UTC().Truncate(time.Millisecond), nil
}

// inviteAccess checks the term and the permissions of a member invite and returns them as stored.
func (s *Service) inviteAccess(ctx context.Context, a core.AccountID, spec InviteSpec) (*time.Time, []string,
	error) {
	var until *time.Time
	if spec.AccessUntil != nil {
		if s.o.Permissions == nil {
			return nil, nil, errNoTerms
		}
		now := s.now()
		u := spec.AccessUntil.UTC().Truncate(time.Millisecond)
		switch {
		case !u.After(now):
			return nil, nil, errPastUntil
		case u.After(maxTerm(now)):
			return nil, nil, errFarUntil
		}
		until = &u
	}
	if spec.Permissions == nil {
		return until, nil, nil
	}
	perms, err := s.permissions(ctx, a, spec.Permissions)
	return until, perms, err
}

// permissions checks ids against the catalog of account a and returns them sorted without repeats; with
// core.PermissionAll among them, that alone. No ids is nil.
func (s *Service) permissions(ctx context.Context, a core.AccountID, ids []string) ([]string, error) {
	if s.o.Permissions == nil {
		return nil, errNoPermissions
	}
	if len(ids) == 0 {
		return nil, nil
	}
	offered, err := s.o.Permissions.Permissions(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("people: the permission catalog: %w", err)
	}
	known := map[string]bool{core.PermissionAll: true}
	for _, p := range offered {
		known[p.ID] = true
	}
	for _, id := range ids {
		if !known[id] {
			return nil, errBadPermission
		}
	}
	if slices.Contains(ids, core.PermissionAll) {
		return []string{core.PermissionAll}, nil
	}
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out), nil
}

// accessDetail is the audit detail of a term and permissions that were set: access_until (RFC 3339, or "none" for
// no end) and permissions (ids, comma-separated). Never more than ids: no titles, no application data.
func accessDetail(setUntil bool, until *time.Time, setPerms bool, perms []string) map[string]string {
	out := map[string]string{}
	if setUntil {
		out["access_until"] = "none"
		if until != nil {
			out["access_until"] = rfc3339(*until)
		}
	}
	if setPerms {
		out["permissions"] = strings.Join(perms, ",")
	}
	return out
}

// effectivePermissions is what a person may use as the listings show it: an owner has core.PermissionAll; a member
// what they were given, never null.
func effectivePermissions(role core.Role, perms []string) []string {
	if role == core.RoleOwner {
		return []string{core.PermissionAll}
	}
	if perms == nil {
		return []string{}
	}
	return perms
}

// widens reports whether p going to the term until and the permissions perms gains access: a later end, no end
// after having one, or a permission p lacked (core.PermissionAll covers every permission).
func widens(p core.Person, until *time.Time, perms []string) bool {
	switch {
	case until == nil && p.AccessUntil != nil:
		return true
	case until != nil && p.AccessUntil != nil && until.After(*p.AccessUntil):
		return true
	}
	had := effectivePermissions(p.Role, p.Permissions)
	if slices.Contains(had, core.PermissionAll) {
		return false
	}
	return slices.ContainsFunc(perms, func(id string) bool { return !slices.Contains(had, id) })
}

// AccessChange is a change of a person's term and permissions; a field whose Set flag is false stays as it is.
type AccessChange struct {
	SetUntil       bool
	Until          *time.Time // the new end; nil is no end. A time in the past ends the access now.
	SetPermissions bool
	Permissions    []string // the new permissions, checked against the catalog; nil or empty is none
}

// UpdateMember changes the term and permissions of person target of account a, by from ip, and returns the person as
// changed. It is audited as ActionMemberUpdate with the role of the person and what was set.
//
// confirmed says the caller confirmed the change with step-up: a change that widens the person's access without it
// is ErrWidens, and nothing is changed. The refusals: yourself (400), another account's person (core.ErrNotFound), an
// owner or a superadmin unless by is the superadmin (ErrSuperadminOnly), a superadmin at all (409), permissions of an
// owner (400), a term more than a year away (400), and permissions the catalog does not offer (400
// invalid_permission). Without Options.Permissions every change is refused.
func (s *Service) UpdateMember(ctx context.Context, a core.AccountID, target, by core.PersonID, ch AccessChange,
	confirmed bool, ip string) (core.Person, error) {
	if s.o.Permissions == nil {
		return core.Person{}, errNoPermissions
	}
	if !ch.SetUntil && !ch.SetPermissions {
		return core.Person{}, errNoChange
	}
	if target == by {
		return core.Person{}, errSelfAccess
	}
	now := s.now().Truncate(time.Millisecond)
	var until *time.Time
	if ch.SetUntil && ch.Until != nil {
		u := ch.Until.UTC().Truncate(time.Millisecond)
		if u.Before(now) {
			u = now
		}
		if u.After(maxTerm(now)) {
			return core.Person{}, errFarUntil
		}
		until = &u
	}
	var perms []string
	if ch.SetPermissions {
		var err error
		if perms, err = s.permissions(ctx, a, ch.Permissions); err != nil {
			return core.Person{}, err
		}
	}
	var out core.Person
	err := s.st.Tx(ctx, func(ctx context.Context) error {
		p, err := s.member(ctx, a, target)
		if err != nil {
			return err
		}
		if err := s.mayManage(ctx, a, by, p); err != nil {
			return err
		}
		switch {
		case p.Superadmin:
			return errSuperadminTerm
		case ch.SetPermissions && p.Role == core.RoleOwner:
			return errOwnerAccess
		}
		newUntil, newPerms := p.AccessUntil, p.Permissions
		if ch.SetUntil {
			newUntil = until
		}
		if ch.SetPermissions {
			newPerms = perms
		}
		if !confirmed && widens(p, newUntil, newPerms) {
			return ErrWidens
		}
		if err := s.st.People().SetAccess(ctx, target, newUntil, newPerms); err != nil {
			return fmt.Errorf("people: change a member's access: %w", err)
		}
		detail := map[string]string{"role": string(p.Role)}
		maps.Copy(detail, accessDetail(ch.SetUntil, newUntil, ch.SetPermissions, newPerms))
		p.AccessUntil, p.Permissions = newUntil, newPerms
		out = p
		return s.st.Audit().Append(ctx, actorname.Stamp(ctx, s.st.People(), core.AuditEntry{At: now, AccountID: a,
			Actor: by, Action: ActionMemberUpdate, Target: string(target), Detail: detail, IP: ip}))
	})
	if err != nil {
		return core.Person{}, err
	}
	return out, nil
}
