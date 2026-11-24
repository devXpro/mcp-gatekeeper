package people

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
	"github.com/devXpro/mcp-gatekeeper/people/actorname"
)

// AccountFields adds the application's fields to GET /api/account (Family Hub: "modules", the modules the viewer
// sees with their switches).
type AccountFields interface {
	// AccountFields returns top-level fields for the viewer's account; every value must marshal to JSON. A key of
	// this package's answer ("id", "name", "members", "invites") is refused with 500. An error is answered like
	// every error of this package.
	AccountFields(ctx context.Context, v core.Viewer) (map[string]any, error)
}

// SummaryFields adds the application's fields to each row of GET /api/admin/accounts (Family Hub: "modules", how
// many are switched on). Counts only: the superadmin never sees an account's data.
type SummaryFields interface {
	// SummaryFields returns fields of account a, under the same rules as AccountFields ("id", "name", "members" and
	// "created_at" are this package's).
	SummaryFields(ctx context.Context, a core.AccountID) (map[string]any, error)
}

// Connection is a connection the application keeps besides the OAuth grants (Family Hub: the legacy keys of
// ChatGPT Sites), as GET /api/account/connections lists it.
type Connection struct {
	ID         string // the "grant_id" of the row; ConnectionSource.Owns reports true for it
	ResourceID core.ResourceID
	Assistant  core.Assistant // e.g. "site"
	ClientName string
	Label      string // optional
	PersonID   core.PersonID
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// ConnectionSource lists and revokes the application's own connections.
type ConnectionSource interface {
	// Connections returns the connections of members, the people of v's account (oldest first). The handler drops
	// any of a person outside the account, shows a member only their own, and names each person.
	Connections(ctx context.Context, v core.Viewer, members []core.Person) ([]Connection, error)
	// Owns reports whether id names one of its connections (Family Hub: the "lk_" prefix). DELETE
	// /api/account/connections/{id} hands such an id to Revoke and never to the grants.
	Owns(id string) bool
	// Revoke removes connection id of v's account and audits it, from ip. Refusals are *APIErrors, e.g.
	// ErrNoConnection for one that is unknown or not v's to see, ErrOwnerOnly.
	Revoke(ctx context.Context, v core.Viewer, id, ip string) error
}

// RegisterRoutes implements core.RouteRegistrar. Every route runs NoStore and RequireViewer, which also applies the
// CSRF checks to writes; then the role check, then step-up where it is required, so a member is told "forbidden"
// rather than asked for a passkey.
func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	view := func(h http.HandlerFunc, guards ...func(http.Handler) http.Handler) http.Handler {
		var out http.Handler = h
		for _, g := range slices.Backward(guards) {
			out = g(out)
		}
		return NoStore(s.o.Sessions.RequireViewer(out))
	}
	owner, super, step := RequireOwner, RequireSuperadmin, s.o.Sessions.RequireStepUp

	mux.Handle("GET /api/account", view(s.getAccount))
	mux.Handle("DELETE /api/account", view(s.deleteAccount, owner, step))
	mux.Handle("POST /api/account/invites", view(s.createInvite, owner, step))
	mux.Handle("DELETE /api/account/invites/{id}", view(s.revokeInvite, owner))
	mux.Handle("DELETE /api/account/members/{id}", view(s.removeMember, owner, step))
	mux.Handle("GET /api/account/connections", view(s.listConnections))
	mux.Handle("DELETE /api/account/connections/{id}", view(s.revokeConnection))
	mux.Handle("GET /api/account/audit", view(s.accountAudit))

	mux.Handle("GET /api/admin/accounts", view(s.listAccounts, super))
	mux.Handle("POST /api/admin/accounts", view(s.createAccount, super, step))
	mux.Handle("DELETE /api/admin/accounts/{id}", view(s.adminDeleteAccount, super, step))
	mux.Handle("GET /api/admin/audit", view(s.systemAudit, super))
}

func (s *Service) ip(r *http.Request) string {
	ip := core.ClientIP(r, s.o.Site.ClientIP)
	if len(ip) > 64 {
		ip = ip[:64]
	}
	return ip
}

// withFields appends the fields of extra to the JSON object base, by name; a field base has is refused.
func withFields(base []byte, extra map[string]any, reserved ...string) ([]byte, error) {
	if len(extra) == 0 {
		return base, nil
	}
	out := slices.Clone(base[:len(base)-1])
	for _, k := range slices.Sorted(maps.Keys(extra)) {
		if slices.Contains(reserved, k) {
			return nil, fmt.Errorf("people: the application's field %q is one of this package's", k)
		}
		kj, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		vj, err := json.Marshal(extra[k])
		if err != nil {
			return nil, fmt.Errorf("people: the application's field %q: %w", k, err)
		}
		out = append(append(append(append(out, ','), kj...), ':'), vj...)
	}
	return append(out, '}'), nil
}

type memberJSON struct {
	ID       core.PersonID `json:"id"`
	Name     string        `json:"name"`
	Role     core.Role     `json:"role"`
	JoinedAt string        `json:"joined_at"`
	You      bool          `json:"you"`
}

type inviteJSON struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at"`
}

type accountJSON struct {
	ID      core.AccountID `json:"id"`
	Name    string         `json:"name"`
	Members []memberJSON   `json:"members"`
	Invites []inviteJSON   `json:"invites"`
}

// getAccount is GET /api/account: the viewer's account, its members, its live invites (the owner's view only) and
// the application's fields.
func (s *Service) getAccount(w http.ResponseWriter, r *http.Request) {
	ctx, v := r.Context(), viewer(r)
	people, err := s.Members(ctx, v.Account.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := accountJSON{ID: v.Account.ID, Name: v.Account.Name, Members: []memberJSON{}, Invites: []inviteJSON{}}
	for _, p := range people {
		out.Members = append(out.Members, memberJSON{ID: p.ID, Name: p.Name, Role: p.Role,
			JoinedAt: rfc3339(p.CreatedAt), You: p.ID == v.Person.ID})
	}
	if v.Person.Role == core.RoleOwner {
		invites, err := s.Invites(ctx, v.Account.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, inv := range invites {
			out.Invites = append(out.Invites, inviteJSON{ID: inv.ID, Name: inv.Name, ExpiresAt: rfc3339(inv.ExpiresAt)})
		}
	}
	var extra map[string]any
	if s.o.Fields != nil {
		if extra, err = s.o.Fields.AccountFields(ctx, v); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	base, err := json.Marshal(out)
	if err == nil {
		base, err = withFields(base, extra, "id", "name", "members", "invites")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeRaw(w, base)
}

type confirmBody struct {
	Confirm string `json:"confirm"`
}

// deleteAccount is DELETE /api/account (owner, step-up): delete everything, once confirm equals the account name.
func (s *Service) deleteAccount(w http.ResponseWriter, r *http.Request) {
	v := viewer(r)
	var body confirmBody
	if err := decode(w, r, &body); err != nil {
		s.fail(w, r, err)
		return
	}
	if body.Confirm != v.Account.Name {
		s.fail(w, r, invalid("confirm must equal the account name"))
		return
	}
	if err := s.DeleteAccount(r.Context(), v.Account.ID, v.Person.ID, s.ip(r), "owner"); err != nil {
		s.fail(w, r, err)
		return
	}
	// The session went with the account; drop the cookie too.
	http.SetCookie(w, &http.Cookie{Name: s.o.Brand.SessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true,
		HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeRaw(w, []byte("{}"))
}

type nameBody struct {
	Name string `json:"name"`
}

type createdInviteJSON struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
}

// createInvite is POST /api/account/invites (owner, step-up). The URL carries the token in its fragment; it is
// answered once and never logged.
func (s *Service) createInvite(w http.ResponseWriter, r *http.Request) {
	v := viewer(r)
	var body nameBody
	if err := decode(w, r, &body); err != nil {
		s.fail(w, r, err)
		return
	}
	inv, err := s.CreateInvite(r.Context(), v.Account.ID, body.Name, v.Person.ID, s.ip(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, r, createdInviteJSON{ID: inv.ID, URL: inv.URL, ExpiresAt: rfc3339(inv.ExpiresAt)})
}

// revokeInvite is DELETE /api/account/invites/{id} (owner).
func (s *Service) revokeInvite(w http.ResponseWriter, r *http.Request) {
	v := viewer(r)
	if err := s.RevokeInvite(r.Context(), v.Account.ID, r.PathValue("id"), v.Person.ID, s.ip(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// removeMember is DELETE /api/account/members/{id} (owner, step-up; never yourself).
func (s *Service) removeMember(w http.ResponseWriter, r *http.Request) {
	v := viewer(r)
	err := s.RemoveMember(r.Context(), v.Account.ID, core.PersonID(r.PathValue("id")), v.Person.ID, s.ip(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

type connectionJSON struct {
	GrantID    string          `json:"grant_id"`
	Resource   core.ResourceID `json:"resource"`
	Assistant  core.Assistant  `json:"assistant"`
	ClientName string          `json:"client_name"`
	Label      string          `json:"label,omitempty"` // a connection of the application may carry one
	Person     personRefJSON   `json:"person"`
	CreatedAt  string          `json:"created_at"`
	LastUsedAt *string         `json:"last_used_at"`
}

type personRefJSON struct {
	ID   core.PersonID `json:"id"`
	Name string        `json:"name"`
}

// listConnections is GET /api/account/connections: the owner sees the account's grants and the application's
// connections, a member only their own.
func (s *Service) listConnections(w http.ResponseWriter, r *http.Request) {
	ctx, v := r.Context(), viewer(r)
	grants, err := s.st.OAuth().ListGrantsByAccount(ctx, v.Account.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	people, err := s.Members(ctx, v.Account.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	names := map[core.PersonID]string{}
	for _, p := range people {
		names[p.ID] = p.Name
	}
	mine := func(p core.PersonID) bool { return v.Person.Role == core.RoleOwner || p == v.Person.ID }
	clients := map[core.ClientID]core.OAuthClient{}
	out := []connectionJSON{}
	for _, g := range grants {
		if g.AccountID != v.Account.ID || !mine(g.PersonID) {
			continue
		}
		cl, seen := clients[g.ClientID]
		if !seen {
			cl, err = s.st.OAuth().GetClient(ctx, g.ClientID)
			if err != nil && !errors.Is(err, core.ErrNotFound) {
				s.fail(w, r, err)
				return
			}
			clients[g.ClientID] = cl
		}
		out = append(out, connectionJSON{GrantID: string(g.ID), Resource: g.ResourceID, Assistant: cl.Assistant,
			ClientName: cl.Name, Person: personRefJSON{ID: g.PersonID, Name: names[g.PersonID]},
			CreatedAt: rfc3339(g.CreatedAt), LastUsedAt: optTime(g.LastUsedAt)})
	}
	if s.o.Connections != nil {
		extra, err := s.o.Connections.Connections(ctx, v, people)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, c := range extra {
			if _, ok := names[c.PersonID]; !ok || !mine(c.PersonID) {
				continue
			}
			out = append(out, connectionJSON{GrantID: c.ID, Resource: c.ResourceID, Assistant: c.Assistant,
				ClientName: c.ClientName, Label: c.Label, Person: personRefJSON{ID: c.PersonID, Name: names[c.PersonID]},
				CreatedAt: rfc3339(c.CreatedAt), LastUsedAt: optTime(c.LastUsedAt)})
		}
	}
	s.writeJSON(w, r, out)
}

// revokeConnection is DELETE /api/account/connections/{grant_id}: your own, or any of the account as the owner. An
// id of the application's ConnectionSource goes to it.
func (s *Service) revokeConnection(w http.ResponseWriter, r *http.Request) {
	ctx, v := r.Context(), viewer(r)
	id := r.PathValue("id")
	if s.o.Connections != nil && s.o.Connections.Owns(id) {
		if err := s.o.Connections.Revoke(ctx, v, id, s.ip(r)); err != nil {
			s.fail(w, r, err)
			return
		}
		noContent(w)
		return
	}
	g, err := s.st.OAuth().GetGrant(ctx, core.GrantID(id))
	if errors.Is(err, core.ErrNotFound) || err == nil && (g.AccountID != v.Account.ID || g.RevokedAt != nil) {
		s.fail(w, r, ErrNoConnection)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if g.PersonID != v.Person.ID && v.Person.Role != core.RoleOwner {
		s.fail(w, r, NewError(http.StatusForbidden, httpsec.CodeForbidden,
			"only the owner may revoke another person's connection"))
		return
	}
	if err := s.o.Revoker.RevokeGrant(ctx, g.ID, v.Person.ID, s.ip(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// accountAudit is GET /api/account/audit?before=&limit=: the viewer's account only. The owner reads all of it; a
// member only the entries where they are the actor or the target, with no other person's address (T2.R L4).
func (s *Service) accountAudit(w http.ResponseWriter, r *http.Request) {
	before, limit, err := page(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, v := r.Context(), viewer(r)
	var list []core.AuditEntry
	if v.Person.Role == core.RoleOwner {
		list, err = s.st.Audit().ListByAccount(ctx, v.Account.ID, before, limit)
	} else {
		list, err = s.memberAudit(ctx, v, before, limit)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeAudit(w, r, list)
}

// Audit paging.
const (
	defaultAuditLimit = 50
	maxAuditLimit     = 200
	// maxAuditScan bounds the account entries one member page reads to find its own. A member page that hits it
	// comes back short, which the SPA takes for the end of the log; an account's log (kept 400 days) is far smaller.
	maxAuditScan = 20000
)

// memberAudit returns at most limit entries of the viewer's account older than before, where the viewer is the actor
// or the target. An entry the viewer is only the target of loses its address: it is another person's.
func (s *Service) memberAudit(ctx context.Context, v core.Viewer, before string, limit int) ([]core.AuditEntry,
	error) {
	me := v.Person.ID
	out := []core.AuditEntry{}
	for scanned := 0; len(out) < limit && scanned < maxAuditScan; {
		batch, err := s.st.Audit().ListByAccount(ctx, v.Account.ID, before, maxAuditLimit)
		if err != nil {
			return nil, err
		}
		for _, e := range batch {
			if e.Actor != me && e.Target != string(me) {
				continue
			}
			if e.Actor != me {
				e.IP = ""
			}
			out = append(out, e)
			if len(out) == limit {
				break
			}
		}
		if len(batch) < maxAuditLimit {
			break
		}
		scanned += len(batch)
		before = batch[len(batch)-1].ID
	}
	return out, nil
}

var auditIDPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)

func page(r *http.Request) (before string, limit int, err error) {
	q := r.URL.Query()
	before = q.Get("before")
	if before != "" && !auditIDPattern.MatchString(before) {
		return "", 0, invalid("before must be an audit entry id")
	}
	limit = defaultAuditLimit
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return "", 0, invalid("limit must be a positive number")
		}
		limit = min(n, maxAuditLimit)
	}
	return before, limit, nil
}

type auditJSON struct {
	ID        string            `json:"id"`
	At        string            `json:"at"`
	Action    string            `json:"action"`
	Actor     *core.PersonID    `json:"actor"`
	ActorName string            `json:"actor_name,omitempty"`
	Target    string            `json:"target,omitempty"`
	Detail    map[string]string `json:"detail"`
	IP        string            `json:"ip,omitempty"`
}

// writeAudit answers entries newest first. actor_name is the person's current name when they are in the viewer's own
// account; otherwise the name stored with the entry when it was written (a person who is gone, or another
// account's owner in a system entry), and absent when neither is known.
func (s *Service) writeAudit(w http.ResponseWriter, r *http.Request, list []core.AuditEntry) {
	people, err := s.Members(r.Context(), viewer(r).Account.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	names := map[core.PersonID]string{}
	for _, p := range people {
		names[p.ID] = p.Name
	}
	out := make([]auditJSON, 0, len(list))
	for _, e := range list {
		stored, detail := actorname.Split(e)
		row := auditJSON{ID: e.ID, At: rfc3339(e.At), Action: e.Action, Target: e.Target, Detail: detail, IP: e.IP}
		if e.Actor != "" {
			actor := e.Actor
			row.Actor, row.ActorName = &actor, cmp.Or(names[actor], stored)
		}
		out = append(out, row)
	}
	s.writeJSON(w, r, out)
}
