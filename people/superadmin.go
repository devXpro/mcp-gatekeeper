package people

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

type adminAccountJSON struct {
	ID        core.AccountID `json:"id"`
	Name      string         `json:"name"`
	Members   int            `json:"members"`
	CreatedAt string         `json:"created_at"`
}

// listAccounts is GET /api/admin/accounts: every account with counts, never its members or data.
func (s *Service) listAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := s.Summaries(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows := make([]json.RawMessage, 0, len(list))
	for _, sum := range list {
		row, err := json.Marshal(adminAccountJSON{ID: sum.Account.ID, Name: sum.Account.Name, Members: sum.Members,
			CreatedAt: rfc3339(sum.Account.CreatedAt)})
		if err == nil && s.o.Summaries != nil {
			var extra map[string]any
			if extra, err = s.o.Summaries.SummaryFields(ctx, sum.Account.ID); err == nil {
				row, err = withFields(row, extra, "id", "name", "members", "created_at")
			}
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		rows = append(rows, row)
	}
	s.writeJSON(w, r, rows)
}

type createAccountBody struct {
	Name      string `json:"name"`
	OwnerName string `json:"owner_name"`
}

type accountRefJSON struct {
	ID   core.AccountID `json:"id"`
	Name string         `json:"name"`
}

type ownerInviteJSON struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
}

type createdAccountJSON struct {
	Account accountRefJSON  `json:"account"`
	Invite  ownerInviteJSON `json:"invite"`
}

// createAccount is POST /api/admin/accounts (step-up): a new account and its owner's invite. The superadmin does
// not join it: only the invitee becomes its owner.
func (s *Service) createAccount(w http.ResponseWriter, r *http.Request) {
	var body createAccountBody
	if err := decode(w, r, &body); err != nil {
		s.fail(w, r, err)
		return
	}
	v := viewer(r)
	acc, inv, err := s.CreateAccount(r.Context(), body.Name, body.OwnerName, v.Person.ID, s.ip(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, r, createdAccountJSON{Account: accountRefJSON{ID: acc.ID, Name: acc.Name},
		Invite: ownerInviteJSON{URL: inv.URL, ExpiresAt: rfc3339(inv.ExpiresAt)}})
}

// adminDeleteAccount is DELETE /api/admin/accounts/{id} (step-up; not your own, which goes through DELETE
// /api/account): delete everything of another account, once confirm equals its name.
func (s *Service) adminDeleteAccount(w http.ResponseWriter, r *http.Request) {
	v := viewer(r)
	id := core.AccountID(r.PathValue("id"))
	if id == v.Account.ID {
		s.fail(w, r, NewError(http.StatusConflict, httpsec.CodeConflict, "delete your own account from the account page"))
		return
	}
	var body confirmBody
	if err := decode(w, r, &body); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	acc, err := s.st.Accounts().Get(ctx, id)
	if errors.Is(err, core.ErrNotFound) {
		s.fail(w, r, NewError(http.StatusNotFound, httpsec.CodeNotFound, "no such account"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if body.Confirm != acc.Name {
		s.fail(w, r, invalid("confirm must equal the account name"))
		return
	}
	if err := s.DeleteAccount(ctx, id, v.Person.ID, s.ip(r), "superadmin"); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}

// actionLoginFail is package auth's audit action for a failed sign-in: a system entry, as nobody is known yet.
const actionLoginFail = "auth.login.fail"

// systemAudit is GET /api/admin/audit?before=&limit=: system entries only, never an account's. A failed sign-in
// shows without its address: it may be anybody's, of any account (T2.R L9).
func (s *Service) systemAudit(w http.ResponseWriter, r *http.Request) {
	before, limit, err := page(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.st.Audit().ListSystem(r.Context(), before, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for i := range list {
		if list[i].Action == actionLoginFail {
			list[i].IP = ""
		}
	}
	s.writeAudit(w, r, list)
}
