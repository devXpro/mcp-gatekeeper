package people_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// route is one route of this package with the marks it carries.
type route struct {
	method, path string
	owner        bool // (owner)
	superadmin   bool // (superadmin)
	stepUp       bool // (step-up)
}

func routes() []route {
	return []route{
		{http.MethodGet, "/api/account", false, false, false},
		{http.MethodPost, "/api/account/invites", true, false, true},
		{http.MethodDelete, "/api/account/invites/inv_x", true, false, false},
		{http.MethodDelete, "/api/account/members/per_x", true, false, true},
		{http.MethodGet, "/api/account/connections", false, false, false},
		{http.MethodDelete, "/api/account/connections/grt_x", false, false, false},
		{http.MethodDelete, "/api/account", true, false, true},
		{http.MethodGet, "/api/account/audit", false, false, false},

		{http.MethodGet, "/api/admin/accounts", false, true, false},
		{http.MethodPost, "/api/admin/accounts", false, true, true},
		{http.MethodDelete, "/api/admin/accounts/acc_x", false, true, true},
		{http.MethodGet, "/api/admin/audit", false, true, false},
	}
}

// TestGuards walks every route through the refusals: no session, no CSRF header on a write, the role marks, and
// step-up. None of the refused requests may reach the application or change the store.
func TestGuards(t *testing.T) {
	e := newEnv(t)
	acc, owner := e.account("Kowalscy", "Alice", false)
	member := e.person(acc, "Bella", core.RoleMember, false)
	ownerStep, ownerNoStep := e.session(owner, true), e.session(owner, false)
	memberStep := e.session(member, true)
	_, root := e.account("Admins", "Root", true)
	rootNoStep := e.session(root, false)

	for _, rt := range routes() {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			w := e.do(rt.method, rt.path, nil, "")
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Equal(t, "no_session", errCode(t, w))
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "refusals are not cached either")
			if rt.method != http.MethodGet {
				// The CSRF checks come first, even with a valid session.
				w = e.do(rt.method, rt.path, nil, ownerStep, noCSRF)
				assert.Equal(t, http.StatusForbidden, w.Code)
				assert.Equal(t, "forbidden", errCode(t, w))
			}
			if rt.owner {
				w = e.do(rt.method, rt.path, nil, memberStep)
				assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
				assert.Equal(t, "forbidden", errCode(t, w))
				assert.Contains(t, w.Body.String(), "only the owner of the account may do this")
			}
			if rt.superadmin {
				w = e.do(rt.method, rt.path, nil, ownerStep)
				assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
				assert.Equal(t, "forbidden", errCode(t, w))
				assert.Contains(t, w.Body.String(), "only the superadmin may do this")
			}
			if rt.stepUp {
				tok := ownerNoStep
				if rt.superadmin {
					tok = rootNoStep
				}
				w = e.do(rt.method, rt.path, nil, tok)
				assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
				assert.Equal(t, "step_up_required", errCode(t, w))
			}
		})
	}
	assert.Empty(t, e.app.erasures(), "no refused request reaches the application")
	assert.Empty(t, e.st.AuditEntries(), "no refused request changes anything")
}

// TestCrossOriginWrite refuses a write from another origin even with the header.
func TestCrossOriginWrite(t *testing.T) {
	e := newEnv(t)
	_, owner := e.account("Kowalscy", "Alice", false)
	tok := e.session(owner, true)
	w := e.do(http.MethodPost, "/api/account/invites", map[string]string{"name": "Bella"}, tok,
		func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") })
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "forbidden", errCode(t, w))
}
