package core

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Brand holds the application-specific names the gatekeeper puts on the wire. Changing one of them for a running
// application signs everybody out (cookies) or breaks old browser tabs (header), so an application keeps its values.
type Brand struct {
	Product       string // shown in passkey prompts and pages, e.g. "Family Hub"
	SessionCookie string // e.g. "__Host-fh_session"; must start with "__Host-"
	TxnCookie     string // the consent-transaction binding cookie, e.g. "__Host-fh_txn"; must start with "__Host-"
	CSRFHeader    string // e.g. "X-Family-Hub"; every mutating /api call must send it with the value "1"

	// ResourceNoun and AppNoun name, in the texts assistants and people read, what one MCP endpoint serves and the
	// application itself. Empty means Family Hub's words, "module" and "hub", so its texts keep their bytes; read them
	// through ResourceWord and AppWord.
	ResourceNoun string
	AppNoun      string
}

// ResourceWord returns ResourceNoun, or "module" when it is empty.
func (b Brand) ResourceWord() string {
	if b.ResourceNoun == "" {
		return "module"
	}
	return b.ResourceNoun
}

// AppWord returns AppNoun, or "hub" when it is empty.
func (b Brand) AppWord() string {
	if b.AppNoun == "" {
		return "hub"
	}
	return b.AppNoun
}

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// RouteRegistrar adds a package's routes to the application's mux (Go 1.22 patterns, e.g. "POST /oauth/token").
type RouteRegistrar interface {
	RegisterRoutes(mux *http.ServeMux)
}

// Sessions resolves browser sessions; package auth implements it.
type Sessions interface {
	// Viewer returns the signed-in person of r, or ErrNoSession.
	Viewer(r *http.Request) (Viewer, error)
	// RequireViewer runs, for mutating methods, the CSRF checks of docs/PLAN.md §4.4 first (403
	// {"error":"forbidden"}). Then: 401 {"error":"no_session"} without a session; otherwise it stores the Viewer in
	// the request context (read it with ViewerFrom) and calls next.
	RequireViewer(next http.Handler) http.Handler
	// RequireStepUp is placed after RequireViewer: 403 {"error":"step_up_required"} unless the session has a fresh
	// step-up.
	RequireStepUp(next http.Handler) http.Handler
	// SameOrigin runs only the CSRF checks of a mutating request (403 {"error":"forbidden"}).
	SameOrigin(next http.Handler) http.Handler
}

// AccessInfo is what a valid access token stands for.
type AccessInfo struct {
	GrantID    GrantID
	PersonID   PersonID
	AccountID  AccountID
	ResourceID ResourceID
	ClientID   ClientID
	Assistant  Assistant
	Scope      string
	ExpiresAt  time.Time
}

// TokenValidator checks access tokens; package oauth implements it.
type TokenValidator interface {
	// ValidateAccess returns the access behind token if it is live and was issued for resource r; otherwise
	// ErrInvalidToken.
	ValidateAccess(ctx context.Context, token string, r ResourceID) (AccessInfo, error)
}

// ToolInfo is one tool of a resource as the consent screen shows it.
type ToolInfo struct {
	Name   string
	Title  string
	Access string // "read" or "write"
}

// ResourceInfo describes a resource for the OAuth metadata and the consent screen.
type ResourceInfo struct {
	ID          ResourceID
	Name        string
	Description string
	Tools       []ToolInfo
}

// ResourceCatalog tells the gatekeeper which MCP resources exist; the application implements it (Family Hub: its
// running modules; Homie: one resource, the home).
type ResourceCatalog interface {
	// Resource returns a resource that can be connected right now, or ErrNotFound.
	Resource(ctx context.Context, id ResourceID) (ResourceInfo, error)
	// Available reports whether account a may use resource id now (Family Hub: the module is switched on for it).
	Available(ctx context.Context, a AccountID, id ResourceID) (bool, error)
}

// PermissionInfo is one permission an application offers when a person is invited or changed (Homie: a device
// family). ID is what Person.Permissions holds, Title is what people read, and Group sorts the choices into sections.
type PermissionInfo struct {
	ID    string
	Title string
	Group string
}

// PermissionCatalog lists the permissions an application offers in account a. An application that gives people
// permissions and access terms passes one to package people; without one, people refuses both, as Family Hub needs.
// The gatekeeper only checks ids against the catalog and stores them: enforcing them is the application's.
type PermissionCatalog interface {
	Permissions(ctx context.Context, a AccountID) ([]PermissionInfo, error)
}

// ResourcePaths maps resources to their MCP paths on the Site and back.
type ResourcePaths interface {
	// Path returns the MCP path of a resource, e.g. "/mcp/notes" or "/mcp".
	Path(id ResourceID) string
	// FromPath returns the resource an MCP path belongs to: the path itself or anything below it.
	FromPath(path string) (ResourceID, bool)
}

// PerResource serves every resource under its own path: Prefix + id (Family Hub: Prefix "/mcp/").
type PerResource struct {
	Prefix string // ends with "/"
}

// Path implements ResourcePaths.
func (p PerResource) Path(id ResourceID) string { return p.Prefix + string(id) }

// FromPath implements ResourcePaths.
func (p PerResource) FromPath(path string) (ResourceID, bool) {
	rest, ok := strings.CutPrefix(path, p.Prefix)
	if !ok {
		return "", false
	}
	id, _, _ := strings.Cut(rest, "/")
	if id == "" {
		return "", false
	}
	return ResourceID(id), true
}

// SingleResource serves one resource at one path (Homie: At "/mcp", ID "home").
type SingleResource struct {
	At string // the path, e.g. "/mcp"
	ID ResourceID
}

// Path implements ResourcePaths.
func (s SingleResource) Path(ResourceID) string { return s.At }

// FromPath implements ResourcePaths.
func (s SingleResource) FromPath(path string) (ResourceID, bool) {
	if path == s.At || strings.HasPrefix(path, s.At+"/") {
		return s.ID, true
	}
	return "", false
}
