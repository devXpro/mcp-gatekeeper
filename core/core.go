// Package core holds the identifiers, domain types, errors and cross-package interfaces of MCP Gatekeeper.
//
// It is frozen (docs/PLAN.md §4.1). Agents never edit it: a change request goes in the agent's report, and the
// orchestrator merges it between waves.
//
// The types came from Family Hub's internal/core. The one rename: a module became a resource, because an application
// decides what an MCP endpoint stands for (Family Hub: one module; Homie: the whole home).
package core

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Identifiers are opaque strings made by NewID (ResourceID and ClientID excepted).
type (
	// AccountID names an account: one family or one household.
	AccountID string
	// PersonID names a person.
	PersonID string
	// ResourceID names what one MCP endpoint serves, chosen by the application (e.g. "notes", "home").
	ResourceID string
	// ClientID is an OAuth client_id: an id issued by DCR or, for CIMD, the URL of the metadata document.
	ClientID string
	// GrantID names one consent: a person, an assistant's client and a resource.
	GrantID string
)

// Prefixes for NewID.
const (
	PrefixAccount = "acc"
	PrefixPerson  = "per"
	PrefixPasskey = "pk"
	PrefixInvite  = "inv"
	PrefixGrant   = "grt"
	PrefixClient  = "cli"
	PrefixTxn     = "txn"
)

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewID returns prefix + "_" + 16 random lower-case base32 characters (80 bits).
func NewID(prefix string) string {
	b := make([]byte, 10)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error since Go 1.24
	return prefix + "_" + idEncoding.EncodeToString(b)
}

// Role is a person's role inside their account.
type Role string

// Roles inside an account.
const (
	RoleOwner  Role = "owner"
	RoleMember Role = "member"
)

// Account is one family or household. Application data is kept per account.
type Account struct {
	ID        AccountID
	Name      string
	CreatedAt time.Time
}

// Person is someone who signs in with a passkey. Every person belongs to exactly one account.
type Person struct {
	ID         PersonID
	AccountID  AccountID
	Name       string
	Role       Role
	Superadmin bool // manages accounts and the application; never sees other accounts' data
	CreatedAt  time.Time
	DisabledAt *time.Time
	// AccessUntil ends the person's access at that instant (a guest's term); nil means no end. Only an application
	// that offers terms sets it (package people, with a PermissionCatalog).
	AccessUntil *time.Time
	// Permissions are application-defined ids of what the person may use (e.g. PermissionAll, "plugin:tv"); nil means
	// the application's default. The gatekeeper checks them against the application's PermissionCatalog and stores
	// them; it never interprets them.
	Permissions []string
}

// PermissionAll is the permission id for everything an application offers, now and later. An owner has it.
const PermissionAll = "all"

// Active reports whether p may act at now: not disabled, and before the end of their term if they have one. Every
// check of a session, an access token, a refresh and a consent uses it.
func (p Person) Active(now time.Time) bool {
	return p.DisabledAt == nil && (p.AccessUntil == nil || now.Before(*p.AccessUntil))
}

// Passkey is a stored WebAuthn credential. Data belongs to package auth (the credential as JSON).
type Passkey struct {
	ID           string
	PersonID     PersonID
	CredentialID []byte
	Data         []byte
	Name         string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// Session is a browser session. Only the sha256 of the cookie value is stored.
type Session struct {
	IDHash      []byte
	PersonID    PersonID
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time // the absolute end
	StepUpUntil time.Time // zero when there is no fresh step-up
	UserAgent   string
}

// InviteKind says what redeeming an invite creates.
type InviteKind string

// Invite kinds.
const (
	InviteSetup  InviteKind = "setup"  // the first superadmin and their account (CLI only)
	InviteOwner  InviteKind = "owner"  // an owner: of a new account, or a co-owner of an existing one; by the superadmin
	InviteMember InviteKind = "member" // a member of an existing account, made by its owner
)

// Invite is a one-time link. Only the sha256 of the token is stored.
type Invite struct {
	ID        string
	TokenHash []byte
	Kind      InviteKind
	AccountID AccountID // empty for InviteSetup
	Name      string    // the person's name as the inviter typed it
	CreatedBy PersonID  // empty for InviteSetup
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
	// AccessUntil and Permissions are copied to the person who redeems a member invite, in the same transaction (see
	// Person). ExpiresAt is the link's life; AccessUntil is the person's.
	AccessUntil *time.Time
	Permissions []string
}

// Assistant is the AI product behind an OAuth client.
type Assistant string

// Assistants the gatekeeper accepts.
const (
	AssistantChatGPT Assistant = "chatgpt"
	AssistantClaude  Assistant = "claude"
)

// ClientKind says how an OAuth client registered.
type ClientKind string

// Client kinds.
const (
	ClientDCR  ClientKind = "dcr"
	ClientCIMD ClientKind = "cimd"
)

// OAuthClient is a registered assistant client.
type OAuthClient struct {
	ID           ClientID
	Kind         ClientKind
	Assistant    Assistant
	Name         string
	RedirectURIs []string
	AuthMethod   string    // "none", "client_secret_post" or "client_secret_basic"
	SecretHash   []byte    // sha256 of the client secret; nil for "none"
	FetchedAt    time.Time // CIMD: when the metadata document was last fetched
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// AuthCode is a one-time authorization code. Only its sha256 is stored.
type AuthCode struct {
	CodeHash      []byte
	GrantID       GrantID
	ClientID      ClientID
	RedirectURI   string
	Resource      string
	Scope         string
	CodeChallenge string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// Grant is a consent: one person let one assistant client use one resource. Revoking it revokes its tokens.
type Grant struct {
	ID         GrantID
	PersonID   PersonID
	AccountID  AccountID
	ClientID   ClientID
	ResourceID ResourceID
	Scope      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// TokenKind is access or refresh.
type TokenKind string

// Token kinds.
const (
	TokenAccess  TokenKind = "access"
	TokenRefresh TokenKind = "refresh"
)

// Token is an opaque OAuth token. Only its sha256 is stored.
type Token struct {
	Hash      []byte
	GrantID   GrantID
	Kind      TokenKind
	Family    string // the refresh rotation family; reusing a rotated refresh token revokes the family
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time // refresh tokens: when it was rotated
	RevokedAt *time.Time
}

// AuditEntry is one line of the audit log. Detail never holds secrets or application data.
type AuditEntry struct {
	ID        string // assigned by the store; newer entries sort after older ones
	At        time.Time
	AccountID AccountID // empty: a system event
	Actor     PersonID  // empty: the CLI or the system
	Action    string    // dotted, e.g. "auth.login", "module.deploy"
	Target    string
	Detail    map[string]string
	IP        string
}

// Errors shared by the packages; wrap them with %w.
var (
	ErrNotFound       = errors.New("not found")
	ErrConflict       = errors.New("conflict")
	ErrExpired        = errors.New("expired")
	ErrUsed           = errors.New("already used")
	ErrNoSession      = errors.New("no session")
	ErrStepUpRequired = errors.New("step-up required")
	ErrForbidden      = errors.New("forbidden")
	ErrInvalidToken   = errors.New("invalid token")
)

// Clock returns the current time; tests pass a fake one.
type Clock func() time.Time

// ClientIPMode says where the client address of a request comes from.
type ClientIPMode string

// Client address sources.
const (
	ClientIPCloudflare ClientIPMode = "cf-connecting-ip" // behind cloudflared: the CF-Connecting-IP header
	ClientIPForwarded  ClientIPMode = "x-forwarded-for"  // behind one reverse proxy: the last X-Forwarded-For hop
	ClientIPRemote     ClientIPMode = "remote"           // no proxy: the TCP peer
)

// Site says where the application is served. Every package that builds URLs or checks origins takes one.
type Site struct {
	PublicURL string // "https://hub.example.com": no path, no trailing slash; also the OAuth issuer and the WebAuthn origin
	RPID      string // the WebAuthn relying party ID: the host of PublicURL
	ClientIP  ClientIPMode
}

// Validate reports whether s can be served (review GK-2):
//   - PublicURL is https with a host and nothing after it; plain http only for localhost or a loopback address;
//   - RPID, when set, is that host or a parent domain of it (package auth requires it to be set);
//   - ClientIP is one of the known modes; an empty or unknown mode would silently mean the TCP peer, which behind a
//     local connector is every client at once.
//
// Every constructor that takes a Site calls it, so a mistake fails at start.
func (s Site) Validate() error {
	u, err := url.Parse(s.PublicURL)
	// ForceQuery and a bare "#" are an empty query or fragment the parsed fields would not show; a port alone
	// ("https://:443") has a Host but no hostname.
	if err != nil || u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s.PublicURL, "#") {
		return fmt.Errorf("site: the public URL %q must be scheme://host[:port] and nothing more", s.PublicURL)
	}
	host := u.Hostname()
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("site: the public URL %q uses plain http, which is only for localhost", s.PublicURL)
		}
	default:
		return fmt.Errorf("site: the public URL %q must be https", s.PublicURL)
	}
	if s.RPID != "" && s.RPID != host && !strings.HasSuffix(host, "."+s.RPID) {
		return fmt.Errorf("site: the RP ID %q is neither the host %q nor a parent domain of it", s.RPID, host)
	}
	switch s.ClientIP {
	case ClientIPCloudflare, ClientIPForwarded, ClientIPRemote:
		return nil
	default:
		return fmt.Errorf("site: the client address mode %q is not %q, %q or %q", s.ClientIP, ClientIPCloudflare,
			ClientIPForwarded, ClientIPRemote)
	}
}

// ClientIP returns the client address of r under mode, falling back to the TCP peer.
//
// The application must make sure only a trusted peer can set the header that mode reads (Family Hub deletes
// CF-Connecting-IP and X-Forwarded-For from any peer outside its edge network before this runs). A request without
// the header falls back to the TCP peer: in a header mode only the trusted connector should reach the listener (a
// local connector: listen on loopback only), or every such request shares one address.
func ClientIP(r *http.Request, mode ClientIPMode) string {
	switch mode {
	case ClientIPCloudflare:
		if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
			return v
		}
	case ClientIPForwarded:
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			hops := strings.Split(v, ",")
			if last := strings.TrimSpace(hops[len(hops)-1]); last != "" {
				return last
			}
		}
	case ClientIPRemote:
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Viewer is the signed-in person behind a request.
type Viewer struct {
	Person  Person
	Account Account
	Session Session
}

type viewerKey struct{}

// WithViewer returns ctx carrying v.
func WithViewer(ctx context.Context, v Viewer) context.Context {
	return context.WithValue(ctx, viewerKey{}, v)
}

// ViewerFrom returns the Viewer that WithViewer stored in ctx.
func ViewerFrom(ctx context.Context) (Viewer, bool) {
	v, ok := ctx.Value(viewerKey{}).(Viewer)
	return v, ok
}
