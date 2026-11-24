package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// metadataHosts are the hosts a client ID metadata document may live on, with their assistants. Hosts are added only
// by a deliberate change: the fixed list is what keeps the fetch from reaching anything else.
var metadataHosts = map[string]core.Assistant{
	"chatgpt.com": core.AssistantChatGPT,
	"claude.ai":   core.AssistantClaude,
	"claude.com":  core.AssistantClaude,
}

// metadataAssistant returns the assistant whose client ID metadata document URL raw is
// (draft-ietf-oauth-client-id-metadata-document), or "": an https URL in canonical form on one of metadataHosts,
// with a path, no dot segments, and no port, user, query or fragment.
func metadataAssistant(raw string) core.Assistant {
	u, ok := canonicalHTTPS(raw)
	if !ok || u.Path == "" || u.Path == "/" {
		return ""
	}
	for seg := range strings.SplitSeq(u.Path, "/") {
		if seg == "." || seg == ".." {
			return ""
		}
	}
	return metadataHosts[u.Host]
}

// fetcher reads a client ID metadata document. The server uses httpFetcher; tests bring their own, since a fetch is
// a live call.
type fetcher interface {
	Fetch(ctx context.Context, rawURL string) ([]byte, error)
}

// httpFetcher fetches a document with one GET: no redirects, a timeout and a size cap.
type httpFetcher struct {
	client  *http.Client
	maxSize int64
}

func newHTTPFetcher(timeout time.Duration, maxSize int64) *httpFetcher {
	return &httpFetcher{
		client: &http.Client{
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		maxSize: maxSize,
	}
}

// Fetch returns the body of a 200 answer to GET rawURL. A redirect, another status or a body over the cap is an
// error.
func (f *httpFetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oauth: client metadata request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: client metadata fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: client metadata fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("oauth: client metadata read: %w", err)
	}
	if int64(len(body)) > f.maxSize {
		return nil, fmt.Errorf("oauth: client metadata document is over %d bytes", f.maxSize)
	}
	return body, nil
}

// metadataDocument is the part of a client ID metadata document the server reads.
type metadataDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	// TokenEndpointAuthMethodsSupported lists the methods the client can use. ChatGPT's document names
	// private_key_jwt as its method and lists none here as well.
	TokenEndpointAuthMethodsSupported []string        `json:"token_endpoint_auth_methods_supported"`
	ClientSecret                      json.RawMessage `json:"client_secret"`
}

// parseMetadataDocument checks the fetched document of the client at rawURL, which belongs to assistant a: its
// client_id is the URL itself, its redirect URIs pass the callback rules (connector: see callbackAssistant) and are
// a's, and it can authenticate with "none", since a public document cannot carry a secret. A document whose own
// method is another one (ChatGPT's is private_key_jwt) is accepted when it lists none among the methods it supports:
// the server's metadata does not offer private_key_jwt, so such a client authenticates with none here, bound by PKCE
// and its registered callbacks like every public client. It returns the client's display name and redirect URIs.
func parseMetadataDocument(body []byte, rawURL string, a core.Assistant, connector bool) (string, []string, error) {
	var d metadataDocument
	if err := json.Unmarshal(body, &d); err != nil {
		return "", nil, fmt.Errorf("%w: not a JSON object", errMetadataInvalid)
	}
	if d.ClientID != rawURL {
		return "", nil, fmt.Errorf("%w: its client_id is not its URL", errMetadataInvalid)
	}
	uris, assistant, ok := callbackSet(d.RedirectURIs, connector)
	if !ok || assistant != a {
		return "", nil, fmt.Errorf("%w: its redirect_uris are not %s's callbacks", errMetadataInvalid, a)
	}
	if d.TokenEndpointAuthMethod != "" && d.TokenEndpointAuthMethod != authNone &&
		!slices.Contains(d.TokenEndpointAuthMethodsSupported, authNone) {
		// The method is named in the log, so the operator sees what the assistants really publish (T2.R I4).
		return "", nil, fmt.Errorf("%w: token_endpoint_auth_method must be none, not %q", errMetadataInvalid,
			clip(d.TokenEndpointAuthMethod, maxNameRunes))
	}
	if d.ClientSecret != nil {
		return "", nil, fmt.Errorf("%w: it carries a client_secret", errMetadataInvalid)
	}
	return displayName(d.ClientName, a), uris, nil
}

// limitedError is a client metadata fetch refused by the limit of the client's address group.
type limitedError struct{ wait time.Duration }

func (e *limitedError) Error() string { return "oauth: too many client metadata fetches" }

// metadataClient returns the CIMD client whose client_id is rawURL: the stored copy while it is under 24 h old,
// otherwise the document fetched again (5 s, 64 KiB, no redirects), checked and stored. The first fetch is audited
// as a registration. A document that failed is not fetched again for 5 minutes, and one address group fetches at
// most 5 a minute (T2.R M1), so authorize cannot be made to fetch from the assistants' hosts at will. There is no
// budget shared by every address: a flood would spend it and stop the refetch of a real client.
func (s *Server) metadataClient(ctx context.Context, rawURL, ip string) (core.OAuthClient, error) {
	a := metadataAssistant(rawURL)
	if a == "" {
		return core.OAuthClient{}, errUnknownClient
	}
	now := s.now()
	id := core.ClientID(rawURL)
	cached, err := s.store.OAuth().GetClient(ctx, id)
	known := err == nil
	switch {
	case known && cached.Kind == core.ClientCIMD && now.Sub(cached.FetchedAt) < cimdCacheTTL:
		return cached, nil
	case err != nil && !errors.Is(err, core.ErrNotFound):
		return core.OAuthClient{}, fmt.Errorf("oauth: client %s: %w", id, err)
	}
	if err := s.failures.get(rawURL, now); err != nil {
		return core.OAuthClient{}, err
	}
	if ok, wait := s.fetchLimit.take(addressKey(ip), now); !ok {
		return core.OAuthClient{}, &limitedError{wait: wait}
	}

	fetchCtx, cancel := context.WithTimeout(ctx, cimdTimeout)
	defer cancel()
	body, err := s.fetcher.Fetch(fetchCtx, rawURL)
	if err != nil {
		s.log.Warn("oauth: client metadata document not fetched", slog.String("client", rawURL), slog.Any("error", err))
		s.failures.add(rawURL, errMetadataFetch, now)
		return core.OAuthClient{}, errMetadataFetch
	}
	name, uris, err := parseMetadataDocument(body, rawURL, a, s.cfg.connector)
	if err != nil {
		s.log.Warn("oauth: client metadata document refused", slog.String("client", rawURL), slog.Any("error", err))
		s.failures.add(rawURL, errMetadataInvalid, now)
		return core.OAuthClient{}, errMetadataInvalid
	}
	client := core.OAuthClient{
		ID: id, Kind: core.ClientCIMD, Assistant: a, Name: name, RedirectURIs: uris, AuthMethod: authNone,
		FetchedAt: now, CreatedAt: now,
	}
	if known {
		client.CreatedAt, client.LastUsedAt = cached.CreatedAt, cached.LastUsedAt
	}
	if err := s.store.OAuth().PutClient(ctx, client); err != nil {
		return core.OAuthClient{}, fmt.Errorf("oauth: store client %s: %w", id, err)
	}
	if !known {
		s.audit(ctx, core.AuditEntry{
			At: now, Action: actionClientRegister, Target: rawURL, IP: ip,
			Detail: map[string]string{"kind": string(core.ClientCIMD), "assistant": string(a)},
		})
		s.log.Info("oauth: client registered", slog.String("kind", string(core.ClientCIMD)),
			slog.String("assistant", string(a)), slog.String("client", rawURL))
	}
	return client, nil
}

// fetchFailures remembers for cimdFailureTTL the client metadata documents that could not be fetched or were
// refused, with what went wrong.
type fetchFailures struct {
	mu    sync.Mutex
	items map[string]fetchFailure
}

type fetchFailure struct {
	err   error // errMetadataFetch or errMetadataInvalid
	until time.Time
}

func newFetchFailures() *fetchFailures {
	return &fetchFailures{items: map[string]fetchFailure{}}
}

// get returns the failure of rawURL while it is remembered, otherwise nil.
func (f *fetchFailures) get(rawURL string, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if x, ok := f.items[rawURL]; ok && now.Before(x.until) {
		return x.err
	}
	return nil
}

// add remembers the failure err of rawURL. When the memo is full, the forgotten ones go first, then any half.
func (f *fetchFailures) add(rawURL string, err error, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.items) >= maxKeys {
		for k, x := range f.items {
			if !now.Before(x.until) {
				delete(f.items, k)
			}
		}
		for k := range f.items {
			if len(f.items) < maxKeys/2 {
				break
			}
			delete(f.items, k)
		}
	}
	f.items[rawURL] = fetchFailure{err: err, until: now.Add(cimdFailureTTL)}
}
