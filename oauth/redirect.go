package oauth

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// callbackHosts are the hosts of the assistants' OAuth callbacks; the host tells the assistant. Hosts are added only
// by a deliberate change.
var callbackHosts = map[string]core.Assistant{
	"chatgpt.com":     core.AssistantChatGPT,
	"chat.openai.com": core.AssistantChatGPT,
	"claude.ai":       core.AssistantClaude,
	"claude.com":      core.AssistantClaude,
}

// callbackIDPattern is the {callback_id} of ChatGPT's /connector/oauth/{callback_id}: one path segment.
var callbackIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// callbackAssistant returns the assistant whose OAuth callback raw is, or "" when it is none of theirs. A callback
// is an https URL in canonical form on one of callbackHosts, with no port, user, query or fragment, and one of the
// host's paths: ChatGPT's /connector_platform_oauth_redirect or, when connector is set, /connector/oauth/{callback_id},
// Claude's /api/mcp/auth_callback. ChatGPT gives the per-connector callback to servers without RFC 9207 iss, where
// a connector of anybody's may name it (the mix-up of T2.R H1), so Options.RefuseConnectorCallback can refuse it.
func callbackAssistant(raw string, connector bool) core.Assistant {
	u, ok := canonicalHTTPS(raw)
	if !ok {
		return ""
	}
	switch a := callbackHosts[u.Host]; a {
	case core.AssistantChatGPT:
		id, perConnector := strings.CutPrefix(u.Path, "/connector/oauth/")
		if u.Path == "/connector_platform_oauth_redirect" ||
			(connector && perConnector && callbackIDPattern.MatchString(id)) {
			return a
		}
	case core.AssistantClaude:
		if u.Path == "/api/mcp/auth_callback" {
			return a
		}
	}
	return ""
}

// callbackSet checks the redirect URIs of a client, DCR and CIMD alike: 1 to 10 callbacks, all of one assistant, by
// the rules of callbackAssistant. It returns them without repeats, with the assistant.
func callbackSet(uris []string, connector bool) ([]string, core.Assistant, bool) {
	if len(uris) == 0 || len(uris) > maxRedirectURIs {
		return nil, "", false
	}
	var assistant core.Assistant
	out := make([]string, 0, len(uris))
	for _, raw := range uris {
		a := callbackAssistant(raw, connector)
		if a == "" || (assistant != "" && a != assistant) {
			return nil, "", false
		}
		assistant = a
		if !slices.Contains(out, raw) {
			out = append(out, raw)
		}
	}
	return out, assistant, true
}

// canonicalHTTPS parses an absolute https URL with a host and no port, user, query or fragment. raw must already be
// in the form url.URL prints, so no escape or letter case gives one address two spellings.
func canonicalHTTPS(raw string) (*url.URL, bool) {
	if len(raw) > maxURLLen {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Port() != "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.String() != raw {
		return nil, false
	}
	return u, true
}

// displayName is what the consent screen calls a client: the name it chose, without control, format or separator
// characters (bidi overrides, zero-width marks, line breaks) and cut to 64 characters, or else its assistant's name.
func displayName(name string, a core.Assistant) string {
	var b strings.Builder
	n := 0
	for _, r := range name {
		if n == maxNameRunes {
			break
		}
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			continue
		}
		b.WriteRune(r)
		n++
	}
	if s := strings.TrimSpace(b.String()); s != "" {
		return s
	}
	return assistantName(a)
}

func assistantName(a core.Assistant) string {
	switch a {
	case core.AssistantChatGPT:
		return "ChatGPT"
	case core.AssistantClaude:
		return "Claude"
	}
	return string(a)
}
