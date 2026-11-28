package oauth

import (
	"net/url"
	"regexp"
	"slices"
	"strconv"
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

// nativeCallbacks are the redirect URIs a native app registers (RFC 8252 §7.3): its loopback callback on the IPv4 or
// the IPv6 loopback address, without a port. localhost is not one: a name can resolve elsewhere (RFC 8252 §8.3).
var nativeCallbacks = []string{"http://127.0.0.1/oauth/callback", "http://[::1]/oauth/callback"}

// nativeSet checks the redirect URIs of a native app's registration: 1 to 10, each one of nativeCallbacks. It
// returns them without repeats.
func nativeSet(uris []string) ([]string, bool) {
	if len(uris) == 0 || len(uris) > maxRedirectURIs {
		return nil, false
	}
	out := make([]string, 0, len(nativeCallbacks))
	for _, raw := range uris {
		if !slices.Contains(nativeCallbacks, raw) {
			return nil, false
		}
		if !slices.Contains(out, raw) {
			out = append(out, raw)
		}
	}
	return out, true
}

// loopbackCallback returns the registered form of a native app's redirect URI raw: raw without its port, which is
// whatever the app listens on for this one request (RFC 8252 §7.3). raw is http on 127.0.0.1 or [::1], with an
// optional port of 1 to 65535 in plain digits, the path /oauth/callback, and no user, query or fragment, in the form
// url.URL prints. ok is false for anything else.
func loopbackCallback(raw string) (string, bool) {
	if len(raw) > maxURLLen {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawPath != "" || u.String() != raw {
		return "", false
	}
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port ||
			u.Host != host+":"+port {
			return "", false
		}
	} else if u.Host != host { // "127.0.0.1:" has an empty port
		return "", false
	}
	registered := "http://" + host + u.Path
	if !slices.Contains(nativeCallbacks, registered) {
		return "", false
	}
	return registered, true
}

// loopbackPort is the port of a redirect URI loopbackCallback accepted: its own, or 80 without one (http's).
func loopbackPort(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	if u.Port() == "" {
		return 80
	}
	n, _ := strconv.Atoi(u.Port())
	return n
}
