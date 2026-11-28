package oauth

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// NativeApp is a program of the application's own that runs on the person's computer or phone and connects the way
// an assistant does, but with a loopback or a private-use URI scheme redirect (RFC 8252 §7.3, §7.1): it registers by
// DCR with software_id ID, and its client's core.Assistant is AppAssistantPrefix + ID. The application maps that to
// its own client label.
type NativeApp struct {
	ID   string // ^[a-z][a-z0-9-]{1,30}$, e.g. "desk"; the software_id of its registrations
	Name string // what the consent screen calls it, e.g. "Desk"; at most 64 characters, none invisible

	// Ports, when set, are the only loopback ports the app's redirect may use (1 to 65535, no repeats): another
	// program on the computer that listens on a port of its own cannot receive the app's code then. None (the
	// default) allows any port, as RFC 8252 §7.3 describes.
	Ports []int

	// Schemes, when set, are private-use URI schemes of the app (RFC 8252 §7.1), e.g. "com.example.desk": a client of
	// the app may register <scheme>:/oauth/callback for each, next to the loopback callbacks, and authorize matches it
	// exactly. A scheme is a lowercase reverse-DNS name with at least one dot (RFC 8252 §7.1 asks for a domain the
	// app's maker controls), at most 128 characters, and no scheme comes twice, in one app or across apps. None (the
	// default) allows the loopback callbacks only.
	Schemes []string
}

// AppAssistantPrefix starts the core.Assistant of a native app's client: "app:<ID>".
const AppAssistantPrefix = "app:"

// nativeAppIDPattern is a NativeApp.ID.
var nativeAppIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// schemePattern is a NativeApp scheme: a lowercase reverse-DNS name, labels of letters, digits and hyphens that start
// and end with a letter or digit, at least two of them, the first starting with a letter (an RFC 3986 scheme).
var schemePattern = regexp.MustCompile(`^[a-z]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// maxSchemeLen is the longest NativeApp scheme.
const maxSchemeLen = 128

// NativeAppID returns the NativeApp.ID of a native app's client from its assistant, and false for any other client.
func NativeAppID(a core.Assistant) (string, bool) {
	id, ok := strings.CutPrefix(string(a), AppAssistantPrefix)
	return id, ok && nativeAppIDPattern.MatchString(id)
}

// nativeApps returns the declared native apps by their ID, nil when there are none. It refuses an ID that does not
// match nativeAppIDPattern or comes twice, a Name that is empty, over 64 characters or has characters the consent
// screen would drop, a bad or repeated port, and a scheme that does not match schemePattern, is over maxSchemeLen or
// comes twice in any app.
func nativeApps(apps []NativeApp) (map[string]NativeApp, error) {
	if len(apps) == 0 {
		return nil, nil
	}
	out := make(map[string]NativeApp, len(apps))
	schemes := make(map[string]string) // scheme -> the ID of the app that declared it
	for _, a := range apps {
		if !nativeAppIDPattern.MatchString(a.ID) {
			return nil, fmt.Errorf("oauth: the native app id %q does not match %s", a.ID, nativeAppIDPattern)
		}
		if _, dup := out[a.ID]; dup {
			return nil, fmt.Errorf("oauth: the native app %q is declared twice", a.ID)
		}
		if a.Name == "" || displayName(a.Name, "") != a.Name {
			return nil, fmt.Errorf("oauth: the name %q of the native app %q is empty, over %d characters or has "+
				"invisible characters or spaces around it", a.Name, a.ID, maxNameRunes)
		}
		for i, p := range a.Ports {
			if p < 1 || p > 65535 || slices.Contains(a.Ports[:i], p) {
				return nil, fmt.Errorf("oauth: the port %d of the native app %q is not 1 to 65535 or comes twice", p, a.ID)
			}
		}
		for _, sc := range a.Schemes {
			if len(sc) > maxSchemeLen || !schemePattern.MatchString(sc) {
				return nil, fmt.Errorf("oauth: the scheme %q of the native app %q is not a lowercase reverse-DNS name "+
					"with a dot of at most %d characters", sc, a.ID, maxSchemeLen)
			}
			if other, dup := schemes[sc]; dup {
				return nil, fmt.Errorf("oauth: the scheme %q of the native app %q is declared twice (also by %q)",
					sc, a.ID, other)
			}
			schemes[sc] = a.ID
		}
		a.Ports, a.Schemes = slices.Clone(a.Ports), slices.Clone(a.Schemes)
		out[a.ID] = a
	}
	return out, nil
}

// schemeOwner returns the declared native app whose Schemes has scheme.
func (s *Server) schemeOwner(scheme string) (NativeApp, bool) {
	for _, a := range s.apps {
		if slices.Contains(a.Schemes, scheme) {
			return a, true
		}
	}
	return NativeApp{}, false
}

// nativeApp returns the declared native app of a client's assistant; ok is false for an assistant's client and for
// an app that is no longer declared.
func (s *Server) nativeApp(a core.Assistant) (NativeApp, bool) {
	id, ok := NativeAppID(a)
	if !ok {
		return NativeApp{}, false
	}
	app, ok := s.apps[id]
	return app, ok
}
