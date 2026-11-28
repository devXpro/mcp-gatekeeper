package oauth

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// NativeApp is a program of the application's own that runs on the person's computer and connects the way an
// assistant does, but with a loopback redirect (RFC 8252): it registers by DCR with software_id ID, and its client's
// core.Assistant is AppAssistantPrefix + ID. The application maps that to its own client label.
type NativeApp struct {
	ID   string // ^[a-z][a-z0-9-]{1,30}$, e.g. "desk"; the software_id of its registrations
	Name string // what the consent screen calls it, e.g. "Desk"; at most 64 characters, none invisible

	// Ports, when set, are the only loopback ports the app's redirect may use (1 to 65535, no repeats): another
	// program on the computer that listens on a port of its own cannot receive the app's code then. None (the
	// default) allows any port, as RFC 8252 §7.3 describes.
	Ports []int
}

// AppAssistantPrefix starts the core.Assistant of a native app's client: "app:<ID>".
const AppAssistantPrefix = "app:"

// nativeAppIDPattern is a NativeApp.ID.
var nativeAppIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// NativeAppID returns the NativeApp.ID of a native app's client from its assistant, and false for any other client.
func NativeAppID(a core.Assistant) (string, bool) {
	id, ok := strings.CutPrefix(string(a), AppAssistantPrefix)
	return id, ok && nativeAppIDPattern.MatchString(id)
}

// nativeApps returns the declared native apps by their ID, nil when there are none. It refuses an ID that does not
// match nativeAppIDPattern or comes twice, and a Name that is empty, over 64 characters or has characters the
// consent screen would drop.
func nativeApps(apps []NativeApp) (map[string]NativeApp, error) {
	if len(apps) == 0 {
		return nil, nil
	}
	out := make(map[string]NativeApp, len(apps))
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
		a.Ports = slices.Clone(a.Ports)
		out[a.ID] = a
	}
	return out, nil
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
