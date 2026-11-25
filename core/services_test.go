package core

import (
	"testing"
	"time"
)

func TestResourcePaths(t *testing.T) {
	per := PerResource{Prefix: "/mcp/"}
	one := SingleResource{At: "/mcp", ID: "home"}
	tests := []struct {
		name  string
		paths ResourcePaths
		path  string
		want  ResourceID
		ok    bool
	}{
		{"per: the resource", per, "/mcp/notes", "notes", true},
		{"per: below it", per, "/mcp/notes/sse", "notes", true},
		{"per: no id", per, "/mcp/", "", false},
		{"per: the prefix without a slash", per, "/mcp", "", false},
		{"per: another path", per, "/oauth/token", "", false},
		{"single: the path", one, "/mcp", "home", true},
		{"single: below it", one, "/mcp/messages", "home", true},
		{"single: a longer word", one, "/mcpx", "", false},
		{"single: another path", one, "/api/me", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.paths.FromPath(tt.path)
			if got != tt.want || ok != tt.ok {
				t.Errorf("FromPath(%q) = %q, %v; want %q, %v", tt.path, got, ok, tt.want, tt.ok)
			}
		})
	}
	if p := per.Path("photos"); p != "/mcp/photos" {
		t.Errorf("PerResource.Path = %q", p)
	}
	if p := one.Path("anything"); p != "/mcp" {
		t.Errorf("SingleResource.Path = %q", p)
	}
}

func TestNewID(t *testing.T) {
	a, b := NewID(PrefixGrant), NewID(PrefixGrant)
	if a == b || len(a) != len("grt_")+16 || a[:4] != "grt_" {
		t.Errorf("NewID = %q, %q", a, b)
	}
}

func TestPersonActive(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	tests := []struct {
		name string
		p    Person
		want bool
	}{
		{"no term", Person{}, true},
		{"before the end of the term", Person{AccessUntil: &future}, true},
		{"at the end of the term", Person{AccessUntil: &now}, false},
		{"after the end of the term", Person{AccessUntil: &past}, false},
		{"disabled", Person{DisabledAt: &past}, false},
		{"disabled with a term ahead", Person{DisabledAt: &past, AccessUntil: &future}, false},
	}
	for _, tt := range tests {
		if got := tt.p.Active(now); got != tt.want {
			t.Errorf("%s: Active = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSiteValidate(t *testing.T) {
	for _, s := range []Site{
		{PublicURL: "https://hub.example.com", RPID: "hub.example.com", ClientIP: ClientIPCloudflare},
		{PublicURL: "https://hub.example.com", ClientIP: ClientIPRemote},
		{PublicURL: "https://home.example.com:8443", RPID: "example.com", ClientIP: ClientIPForwarded},
		{PublicURL: "http://localhost:8080", RPID: "localhost", ClientIP: ClientIPRemote},
		{PublicURL: "http://127.0.0.1:8080", ClientIP: ClientIPRemote},
		{PublicURL: "http://[::1]:8080", ClientIP: ClientIPRemote},
	} {
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", s, err)
		}
	}
	for name, s := range map[string]Site{
		"an empty mode":                     {PublicURL: "https://hub.example.com"},
		"an unknown mode":                   {PublicURL: "https://hub.example.com", ClientIP: "cf-connecting"},
		"a trailing slash":                  {PublicURL: "https://hub.example.com/", ClientIP: ClientIPRemote},
		"a path":                            {PublicURL: "https://hub.example.com/hub", ClientIP: ClientIPRemote},
		"a query":                           {PublicURL: "https://hub.example.com?x=1", ClientIP: ClientIPRemote},
		"a fragment":                        {PublicURL: "https://hub.example.com#x", ClientIP: ClientIPRemote},
		"credentials":                       {PublicURL: "https://u@hub.example.com", ClientIP: ClientIPRemote},
		"no host":                           {PublicURL: "https://", ClientIP: ClientIPRemote},
		"not a URL":                         {PublicURL: "hub.example.com", ClientIP: ClientIPRemote},
		"plain http on a public host":       {PublicURL: "http://hub.example.com", ClientIP: ClientIPRemote},
		"another scheme":                    {PublicURL: "ftp://hub.example.com", ClientIP: ClientIPRemote},
		"a foreign RP ID":                   {PublicURL: "https://hub.example.com", RPID: "other.example.com", ClientIP: ClientIPRemote},
		"an RP ID that is no label of host": {PublicURL: "https://myexample.com", RPID: "example.com", ClientIP: ClientIPRemote},
		"an empty query":                    {PublicURL: "https://hub.example.com?", ClientIP: ClientIPRemote},
		"an empty fragment":                 {PublicURL: "https://hub.example.com#", ClientIP: ClientIPRemote},
		"a port without a host":             {PublicURL: "https://:443", ClientIP: ClientIPRemote},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: Validate(%+v) = nil, want an error", name, s)
		}
	}
}

func TestBrandWords(t *testing.T) {
	var fh Brand
	if fh.ResourceWord() != "module" || fh.AppWord() != "hub" {
		t.Errorf("defaults = %q, %q; want Family Hub's words", fh.ResourceWord(), fh.AppWord())
	}
	home := Brand{ResourceNoun: "home", AppNoun: "Homie"}
	if home.ResourceWord() != "home" || home.AppWord() != "Homie" {
		t.Errorf("custom = %q, %q", home.ResourceWord(), home.AppWord())
	}
}
