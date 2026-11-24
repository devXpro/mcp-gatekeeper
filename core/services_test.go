package core

import "testing"

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
