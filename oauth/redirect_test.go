package oauth

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// Invisible characters of the display-name tests, made from code points so the source shows what they are.
var (
	bidiOverride       = string(rune(0x202e)) // RIGHT-TO-LEFT OVERRIDE
	zeroWidth          = string([]rune{0x200b, 0x200d})
	lineSeparator      = string(rune(0x2028))
	paragraphSeparator = string(rune(0x2029))
)

func TestCallbackAssistant(t *testing.T) {
	const chatgpt, claude = core.AssistantChatGPT, core.AssistantClaude
	tests := []struct {
		uri  string
		want core.Assistant
	}{
		{"https://chatgpt.com/connector_platform_oauth_redirect", chatgpt},
		{"https://chat.openai.com/connector_platform_oauth_redirect", chatgpt},
		{"https://chatgpt.com/connector/oauth/abc_123-XYZ", chatgpt},
		{"https://chat.openai.com/connector/oauth/x", chatgpt},
		{"https://claude.ai/api/mcp/auth_callback", claude},
		{"https://claude.com/api/mcp/auth_callback", claude},

		{"http://claude.ai/api/mcp/auth_callback", ""}, // https only
		{"https://claude.ai:443/api/mcp/auth_callback", ""},
		{"https://claude.ai:/api/mcp/auth_callback", ""},
		{"https://user@claude.ai/api/mcp/auth_callback", ""},
		{"https://claude.ai/api/mcp/auth_callback?next=x", ""},
		{"https://claude.ai/api/mcp/auth_callback?", ""},
		{"https://claude.ai/api/mcp/auth_callback#x", ""},
		{"https://claude.ai/api/mcp/auth_callback#", ""},
		{"https://claude.ai/api/mcp/auth_callback/", ""},
		{"https://claude.ai/api/mcp/auth%5Fcallback", ""}, // an escape gives the same path two spellings
		{"https://Claude.ai/api/mcp/auth_callback", ""},
		{"HTTPS://claude.ai/api/mcp/auth_callback", ""},
		{"https://claude.ai./api/mcp/auth_callback", ""},
		{"https://evil.claude.ai/api/mcp/auth_callback", ""},
		{"https://claude.ai.evil.example/api/mcp/auth_callback", ""},
		{`https://claude.ai\@evil.example/api/mcp/auth_callback`, ""},
		{"//claude.ai/api/mcp/auth_callback", ""},
		{"https://claude.ai/api/mcp/auth_callback\n", ""},
		{"https://claude.ai/connector_platform_oauth_redirect", ""}, // the other assistant's path
		{"https://chatgpt.com/api/mcp/auth_callback", ""},
		{"https://chatgpt.com/connector/oauth/", ""},
		{"https://chatgpt.com/connector/oauth/a/b", ""},
		{"https://chatgpt.com/connector/oauth/..", ""},
		{"https://chatgpt.com/connector/oauth/a.b", ""},
		{"https://chatgpt.com/connector/oauth/a%2Fb", ""},
		{"https://chatgpt.com/connector/oauth/" + strings.Repeat("a", 129), ""},
		{"https://evil.example/cb", ""},
		{"not a url", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.uri), func(t *testing.T) {
			assert.Equal(t, tt.want, callbackAssistant(tt.uri, true))
			want := tt.want
			if strings.Contains(tt.uri, "/connector/oauth/") {
				want = "" // RefuseConnectorCallback
			}
			assert.Equal(t, want, callbackAssistant(tt.uri, false), "with per-connector callbacks refused")
		})
	}
}

func TestCallbackSet(t *testing.T) {
	many := make([]string, 11)
	for i := range many {
		many[i] = fmt.Sprintf("https://chatgpt.com/connector/oauth/cb%d", i)
	}
	tests := []struct {
		name      string
		uris      []string
		ok        bool
		want      []string
		assistant core.Assistant
	}{
		{"one", []string{claudeCallback}, true, []string{claudeCallback}, core.AssistantClaude},
		{"both of claude", []string{claudeCallback, "https://claude.com/api/mcp/auth_callback"}, true,
			[]string{claudeCallback, "https://claude.com/api/mcp/auth_callback"}, core.AssistantClaude},
		{"repeats dropped", []string{chatgptCallback, chatgptCallback, chatgptConnectors}, true,
			[]string{chatgptCallback, chatgptConnectors}, core.AssistantChatGPT},
		{"ten", many[:10], true, many[:10], core.AssistantChatGPT},
		{"eleven", many, false, nil, ""},
		{"none", nil, false, nil, ""},
		{"two assistants", []string{claudeCallback, chatgptCallback}, false, nil, ""},
		{"one foreign", []string{claudeCallback, "https://evil.example/cb"}, false, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, assistant, ok := callbackSet(tt.uris, true)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.assistant, assistant)
		})
	}
	t.Run("a per-connector callback when they are refused", func(t *testing.T) {
		_, _, ok := callbackSet([]string{chatgptCallback, chatgptConnectors}, false)
		assert.False(t, ok)
		got, _, ok := callbackSet([]string{chatgptCallback}, false)
		assert.True(t, ok)
		assert.Equal(t, []string{chatgptCallback}, got)
	})
}

func TestMetadataAssistant(t *testing.T) {
	tests := []struct {
		uri  string
		want core.Assistant
	}{
		{chatgptDocument, core.AssistantChatGPT},
		{"https://chatgpt.com/oauth/cb_42/client.json", core.AssistantChatGPT},
		{claudeDocument, core.AssistantClaude},
		{"https://claude.com/oauth/mcp-oauth-client-metadata", core.AssistantClaude},

		{"https://chat.openai.com/oauth/client.json", ""}, // a callback host, not a document host
		{"http://chatgpt.com/oauth/client.json", ""},
		{"https://chatgpt.com", ""},
		{"https://chatgpt.com/", ""},
		{"https://chatgpt.com/oauth/../client.json", ""},
		{"https://chatgpt.com/./client.json", ""},
		{"https://chatgpt.com/oauth/client.json?v=1", ""},
		{"https://chatgpt.com/oauth/client.json#x", ""},
		{"https://chatgpt.com:8443/oauth/client.json", ""},
		{"https://me@chatgpt.com/oauth/client.json", ""},
		{"https://evil.example/oauth/client.json", ""},
		{"cli_abcdefghijklmnop", ""},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			assert.Equal(t, tt.want, metadataAssistant(tt.uri))
		})
	}
}

func TestDisplayName(t *testing.T) {
	tests := []struct {
		name, in, want string
		assistant      core.Assistant
	}{
		{"kept", "Claude Desktop", "Claude Desktop", core.AssistantClaude},
		{"trimmed", "  ChatGPT  ", "ChatGPT", core.AssistantChatGPT},
		{"empty takes the assistant's", "", "Claude", core.AssistantClaude},
		{"blank takes the assistant's", " \t ", "ChatGPT", core.AssistantChatGPT},
		{"control characters dropped", "Cl\x00au\x1bde", "Claude", core.AssistantClaude},
		{"bidi override dropped", bidiOverride + "Your bank", "Your bank", core.AssistantChatGPT},
		{"zero-width only", zeroWidth, "ChatGPT", core.AssistantChatGPT},
		{"line separators dropped", "a" + lineSeparator + "b" + paragraphSeparator + "c", "abc", core.AssistantClaude},
		{"invalid UTF-8 dropped", "\xffok", "ok", core.AssistantClaude},
		{"cut to 64 characters", strings.Repeat("я", 100), strings.Repeat("я", 64), core.AssistantClaude},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, displayName(tt.in, tt.assistant))
		})
	}
}

func TestCheckIssuer(t *testing.T) {
	for _, ok := range []string{"https://hub.example.com", "https://hub.example.com:8443", "http://localhost:8080",
		"http://127.0.0.1:8080", "http://[::1]:8080"} {
		_, err := checkIssuer(ok)
		assert.NoError(t, err, ok)
	}
	for _, bad := range []string{"", "hub.example.com", "https://hub.example.com/", "https://hub.example.com/hub",
		"https://hub.example.com?x=1", "https://hub.example.com#x", "https://me@hub.example.com",
		"http://hub.example.com", "HTTPS://hub.example.com", "ftp://hub.example.com"} {
		_, err := checkIssuer(bad)
		assert.Error(t, err, bad)
	}
}
