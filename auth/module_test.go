package auth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/adminsock"
	"github.com/devXpro/mcp-gatekeeper/core"
)

// Auth with an admin socket, as an application wires them (Family Hub's cmd/hub through its Fx adapter):
// core.Sessions, the routes on a mux, and the commands on a real socket next to the application's own.
func TestWiring(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "gkauth-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "admin.sock")
	st := newFakeStore()
	reg := adminsock.NewRegistry()
	require.NoError(t, reg.Add(adminsock.Command{Name: "status", Summary: "the application's own",
		Run: func(context.Context, adminsock.Invocation) error { return nil }}))
	a, err := New(Options{Site: testSite, Brand: testBrand, Store: st, Admin: reg,
		AdminCLI: "hub admin"})
	require.NoError(t, err)
	var sessions core.Sessions = a
	var routes core.RouteRegistrar = a
	assert.Equal(t, testHost, a.site.RPID, "the RP ID defaults to the public URL's host")
	srv, err := adminsock.New(adminsock.Options{Path: path, Registry: reg})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, a.Start(ctx))
	require.NoError(t, srv.Start(ctx))

	c := adminsock.NewClient(path)
	list, err := c.Commands(ctx)
	require.NoError(t, err)
	require.Len(t, list, 3)
	assert.Equal(t, "reset-access", list[0].Name)
	assert.Equal(t, "setup-link", list[1].Name)
	assert.Equal(t, "status", list[2].Name)
	var out bytes.Buffer
	require.NoError(t, c.Run(ctx, "setup-link", nil, nil, &out))
	assert.Contains(t, out.String(), testOrigin+"/setup#t=")
	// The audit names the socket's peer: this test process (review GK-5), and who started it (review R-5).
	entries := st.Audit().(fakeAudit).entries()
	require.NotEmpty(t, entries)
	assert.Equal(t, strconv.Itoa(os.Getpid()), entries[len(entries)-1].Detail["peer_pid"])
	assert.NotEmpty(t, entries[len(entries)-1].Detail["peer_exe"])
	assert.Contains(t, entries[len(entries)-1].Detail["peer_chain"], " (pid "+strconv.Itoa(os.Getppid())+")")
	// Through the CLI: a second link is fine while nobody registered; a superadmin with a passkey blocks it.
	cli := adminsock.CLI{Socket: path, Prog: "hub admin", App: "hub"}
	var stdout, stderr bytes.Buffer
	assert.Equal(t, adminsock.ExitOK, cli.Run(ctx, []string{"setup-link"}, nil, &stdout, &stderr))
	assert.Contains(t, stdout.String(), testOrigin+"/setup#t=")
	require.NoError(t, st.Accounts().Create(ctx, core.Account{ID: "acc_aaaaaaaaaaaaaaaa", Name: "Семья"}))
	require.NoError(t, st.People().Create(ctx, core.Person{ID: "per_aaaaaaaaaaaaaaaa", AccountID: "acc_aaaaaaaaaaaaaaaa",
		Name: "Алиса", Role: core.RoleOwner, Superadmin: true}))
	require.NoError(t, st.Passkeys().Add(ctx, core.Passkey{ID: "pk_aaaaaaaaaaaaaaaa", PersonID: "per_aaaaaaaaaaaaaaaa",
		CredentialID: []byte("cred"), Data: mustEncode(t, testHost)}))
	stderr.Reset()
	assert.Equal(t, adminsock.ExitFailed, cli.Run(ctx, []string{"setup-link"}, nil, &stdout, &stderr))
	assert.Equal(t, "hub admin setup-link: the superadmin already has a passkey; `hub admin reset-access` replaces it\n",
		stderr.String())

	mux := http.NewServeMux()
	routes.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/me", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	_, err = sessions.Viewer(httptest.NewRequest(http.MethodGet, "/", nil))
	require.ErrorIs(t, err, core.ErrNoSession)

	require.NoError(t, srv.Stop(ctx))
	require.NoError(t, a.Stop(ctx))
	require.NoError(t, a.Stop(ctx), "a second stop is a no-op")

	// A registry that already holds auth's commands refuses a second Auth.
	_, err = New(Options{Site: testSite, Brand: testBrand, Store: st, Admin: reg})
	require.ErrorContains(t, err, "registered twice")
}

func mustEncode(t *testing.T, rpID string) []byte {
	t.Helper()
	b, err := encodeCredential(rpID, &webauthn.Credential{ID: []byte("cred"), PublicKey: []byte{1}})
	require.NoError(t, err)
	return b
}

func TestStartStop(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	require.NoError(t, e.a.Start(ctx))
	require.NoError(t, e.a.Start(ctx), "a second start is a no-op")
	require.NoError(t, e.a.Stop(ctx))
	require.NoError(t, e.a.Stop(ctx))
}

func TestNew(t *testing.T) {
	st := newFakeStore()
	_, err := New(Options{Site: testSite, Brand: testBrand})
	require.Error(t, err, "a store is required")
	remote := core.ClientIPRemote
	for _, site := range []core.Site{
		{PublicURL: "", ClientIP: remote},
		{PublicURL: "hub.example.com", ClientIP: remote},
		{PublicURL: "ftp://hub.example.com", ClientIP: remote},
		{PublicURL: "https://hub.example.com/path", ClientIP: remote},
		{PublicURL: "https://hub.example.com/", ClientIP: remote},
		{PublicURL: "https://hub.example.com?q=1", ClientIP: remote},
		{PublicURL: "https://user@hub.example.com", ClientIP: remote},
		{PublicURL: "https://hub.example.com", RPID: "other.example.com", ClientIP: remote},
		{PublicURL: "https://hub.example.com", RPID: "ub.example.com", ClientIP: remote},
		{PublicURL: "http://hub.example.com", ClientIP: remote},
		// Review GK-2: no client address mode, or an unknown one, would silently mean the TCP peer.
		{PublicURL: "https://hub.example.com"},
		{PublicURL: "https://hub.example.com", ClientIP: "cf-connecting"},
	} {
		_, err := New(Options{Site: site, Brand: testBrand, Store: st})
		require.Error(t, err, "%+v", site)
	}
	_, err = New(Options{Site: core.Site{PublicURL: testOrigin, ClientIP: "x-real-ip"}, Brand: testBrand, Store: st})
	require.ErrorContains(t, err, "client address mode")
	for _, tc := range []struct {
		in       core.Site
		url, rpi string
	}{
		{core.Site{PublicURL: "https://Hub.Example.com", ClientIP: remote}, "https://hub.example.com", "hub.example.com"},
		{core.Site{PublicURL: "https://hub.example.com", RPID: "example.com", ClientIP: core.ClientIPForwarded},
			"https://hub.example.com", "example.com"},
		{core.Site{PublicURL: "http://localhost:5173", ClientIP: remote}, "http://localhost:5173", "localhost"},
		{core.Site{PublicURL: testOrigin, ClientIP: core.ClientIPCloudflare}, testOrigin, testHost},
	} {
		a, err := New(Options{Site: tc.in, Brand: testBrand, Store: st})
		require.NoError(t, err, "%+v", tc.in)
		assert.Equal(t, tc.url, a.site.PublicURL)
		assert.Equal(t, tc.rpi, a.site.RPID)
	}
	// Without a clock the system clock is used, in UTC.
	a, err := New(Options{Site: testSite, Brand: testBrand, Store: st})
	require.NoError(t, err)
	assert.Equal(t, time.UTC, a.now().Location())
	assert.WithinDuration(t, time.Now(), a.now(), time.Minute)
	assert.Equal(t, "admin", a.adminCLI, "the admin command's default name")

	// The brand must make a valid cookie and header.
	for _, b := range []core.Brand{
		{Product: product, SessionCookie: "fh_session", CSRFHeader: csrfHeader},
		{Product: product, SessionCookie: "__Host-fh session", CSRFHeader: csrfHeader},
		{Product: product, SessionCookie: "__Host-", CSRFHeader: csrfHeader},
		{Product: product, SessionCookie: cookieName, CSRFHeader: ""},
		{Product: product, SessionCookie: cookieName, CSRFHeader: "X Family"},
		{Product: product, SessionCookie: cookieName, CSRFHeader: "X-Семья"},
		{Product: " ", SessionCookie: cookieName, CSRFHeader: csrfHeader},
	} {
		_, err := New(Options{Site: testSite, Brand: b, Store: st})
		require.Error(t, err, "%+v", b)
	}
	// Reset steps need a key, a phrase and a Run, and a key of their own.
	run := func(context.Context, core.Person, time.Time) (int, error) { return 0, nil }
	for _, steps := range [][]ResetStep{
		{{Key: "", Phrase: "keys", Run: run}},
		{{Key: "keys", Phrase: "", Run: run}},
		{{Key: "keys", Phrase: "keys"}},
		{{Key: "grants", Phrase: "grants", Run: run}},
		{{Key: "keys", Phrase: "keys", Run: run}, {Key: "keys", Phrase: "more keys", Run: run}},
	} {
		_, err := New(Options{Site: testSite, Brand: testBrand, Store: st, ResetSteps: steps})
		require.Error(t, err, "%+v", steps)
	}
}

// The relying party's name in the passkey prompt is the brand's product.
func TestProductName(t *testing.T) {
	st := newFakeStore()
	brand := testBrand
	brand.Product = "Homie"
	a, err := New(Options{Site: testSite, Brand: brand, Store: st})
	require.NoError(t, err)
	mux := http.NewServeMux()
	a.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login/begin", nil)
	req.Header.Set(csrfHeader, "1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "Homie", user{id: "per_x", rp: "Homie"}.WebAuthnName(), "a person without a name yet")
	assert.Equal(t, "Homie", a.wa.Config.RPDisplayName)
	assert.True(t, strings.Contains(rec.Body.String(), `"rpId":"hub.example.com"`), rec.Body.String())
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"  Наш дом \t":                "Наш дом",
		"«Семья»":                     "«Семья»",
		"Alice's":                     "Alice's",
		"🏠 Дача 2":                    "🏠 Дача 2",
		"Ю" + strings.Repeat("x", 39): "Ю" + strings.Repeat("x", 39),
	} {
		got, err := NormalizeName(in)
		require.NoError(t, err, "%q", in)
		assert.Equal(t, want, got)
	}
	for _, bad := range []string{
		"", " ", strings.Repeat("x", 41), "a\x00b", "line\nbreak", "cr\rhere", "tab\tinside", "\xff\xfe",
		"nel" + string(rune(0x85)) + "here", "line" + string(rune(0x2028)) + "sep", "para" + string(rune(0x2029)) + "sep",
		"rtl" + string(rune(0x202e)) + "override", "isolate" + string(rune(0x2066)) + "x", "mark" + string(rune(0x200f)),
		"arabic" + string(rune(0x061c)), `say "hi"`, `back\slash`, "tick`", "replacement" + string(rune(0xfffd)),
	} {
		_, err := NormalizeName(bad)
		require.ErrorIs(t, err, ErrInvalidName, "%q accepted", bad)
	}
}

func TestDefaultPasskeyName(t *testing.T) {
	for ua, want := range map[string]string{
		safariMac: "Mac",
		safariIOS: "iPhone",
		"Mozilla/5.0 (iPad; CPU OS 19_0 like Mac OS X) AppleWebKit/605.1.15":            "iPad",
		"Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/140.0 Mobile":        "Android",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0": "Windows",
		"Mozilla/5.0 (X11; CrOS x86_64 16000.0.0) AppleWebKit/537.36":                   "ChromeOS",
		"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0":        "Linux",
		"curl/8.11.1": "Passkey",
		"":            "Passkey",
	} {
		assert.Equal(t, want, defaultPasskeyName(ua), ua)
	}
}

func TestClip(t *testing.T) {
	assert.Equal(t, "abc", clip("abc", 5))
	assert.Equal(t, "ab", clip("abc", 2))
	assert.Equal(t, "я", clip("яя", 3), "never half a character")
	assert.Equal(t, "", clip("я", 1))
}

func TestPlausiblePersonID(t *testing.T) {
	assert.True(t, plausiblePersonID([]byte(core.NewID(core.PrefixPerson))))
	for _, bad := range []string{"", "per_", "acc_aaaaaaaaaaaaaaaa", "admin", "per_" + strings.Repeat("a", 61)} {
		assert.False(t, plausiblePersonID([]byte(bad)), bad)
	}
}

// The stored form keeps what go-webauthn needs at the next assertion, the raw flags included.
func TestCredentialRoundTrip(t *testing.T) {
	flags := protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagBackupEligible | protocol.FlagBackupState
	in := webauthn.Credential{
		ID: []byte{1, 2, 3}, PublicKey: []byte{4, 5}, AttestationFormat: "none",
		Transport: []protocol.AuthenticatorTransport{protocol.Internal, protocol.Hybrid},
		Flags:     webauthn.NewCredentialFlags(flags),
		Authenticator: webauthn.Authenticator{
			AAGUID: make([]byte, 16), SignCount: 7, CloneWarning: true,
		},
	}
	blob, err := encodeCredential(testHost, &in)
	require.NoError(t, err)
	rpID, out, err := decodeCredential(blob)
	require.NoError(t, err)
	assert.Equal(t, testHost, rpID)
	assert.Equal(t, flags, out.Flags.ProtocolValue())
	assert.True(t, out.Flags.BackupEligible)
	assert.Equal(t, uint32(7), out.Authenticator.SignCount)
	assert.False(t, out.Authenticator.CloneWarning, "a clone warning is never stored")
	assert.Equal(t, in.PublicKey, out.PublicKey)
	assert.Len(t, out.Transport, 2)
	_, _, err = decodeCredential([]byte(`{"v":2}`))
	require.Error(t, err)
	_, _, err = decodeCredential([]byte(`junk`))
	require.Error(t, err)
}

// A passkey whose stored credential cannot be read is kept, unusable: it never signs in and it can be deleted.
func TestUnreadablePasskey(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	b, admin := e.superadmin(newDevice())
	pid := core.PersonID(admin.Person.ID)
	require.NoError(t, e.st.Passkeys().Add(ctx, core.Passkey{ID: "pk_junkjunkjunkjunkj", PersonID: pid,
		CredentialID: []byte("junk"), Data: []byte("junk"), Name: "Сломанный", CreatedAt: e.clock.Now()}))
	pks, err := e.a.passkeysOf(ctx, pid)
	require.NoError(t, err)
	require.Len(t, pks, 2)
	assert.Len(t, usableCreds(pks), 1)
	assert.True(t, e.logged("auth: unreadable passkey"))
	wantStatus(t, b.do(http.MethodDelete, "/api/me/passkeys/pk_junkjunkjunkjunkj", nil), http.StatusNoContent)
}

func TestRequestFormat(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	for _, tc := range []struct {
		name, body, contentType string
		status                  int
		msg                     string
	}{
		{"not an object", "[1]", "", http.StatusBadRequest, "must be a JSON object"},
		{"broken JSON", "{", "", http.StatusBadRequest, "not valid JSON"},
		{"two values", `{"token":"a"} {}`, "", http.StatusBadRequest, "more than one"},
		{"a wrong type", `{"token":5}`, "", http.StatusBadRequest, "token has the wrong type"},
		{"not JSON", `{"token":"a"}`, "text/plain", http.StatusUnsupportedMediaType, "send application/json"},
		{"too large", `{"token":"` + strings.Repeat("a", maxBody) + `"}`, "", http.StatusRequestEntityTooLarge, "over 64 KiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b.header.Del("Content-Type")
			if tc.contentType != "" {
				b.header.Set("Content-Type", tc.contentType)
			}
			body := wantError(t, b.do(http.MethodPost, "/api/auth/token", tc.body), tc.status, "invalid")
			assert.Contains(t, body.Message, tc.msg)
		})
	}
	b.header.Del("Content-Type")

	// An empty body is {}; every answer is uncacheable JSON.
	for _, rec := range []*httptest.ResponseRecorder{
		b.do(http.MethodPost, "/api/auth/login/begin", nil),
		b.do(http.MethodPost, "/api/auth/token", map[string]string{"token": "x"}),
		b.do(http.MethodGet, "/api/me", nil),
	} {
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
	}
}
