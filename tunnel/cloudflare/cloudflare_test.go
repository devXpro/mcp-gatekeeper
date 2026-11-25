package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tunnelID = "6ff42ae2-765d-4adf-8112-31c55c1551ef"

// fakeCloudflared plays the cloudflared CLI: login saves a certificate in $HOME, create writes credentials, route dns
// answers what the test says.
type fakeCloudflared struct {
	mu        sync.Mutex
	calls     [][]string
	envs      [][]string
	loginFail bool
	noCert    bool
	createOut string // non-empty: create fails with this output
	dnsOut    string // non-empty: route dns fails with this output
	certSeen  []string
}

func envValue(env []string, key string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v
		}
	}
	return ""
}

func (f *fakeCloudflared) Run(_ context.Context, env, args []string, line func(string)) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, args)
	f.envs = append(f.envs, env)
	f.mu.Unlock()
	emit := func(s string) {
		if line != nil {
			line(s)
		}
	}
	cert := envValue(env, "TUNNEL_ORIGIN_CERT")
	if strings.Join(args[:2], " ") == "tunnel login" {
		emit("Please open the following URL and log in with your Cloudflare account:")
		emit("")
		emit("https://dash.cloudflare.com/argotunnel?aud=&callback=https%3A%2F%2Flogin.cloudflareaccess.org%2Fabc")
		emit("")
		emit("Leave cloudflared running to download the cert automatically.")
		if f.loginFail {
			return "Failed to fetch resource\n", errors.New("exit status 1")
		}
		if !f.noCert {
			if err := os.MkdirAll(filepath.Join(envValue(env, "HOME"), ".cloudflared"), 0o700); err != nil {
				return "", err
			}
			if err := os.WriteFile(filepath.Join(envValue(env, "HOME"), ".cloudflared", "cert.pem"), []byte("CERT"), 0o600); err != nil {
				return "", err
			}
		}
		return "You have successfully logged in.\n", nil
	}
	f.certSeen = append(f.certSeen, cert)
	switch args[1] {
	case "create":
		if f.createOut != "" {
			return f.createOut, errors.New("exit status 1")
		}
		creds := args[3]
		if err := os.WriteFile(creds, []byte(`{"AccountTag":"acc","TunnelSecret":"c2VjcmV0","TunnelID":"`+tunnelID+`"}`), 0o644); err != nil { //nolint:gosec // the fake writes what cloudflared writes
			return "", err
		}
		return "Created tunnel " + args[4] + " with id " + tunnelID + "\n", nil
	case "route":
		if f.dnsOut != "" {
			return f.dnsOut, errors.New("exit status 1")
		}
		return "Added CNAME " + args[len(args)-1] + " which will route to this tunnel\n", nil
	}
	return "", errors.New("unexpected command " + strings.Join(args, " "))
}

func (f *fakeCloudflared) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func newConnector(t *testing.T, f *fakeCloudflared) *Connector {
	t.Helper()
	c, err := New(Options{Runner: f, Dir: filepath.Join(t.TempDir(), "tunnel"), Service: "http://fh-hub:8080",
		TempDir: t.TempDir(), NamePrefix: "family-hub-", StartHint: "docker compose restart cloudflared"})
	require.NoError(t, err)
	return c
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	require.NoError(t, err)
	return st.Mode().Perm()
}

func noLeftoverHome(t *testing.T, c *Connector) {
	t.Helper()
	left, err := os.ReadDir(c.tempDir)
	require.NoError(t, err)
	assert.Empty(t, left, "the temporary HOME with the account certificate is gone")
}

func TestConnect(t *testing.T) {
	f := &fakeCloudflared{}
	c := newConnector(t, f)
	var out bytes.Buffer
	rec, err := c.Connect(t.Context(), ConnectOptions{Hostname: "Hub.Example.com"}, &out)
	require.NoError(t, err, out.String())
	assert.Equal(t, Record{Name: "family-hub-hub-example-com", ID: tunnelID, Hostname: "hub.example.com"}, rec)

	creds := filepath.Join(c.dir, CredentialsFile)
	assert.Equal(t, []string{
		"tunnel login",
		"tunnel create --credentials-file " + creds + " family-hub-hub-example-com",
		"tunnel route dns " + tunnelID + " hub.example.com",
	}, f.commands())
	assert.Equal(t, 1, strings.Count(out.String(), "https://dash.cloudflare.com/argotunnel"), "the link is shown once")
	assert.Contains(t, out.String(), "Deleted the Cloudflare account certificate")

	// Every step runs with a private HOME, the certificate in it, and no PATH to open a browser with.
	for _, env := range f.envs {
		home := envValue(env, "HOME")
		assert.Equal(t, filepath.Join(home, ".cloudflared", "cert.pem"), envValue(env, "TUNNEL_ORIGIN_CERT"))
		assert.True(t, strings.HasPrefix(home, c.tempDir), home)
		assert.Len(t, env, 3, "nothing of the hub's environment reaches cloudflared")
	}
	noLeftoverHome(t, c)

	cfg, err := os.ReadFile(filepath.Join(c.dir, ConfigFile))
	require.NoError(t, err)
	assert.Equal(t, "tunnel: "+tunnelID+"\ncredentials-file: '"+creds+"'\nno-autoupdate: true\ningress:\n"+
		"  - hostname: hub.example.com\n    service: http://fh-hub:8080\n  - service: http_status:404\n", string(cfg))
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o700), mode(t, c.dir))
		for _, name := range []string{ConfigFile, CredentialsFile, RecordFile} {
			assert.Equal(t, os.FileMode(0o600), mode(t, filepath.Join(c.dir, name)), name)
		}
	}
	got, err := ReadRecord(c.dir)
	require.NoError(t, err)
	assert.Equal(t, rec, got)

	// A second run reuses the tunnel: login and DNS again, no new tunnel.
	f.calls = nil
	_, err = c.Connect(t.Context(), ConnectOptions{Hostname: "hub.example.com", OverwriteDNS: true}, &out)
	require.NoError(t, err)
	assert.Equal(t, []string{"tunnel login", "tunnel route dns --overwrite-dns " + tunnelID + " hub.example.com"},
		f.commands())
	assert.Contains(t, out.String(), "reusing tunnel family-hub-hub-example-com")
	noLeftoverHome(t, c)
}

// A tunnel directory whose name holds YAML syntax (": ", " #", a quote) still gives a config.yml that reads back the
// exact credentials path (review R-14).
func TestConfigQuotesTheCredentialsPath(t *testing.T) {
	f := &fakeCloudflared{}
	dir := filepath.Join(t.TempDir(), "my data: it's #1", "tunnel")
	c, err := New(Options{Runner: f, Dir: dir, Service: "http://127.0.0.1:8080", TempDir: t.TempDir()})
	require.NoError(t, err)
	_, err = c.Connect(t.Context(), ConnectOptions{Hostname: "home.example.com"}, &bytes.Buffer{})
	require.NoError(t, err)

	cfg, err := os.ReadFile(filepath.Join(dir, ConfigFile)) //nolint:gosec // G304: the test's own directory
	require.NoError(t, err)
	creds := filepath.Join(dir, CredentialsFile)
	assert.Contains(t, string(cfg), "\ncredentials-file: '"+strings.ReplaceAll(creds, "'", "''")+"'\n")
	want, err := json.Marshal(map[string]any{
		"tunnel": tunnelID, "credentials-file": creds, "no-autoupdate": true,
		"ingress": []map[string]string{{"hostname": "home.example.com", "service": "http://127.0.0.1:8080"},
			{"service": "http_status:404"}},
	})
	require.NoError(t, err)
	assert.YAMLEq(t, string(want), string(cfg), "a YAML parser reads the exact values back")
}

func TestYAMLQuote(t *testing.T) {
	for in, want := range map[string]string{ //nolint:gosec // G101: paths, no credentials
		"/home/user/data/credentials.json": "'/home/user/data/credentials.json'",
		"/home/user/a: b #c/x.json":        "'/home/user/a: b #c/x.json'",
		"/home/user/it's/x.json":           "'/home/user/it''s/x.json'",
		"":                                 "''",
	} {
		assert.Equal(t, want, yamlQuote(in), in)
	}
}

func TestConnectFailures(t *testing.T) {
	tests := []struct {
		name  string
		host  string
		fake  *fakeCloudflared
		want  string
		calls int
	}{
		{name: "bad host", host: "hub", want: "not a full host name"},
		{name: "host with a path", host: "hub.example.com/x", want: "not a full host name"},
		{name: "login fails", host: "hub.example.com", fake: &fakeCloudflared{loginFail: true},
			want: "authorization did not complete (the link lives a few minutes): Failed to fetch resource", calls: 1},
		{name: "login leaves no certificate", host: "hub.example.com", fake: &fakeCloudflared{noCert: true},
			want: "authorization did not complete", calls: 1},
		{name: "tunnel name taken", host: "hub.example.com",
			fake: &fakeCloudflared{createOut: "failed to create tunnel: tunnel with name already exists\n"},
			want: "already has a tunnel named family-hub-hub-example-com", calls: 2},
		{name: "create fails", host: "hub.example.com", fake: &fakeCloudflared{createOut: "boom\nnetwork down\n"},
			want: "could not create the tunnel: network down", calls: 2},
		{name: "dns record exists", host: "hub.example.com",
			fake: &fakeCloudflared{dnsOut: "Failed to add route: code: 1003, reason: An A, AAAA, or CNAME record with that host already exists.\n"},
			want: "run again with --overwrite-dns", calls: 3},
		{name: "dns fails", host: "hub.example.com", fake: &fakeCloudflared{dnsOut: "zone not found\n"},
			want: "could not add the DNS record: zone not found", calls: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fake
			if f == nil {
				f = &fakeCloudflared{}
			}
			c := newConnector(t, f)
			_, err := c.Connect(t.Context(), ConnectOptions{Hostname: tt.host}, &bytes.Buffer{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Len(t, f.commands(), tt.calls)
			noLeftoverHome(t, c)
			assert.NoFileExists(t, filepath.Join(c.dir, ConfigFile))
			for _, cert := range f.certSeen {
				assert.NoFileExists(t, cert)
			}
		})
	}
}

func TestConnectIsSerialized(t *testing.T) {
	c := newConnector(t, &fakeCloudflared{})
	c.mu.Lock()
	_, err := c.Connect(t.Context(), ConnectOptions{Hostname: "hub.example.com"}, &bytes.Buffer{})
	c.mu.Unlock()
	require.ErrorContains(t, err, "another")
}

func TestReadRecordBroken(t *testing.T) {
	dir := t.TempDir()
	r, err := ReadRecord(dir)
	require.NoError(t, err)
	assert.Equal(t, Record{}, r)
	require.NoError(t, os.WriteFile(filepath.Join(dir, RecordFile), []byte("{"), 0o600))
	_, err = ReadRecord(dir)
	require.ErrorContains(t, err, "broken")
}

func TestExecRunner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	var lines []string
	out, err := ExecRunner{Binary: "/bin/sh"}.Run(t.Context(), []string{"A=1"},
		[]string{"-c", `echo one; echo "two $A" >&2; exit 3`}, func(l string) { lines = append(lines, l) })
	require.Error(t, err)
	assert.Equal(t, "one\ntwo 1\n", out)
	slices.Sort(lines)
	assert.Equal(t, []string{"one", "two 1"}, lines)

	_, err = ExecRunner{Binary: "no-such-cloudflared-binary"}.Run(t.Context(), nil, nil, nil)
	require.ErrorContains(t, err, "not installed")
}

func TestNewValidatesAndDefaults(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Options{Service: "http://app:8080"})
	require.ErrorContains(t, err, "Dir")
	_, err = New(Options{Dir: dir})
	require.ErrorContains(t, err, "Service")
	_, err = New(Options{Dir: dir, Service: "http://app:8080\nextra: 1"})
	require.ErrorContains(t, err, "Service")
	_, err = New(Options{Dir: dir, Service: "http://app:8080", NamePrefix: "Bad Prefix"})
	require.ErrorContains(t, err, "NamePrefix")

	c, err := New(Options{Dir: dir, Service: "http://app:8080"})
	require.NoError(t, err)
	assert.Equal(t, dir, c.Dir())
	assert.Equal(t, ExecRunner{Binary: "cloudflared"}, c.runner)
	assert.Equal(t, DefaultNamePrefix, c.namePrefix)
}

// The tunnel's name starts with the application's prefix, and the start hint closes the output only when given.
func TestConnectNameAndHint(t *testing.T) {
	f := &fakeCloudflared{}
	c, err := New(Options{Runner: f, Dir: filepath.Join(t.TempDir(), "tunnel"), Service: "http://app:8080", TempDir: t.TempDir()})
	require.NoError(t, err)
	var out bytes.Buffer
	rec, err := c.Connect(t.Context(), ConnectOptions{Hostname: "app.example.com"}, &out)
	require.NoError(t, err)
	assert.Equal(t, "mcp-gatekeeper-app-example-com", rec.Name)
	assert.NotContains(t, out.String(), "Start it")

	c = newConnector(t, f)
	out.Reset()
	_, err = c.Connect(t.Context(), ConnectOptions{Hostname: "app.example.com"}, &out)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(out.String(), "Start it: docker compose restart cloudflared\n"), out.String())
}
