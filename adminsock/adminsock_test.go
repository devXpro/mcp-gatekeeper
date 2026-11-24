package adminsock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/internal/testlog"
)

// socketDir returns a fresh directory with a short path: sun_path holds only 104 bytes on macOS, and t.TempDir()
// paths there are long.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "fhas-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// gate lets a test hold a running command until it says so.
type gate struct {
	started chan struct{}
	release chan struct{}
}

func newGate() *gate { return &gate{started: make(chan struct{}), release: make(chan struct{})} }

func testCommands(g *gate) []Command {
	return []Command{
		{Name: "hello", Usage: "[names…]", Summary: "greets", Run: func(_ context.Context, inv Invocation) error {
			_, err := fmt.Fprintf(inv.Out, "hello %s\n", strings.Join(inv.Args, ","))
			return err
		}},
		{Name: "legacy-key import", Usage: "--label <l>", Summary: "reads a key", Stdin: true,
			Run: func(_ context.Context, inv Invocation) error {
				_, err := fmt.Fprintf(inv.Out, "got %d bytes, args %v\n", len(inv.Stdin), inv.Args)
				return err
			}},
		{Name: "legacy-key", Summary: "the shorter name", Run: func(_ context.Context, inv Invocation) error {
			_, err := fmt.Fprintln(inv.Out, "short", inv.Args)
			return err
		}},
		{Name: "conflict", Summary: "refuses", Run: func(context.Context, Invocation) error {
			return fmt.Errorf("a superadmin exists: %w", core.ErrConflict)
		}},
		{Name: "missing", Summary: "finds nothing", Run: func(context.Context, Invocation) error {
			return fmt.Errorf("no such person: %w", core.ErrNotFound)
		}},
		{Name: "usage", Summary: "wants arguments", Run: func(context.Context, Invocation) error {
			return fmt.Errorf("%w: give me --x", ErrUsage)
		}},
		{Name: "broken", Summary: "fails", Run: func(context.Context, Invocation) error { return errors.New("disk full") }},
		{Name: "panic", Summary: "panics", Run: func(context.Context, Invocation) error { panic("boom secret-ish") }},
		{Name: "wait", Summary: "streams, then waits", Run: func(ctx context.Context, inv Invocation) error {
			if _, err := fmt.Fprintln(inv.Out, "open https://example.com/authorize and come back"); err != nil {
				return err
			}
			close(g.started)
			select {
			case <-g.release:
				_, err := fmt.Fprintln(inv.Out, "authorized")
				return err
			case <-ctx.Done():
				return ctx.Err()
			}
		}},
	}
}

// registry returns a registry holding cmds.
func registry(t *testing.T, cmds []Command) *Registry {
	t.Helper()
	r := NewRegistry()
	require.NoError(t, r.Add(cmds...))
	return r
}

// newServer returns a server for path serving cmds.
func newServer(t *testing.T, path string, log *slog.Logger, cmds []Command) *Server {
	t.Helper()
	s, err := New(Options{Path: path, Logger: log, Registry: registry(t, cmds)})
	require.NoError(t, err)
	return s
}

func startServer(t *testing.T, cmds []Command) (*Server, string, *testlog.Recorder) {
	t.Helper()
	log, logs := testlog.New()
	path := filepath.Join(socketDir(t), "app", "admin.sock")
	s := newServer(t, path, log, cmds)
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { _ = s.Stop(context.Background()) })
	return s, path, logs
}

func TestRegistryChecksCommands(t *testing.T) {
	run := func(context.Context, Invocation) error { return nil }
	for _, tc := range []struct {
		name string
		cmds []Command
	}{
		{"upper case", []Command{{Name: "Setup", Run: run}}},
		{"double space", []Command{{Name: "legacy  key", Run: run}}},
		{"trailing space", []Command{{Name: "status ", Run: run}}},
		{"empty", []Command{{Name: "", Run: run}}},
		{"help is the CLI's", []Command{{Name: "help", Run: run}}},
		{"no run", []Command{{Name: "status"}}},
		{"twice", []Command{{Name: "status", Run: run}, {Name: "status", Run: run}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, NewRegistry().Add(tc.cmds...))
		})
	}
	r := NewRegistry()
	require.NoError(t, r.Add(Command{Name: "cloudflare connect", Run: run}, Command{Name: "status", Run: run}))

	// A later Add with a name already taken, or a bad one among good ones, adds nothing.
	require.ErrorContains(t, r.Add(Command{Name: "setup-link", Run: run}, Command{Name: "status", Run: run}), "twice")
	require.Error(t, r.Add(Command{Name: "setup-link", Run: run}, Command{Name: "Bad", Run: run}))
	assert.Equal(t, []CommandInfo{{Name: "cloudflare connect"}, {Name: "status"}}, r.Commands())
	require.NoError(t, r.Add(Command{Name: "setup-link", Summary: "links", Run: run}))
	assert.Len(t, r.Commands(), 3)
	assert.NotNil(t, NewRegistry().Commands(), "an empty list, not null")
}

func TestNewChecksOptions(t *testing.T) {
	_, err := New(Options{})
	require.ErrorContains(t, err, "no socket path")
	_, err = New(Options{Path: "/tmp/" + strings.Repeat("x", 100) + ".sock"})
	require.ErrorContains(t, err, "longer than")
	s, err := New(Options{Path: "/tmp/x.sock"})
	require.NoError(t, err)
	assert.NotNil(t, s.Registry(), "a nil registry is an empty one")
	assert.Empty(t, s.Registry().Commands())
}

// Commands added after Start are served at once: every application and package may register at any time.
func TestCommandsAddedLater(t *testing.T) {
	s, path, _ := startServer(t, nil)
	ctx := context.Background()
	list, err := NewClient(path).Commands(ctx)
	require.NoError(t, err)
	assert.Empty(t, list)
	require.NoError(t, s.Registry().Add(Command{Name: "status", Summary: "says ok", Run: func(_ context.Context, inv Invocation) error {
		_, err := io.WriteString(inv.Out, "ok\n")
		return err
	}}))
	var out bytes.Buffer
	require.NoError(t, NewClient(path).Run(ctx, "status", nil, nil, &out))
	assert.Equal(t, "ok\n", out.String())
}

func TestSocketRoundTrip(t *testing.T) {
	g := newGate()
	_, path, logs := startServer(t, testCommands(g))
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), fi.Mode().Perm(), "socket mode")
	dir, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o700), dir.Mode().Perm(), "a directory the server made is 0700")

	ctx := context.Background()
	c := NewClient(path)
	list, err := c.Commands(ctx)
	require.NoError(t, err)
	var names []string
	for _, ci := range list {
		names = append(names, ci.Name)
	}
	assert.Equal(t, []string{"broken", "conflict", "hello", "legacy-key", "legacy-key import", "missing", "panic", "usage", "wait"}, names)
	assert.True(t, list[4].Stdin)
	assert.Equal(t, "--label <l>", list[4].Usage)

	var out bytes.Buffer
	require.NoError(t, c.Run(ctx, "hello", []string{"Roma", "Bella"}, nil, &out))
	assert.Equal(t, "hello Roma,Bella\n", out.String())

	out.Reset()
	require.NoError(t, c.Run(ctx, "legacy-key import", []string{"--label", "Site"}, []byte("lk_secret_value"), &out))
	assert.Equal(t, "got 15 bytes, args [--label Site]\n", out.String())

	for _, tc := range []struct {
		cmd, code, msg string
		stdin          []byte
	}{
		{"conflict", "conflict", "a superadmin exists: conflict", nil},
		{"missing", "not_found", "no such person: not found", nil},
		{"usage", "invalid", "usage: give me --x", nil},
		{"broken", "failed", "disk full", nil},
		{"panic", "failed", "the command failed unexpectedly", nil},
		{"nope", "not_found", `unknown command "nope"`, nil},
		{"hello", "invalid", "hello reads no standard input", []byte("x")},
		{"legacy-key import", "invalid", "the standard input is over 64 KiB", bytes.Repeat([]byte("k"), MaxStdin+1)},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			err := c.Run(ctx, tc.cmd, nil, tc.stdin, io.Discard)
			re, ok := errors.AsType[*RemoteError](err)
			require.True(t, ok, "%v", err)
			assert.Equal(t, tc.code, re.Code)
			assert.Equal(t, tc.msg, re.Message)
		})
	}

	// The log names commands and results, never their arguments, input or output.
	for _, secret := range []string{"Roma", "lk_secret_value", "hello Roma", "secret-ish", "disk full"} {
		assert.False(t, logs.Contains(secret), secret)
	}
	found := false
	for _, rec := range logs.Records() {
		found = found || rec.Message == "adminsock: command" && rec.Attrs["command"] == "hello" && rec.Attrs["result"] == "done"
	}
	assert.True(t, found, "the command's name and result are logged")
}

// Output reaches the client while the command still runs, so a command can show a URL and wait for the operator.
func TestOutputStreams(t *testing.T) {
	g := newGate()
	_, path, _ := startServer(t, testCommands(g))
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := NewClient(path).Run(context.Background(), "wait", nil, nil, pw)
		_ = pw.CloseWithError(err)
		done <- err
	}()
	<-g.started
	line := make([]byte, 64)
	n, err := pr.Read(line)
	require.NoError(t, err)
	assert.Contains(t, string(line[:n]), "open https://example.com/authorize")
	close(g.release)
	rest, err := io.ReadAll(pr)
	require.NoError(t, err)
	assert.Equal(t, "authorized\n", string(rest))
	require.NoError(t, <-done)
}

// Stop cancels a command that still runs, and removes the socket file.
func TestStopCancelsCommands(t *testing.T) {
	g := newGate()
	s, path, _ := startServer(t, testCommands(g))
	done := make(chan error, 1)
	go func() { done <- NewClient(path).Run(context.Background(), "wait", nil, nil, io.Discard) }()
	<-g.started
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, s.Stop(ctx))
	require.Error(t, <-done)
	_, err := os.Lstat(path)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.NoError(t, s.Stop(ctx), "a second Stop is a no-op")
}

func TestStartGuardsThePath(t *testing.T) {
	ctx := context.Background()
	cmds := testCommands(newGate())

	t.Run("a live socket is refused", func(t *testing.T) {
		_, path, _ := startServer(t, cmds)
		s2 := newServer(t, path, nil, cmds)
		require.ErrorContains(t, s2.Start(ctx), "already answers")
		_, err := NewClient(path).Commands(ctx)
		require.NoError(t, err, "the first server still serves")
	})

	t.Run("a stale socket is replaced", func(t *testing.T) {
		path := filepath.Join(socketDir(t), "admin.sock")
		ln, err := net.Listen("unix", path)
		require.NoError(t, err)
		ln.(*net.UnixListener).SetUnlinkOnClose(false)
		require.NoError(t, ln.Close())
		_, err = os.Lstat(path)
		require.NoError(t, err, "the stale file is there")
		s := newServer(t, path, nil, cmds)
		require.NoError(t, s.Start(ctx))
		defer func() { _ = s.Stop(ctx) }()
		_, err = NewClient(path).Commands(ctx)
		require.NoError(t, err)
	})

	t.Run("a file that is not a socket stays", func(t *testing.T) {
		path := filepath.Join(socketDir(t), "admin.sock")
		require.NoError(t, os.WriteFile(path, []byte("keep me"), 0o600))
		s := newServer(t, path, nil, cmds)
		require.ErrorContains(t, s.Start(ctx), "not a socket")
		b, err := os.ReadFile(filepath.Clean(path))
		require.NoError(t, err)
		assert.Equal(t, "keep me", string(b))
	})

	t.Run("twice", func(t *testing.T) {
		s, _, _ := startServer(t, cmds)
		require.ErrorContains(t, s.Start(ctx), "already started")
	})
}

// A peer of another user is closed before it is served.
func TestPeerListenerRefusesOtherUsers(t *testing.T) {
	path := filepath.Join(socketDir(t), "peer.sock")
	ln, err := net.Listen("unix", path)
	require.NoError(t, err)
	log, logs := testlog.New()
	var mu sync.Mutex
	uid := 4242
	pl := &peerListener{Listener: ln, log: log, uidOf: func(net.Conn) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return uid, nil
	}}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := pl.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()

	stranger, err := net.Dial("unix", path)
	require.NoError(t, err)
	require.NoError(t, stranger.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = stranger.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "the stranger's connection is closed")
	_ = stranger.Close()

	mu.Lock()
	uid = os.Getuid()
	mu.Unlock()
	own, err := net.Dial("unix", path)
	require.NoError(t, err)
	defer func() { _ = own.Close() }()
	c := <-accepted
	require.NotNil(t, c, "the own user's connection is accepted")
	_ = c.Close()
	_ = ln.Close()
	refused := 0
	for _, rec := range logs.Records() {
		if rec.Message == "adminsock: refused a connection from another user" {
			refused++
			assert.Equal(t, "4242", rec.Attrs["uid"])
		}
	}
	require.Equal(t, 1, refused)

	// The real peer check sees this test's own user.
	server, client := unixPair(t)
	got, err := peerUID(server)
	require.NoError(t, err)
	assert.Equal(t, os.Getuid(), got)
	_ = client.Close()
}

func unixPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	path := filepath.Join(socketDir(t), "pair.sock")
	ln, err := net.Listen("unix", path)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	client, err := net.Dial("unix", path)
	require.NoError(t, err)
	server := <-ch
	require.NotNil(t, server)
	t.Cleanup(func() { _ = server.Close() })
	return server, client
}

func TestAllowedUID(t *testing.T) {
	assert.True(t, allowedUID(os.Getuid()))
	assert.True(t, allowedUID(0))
	assert.False(t, allowedUID(-1))
	if os.Getuid() != 4243 {
		assert.False(t, allowedUID(4243))
	}
}

func TestCLI(t *testing.T) {
	g := newGate()
	_, path, _ := startServer(t, testCommands(g))
	ctx := context.Background()
	cli := CLI{Socket: path, Prog: "hub admin", App: "hub", Hint: "Is the hub running? Run this inside its container."}
	run := func(stdin string, args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := cli.Run(ctx, args, strings.NewReader(stdin), &out, &errOut)
		return code, out.String(), errOut.String()
	}

	code, out, errOut := run("", "help")
	assert.Equal(t, ExitOK, code)
	assert.Contains(t, out, "Usage: hub admin <command> [arguments]")
	assert.Contains(t, out, "legacy-key import --label <l> < input")
	assert.Contains(t, out, "greets")
	assert.Empty(t, errOut)

	code, out, errOut = run("")
	assert.Equal(t, ExitUsage, code)
	assert.Empty(t, out)
	assert.Contains(t, errOut, "Commands:")

	code, out, _ = run("", "hello", "Roma")
	assert.Equal(t, ExitOK, code)
	assert.Equal(t, "hello Roma\n", out)

	// The longest name wins, and only commands that read stdin get it.
	code, out, _ = run("lk_123", "legacy-key", "import", "--label", "Site")
	assert.Equal(t, ExitOK, code)
	assert.Equal(t, "got 6 bytes, args [--label Site]\n", out)
	code, out, _ = run("lk_123", "legacy-key", "list")
	assert.Equal(t, ExitOK, code)
	assert.Equal(t, "short [list]\n", out)

	code, _, errOut = run(strings.Repeat("k", MaxStdin+1), "legacy-key", "import")
	assert.Equal(t, ExitUsage, code)
	assert.Contains(t, errOut, "over 64 KiB")

	code, _, errOut = run("", "nope", "x")
	assert.Equal(t, ExitUsage, code)
	assert.Equal(t, "hub admin: unknown command \"nope x\"; `hub admin help` lists them\n", errOut)

	code, _, errOut = run("", "conflict")
	assert.Equal(t, ExitFailed, code)
	assert.Equal(t, "hub admin conflict: a superadmin exists: conflict\n", errOut)

	code, _, errOut = run("", "usage")
	assert.Equal(t, ExitUsage, code)
	assert.Contains(t, errOut, "give me --x")

	var o, e bytes.Buffer
	gone := cli
	gone.Socket = filepath.Join(socketDir(t), "none.sock")
	code = gone.Run(ctx, []string{"hello"}, nil, &o, &e)
	assert.Equal(t, ExitFailed, code)
	assert.Contains(t, e.String(), "hub admin: cannot reach the hub on "+gone.Socket+": Get \"http://hub/v1/commands\": ",
		"the request names the application, as Family Hub's CLI always did")
	assert.True(t, strings.HasSuffix(e.String(), "\nIs the hub running? Run this inside its container.\n"), e.String())

	// The defaults name nothing of any application.
	e.Reset()
	assert.Equal(t, ExitFailed, CLI{Socket: gone.Socket}.Run(ctx, []string{"hello"}, nil, &o, &e))
	assert.Contains(t, e.String(), "admin: cannot reach the server on "+gone.Socket+": Get \"http://admin/v1/commands\": ")
	assert.Equal(t, 1, strings.Count(e.String(), "\n"), "no hint line")
	o.Reset()
	assert.Equal(t, ExitOK, CLI{Socket: path}.Run(ctx, []string{"help"}, nil, &o, &e))
	assert.Contains(t, o.String(), "Usage: admin <command> [arguments]")
}

func TestHandlerRejectsBadRequests(t *testing.T) {
	s := newServer(t, "/tmp/unused.sock", nil, testCommands(newGate()))
	for _, tc := range []struct {
		method, path, body string
		status             int
		code               string
	}{
		{http.MethodPost, "/v1/run", "{", http.StatusBadRequest, "invalid"},
		{http.MethodPost, "/v1/run", `{"command":"hello","args":"x"}`, http.StatusBadRequest, "invalid"},
		{http.MethodPost, "/v1/run", `{"command":"hello","stdin":"!!"}`, http.StatusBadRequest, "invalid"},
		{http.MethodGet, "/v1/other", "", http.StatusNotFound, "not_found"},
		{http.MethodPost, "/v1/commands", "", http.StatusNotFound, "not_found"},
		{http.MethodGet, "/v1/run", "", http.StatusNotFound, "not_found"},
	} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		assert.Equal(t, tc.status, rec.Code, "%s %s %.40s", tc.method, tc.path, tc.body)
		assert.Contains(t, rec.Body.String(), `"error":"`+tc.code+`"`)
		assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	}
	// A body over the cap is refused before anything runs.
	rec := httptest.NewRecorder()
	big := `{"command":"hello","args":["` + strings.Repeat("a", maxRequest) + `"]}`
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/run", strings.NewReader(big)))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// A handler that panics answers 500 internal, and its panic's value never reaches the log.
func TestHandlerPanics(t *testing.T) {
	log, logs := testlog.New()
	s := newServer(t, "/tmp/unused.sock", log, nil)
	rec := httptest.NewRecorder()
	s.recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secret-ish") })).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/commands", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.JSONEq(t, `{"error":"internal","message":"internal error"}`, rec.Body.String())
	assert.False(t, logs.Contains("secret-ish"))
	assert.True(t, logs.Contains("adminsock: a request panicked"))
	assert.Panics(t, func() {
		s.recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })).
			ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}, "an aborted handler stays aborted")
}

// Two packages add their commands to one registry, as auth and an application do; the server serves both from Start
// to Stop.
func TestServerLifecycle(t *testing.T) {
	path := filepath.Join(socketDir(t), "admin.sock")
	reg := NewRegistry()
	require.NoError(t, reg.Add(Command{Name: "status", Summary: "says ok", Run: func(_ context.Context, inv Invocation) error {
		_, err := io.WriteString(inv.Out, "ok\n")
		return err
	}}))
	require.NoError(t, reg.Add(Command{Name: "setup-link", Summary: "links", Run: func(context.Context, Invocation) error { return nil }}))
	s, err := New(Options{Path: path, Registry: reg})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, s.Start(ctx))
	list, err := NewClient(path).Commands(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "setup-link", list[0].Name)
	var out bytes.Buffer
	require.NoError(t, NewClient(path).Run(ctx, "status", nil, nil, &out))
	assert.Equal(t, "ok\n", out.String())
	require.NoError(t, s.Stop(ctx))
	_, err = os.Lstat(path)
	require.ErrorIs(t, err, fs.ErrNotExist)
}

// The client against a server that answers badly: a non-JSON error, a stream that ends without a result, garbage
// frames, and a caller that gives up.
func TestClientAgainstABadServer(t *testing.T) {
	path := filepath.Join(socketDir(t), "bad.sock")
	ln, err := net.Listen("unix", path)
	require.NoError(t, err)
	hold := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/commands", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "<html>bad gateway</html>")
	})
	mux.HandleFunc("POST /v1/run", func(w http.ResponseWriter, r *http.Request) {
		var req runRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/x-ndjson")
		switch req.Command {
		case "cut":
			_, _ = io.WriteString(w, `{"out":"half"}`+"\n")
		case "garbage":
			_, _ = io.WriteString(w, `{"out":"ok"}`+"\n"+`not json`+"\n")
		case "hang":
			_, _ = io.WriteString(w, `{"out":"waiting"}`+"\n")
			w.(http.Flusher).Flush()
			select {
			case <-hold:
			case <-r.Context().Done():
			}
		case "teapot":
			w.WriteHeader(http.StatusTeapot)
			_, _ = io.WriteString(w, `{"error":"invalid","message":"no tea"}`)
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		close(hold)
		_ = srv.Close()
	})

	ctx := context.Background()
	c := NewClient(path)
	_, err = c.Commands(ctx)
	re, ok := errors.AsType[*RemoteError](err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, "internal", re.Code)
	assert.Contains(t, re.Message, "502")

	var out bytes.Buffer
	require.ErrorContains(t, c.Run(ctx, "cut", nil, nil, &out), "without a result")
	assert.Equal(t, "half", out.String())
	require.ErrorContains(t, c.Run(ctx, "garbage", nil, nil, io.Discard), "reading the command's output")
	err = c.Run(ctx, "teapot", nil, nil, io.Discard)
	re, ok = errors.AsType[*RemoteError](err)
	require.True(t, ok)
	assert.Equal(t, "no tea", re.Message)

	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	pr, pw := io.Pipe()
	go func() { done <- c.Run(cctx, "hang", nil, nil, pw) }()
	buf := make([]byte, 16)
	_, err = pr.Read(buf)
	require.NoError(t, err)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	// A writer that fails stops the command's output.
	require.Error(t, c.Run(ctx, "cut", nil, nil, failingWriter{}))
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("terminal closed") }
