package cloudflare

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/internal/testlog"
)

// syncBuffer is a Log writer the test can read while the supervisor writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// backoffHook replaces the supervisor's wait between restarts: it reports every delay on delays and then either
// returns at once (free) or waits for the test to send on gate.
type backoffHook struct {
	delays chan time.Duration
	gate   chan time.Time
	free   atomic.Bool
}

func newBackoffHook() *backoffHook {
	return &backoffHook{delays: make(chan time.Duration, 64), gate: make(chan time.Time)}
}

func (h *backoffHook) after(d time.Duration) <-chan time.Time {
	h.delays <- d
	if h.free.Load() {
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}
	return h.gate
}

// testSup is a supervisor over the fake cloudflared, with everything the tests watch.
type testSup struct {
	*Supervisor
	fake *fakeBin
	dir  string
	log  *syncBuffer
	logs *testlog.Recorder // the supervisor's own lines
	urls chan string
	hook *backoffHook
}

// newTestSup builds a supervisor; for Named it first runs the connect flow against the fake, so the directory holds a
// real config.yml, tunnel.json and credentials.
func newTestSup(t *testing.T, mode Mode, tune func(*SupervisorOptions)) *testSup {
	t.Helper()
	f := newFakeBin(t)
	ts := &testSup{fake: f, log: &syncBuffer{}, urls: make(chan string, 16), hook: newBackoffHook()}
	if mode == Named {
		f.set("login-release")
		c := newFakeConnector(t, f)
		_, err := c.Connect(t.Context(), ConnectOptions{Hostname: "home.example.com"}, &bytes.Buffer{})
		require.NoError(t, err)
		ts.dir = c.Dir()
		f.unset("login-release")
	}
	var logger *slog.Logger
	logger, ts.logs = testlog.New()
	o := SupervisorOptions{Mode: mode, Binary: f.Bin, Dir: ts.dir, Log: ts.log, Logger: logger,
		OnURL: func(u string) { ts.urls <- u }}
	if mode == Quick {
		o.Dir, o.Service = filepath.Join(t.TempDir(), "tunnel"), "http://127.0.0.1:8080"
		ts.dir = o.Dir
	}
	if tune != nil {
		tune(&o)
	}
	ts.dir = o.Dir
	s, err := NewSupervisor(o)
	require.NoError(t, err)
	s.after, s.poll, s.probeGap = ts.hook.after, 5*time.Millisecond, time.Millisecond
	ts.Supervisor = s
	t.Cleanup(s.Stop)
	return ts
}

func (ts *testSup) start(t *testing.T) {
	t.Helper()
	require.NoError(t, ts.Start(t.Context()))
}

func (ts *testSup) waitState(t *testing.T, want State) Status {
	t.Helper()
	eventually(t, "state "+string(want), func() bool { return ts.Status().State == want })
	return ts.Status()
}

// waitLogged waits for a line of the supervisor's own with this message and these attributes (key, value pairs).
func (ts *testSup) waitLogged(t *testing.T, msg string, attrs ...string) {
	t.Helper()
	eventually(t, "the log line "+msg, func() bool {
		for _, rec := range ts.logs.Records() {
			ok := rec.Message == msg
			for i := 0; ok && i+1 < len(attrs); i += 2 {
				ok = rec.Attrs[attrs[i]] == attrs[i+1]
			}
			if ok {
				return true
			}
		}
		return false
	})
}

func (ts *testSup) waitRuns(t *testing.T, n int) []fakeRun {
	t.Helper()
	eventually(t, "runs", func() bool { return len(ts.fake.runs()) >= n })
	return ts.fake.runs()
}

func TestSupervisorNamed(t *testing.T) {
	ts := newTestSup(t, Named, nil)
	t.Setenv("CF_TEST_CANARY", "canary-secret") // the test process has a secret; the child must not see it
	assert.Equal(t, StateStopped, ts.Status().State)
	ts.start(t)
	st := ts.waitState(t, StateConnected)
	assert.Equal(t, "https://home.example.com", st.URL)
	assert.Empty(t, st.LastError)

	runs := ts.fake.runs()
	require.Len(t, runs, 1)
	r := runs[0]
	assert.Equal(t, []string{"tunnel", "--no-autoupdate", "--config", filepath.Join(ts.dir, ConfigFile), "run"}, r.Args)

	// The environment is HOME and PATH, nothing else; HOME is the private empty directory.
	home := filepath.Join(ts.dir, "home")
	assert.Equal(t, home, r.env("HOME"))
	assert.Equal(t, filepath.Dir(ts.fake.Bin), r.env("PATH"))
	assert.Len(t, r.Env, 2)
	assert.Zero(t, r.HomeEntries)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o700), mode(t, home))
	}

	// No secret in argv: not the tunnel's secret, not the process's own.
	creds, err := os.ReadFile(filepath.Join(ts.dir, CredentialsFile))
	require.NoError(t, err)
	assert.Contains(t, string(creds), "c2VjcmV0")
	for _, a := range r.Args {
		assert.NotContains(t, a, "c2VjcmV0")
		assert.NotContains(t, a, "canary-secret")
		assert.NotContains(t, strings.ToLower(a), "token")
	}
	assert.NotContains(t, strings.Join(r.Env, "\n"), "canary-secret")

	assert.Eventually(t, func() bool { return strings.Contains(ts.log.String(), "Registered tunnel connection") },
		5*time.Second, 5*time.Millisecond, "the child's output reaches the application's log")
	assert.Empty(t, ts.urls, "OnURL is for quick hostnames")

	ts.Stop()
	assert.Equal(t, StateStopped, ts.Status().State)
	assert.Empty(t, ts.Status().URL)
	ts.Stop() // twice is fine
	if runtime.GOOS != "windows" {
		p, err := os.FindProcess(r.Pid)
		require.NoError(t, err)
		require.Error(t, p.Signal(syscall.Signal(0)), "the child is gone after Stop")
	}
}

func TestSupervisorRestartsADeadChild(t *testing.T) {
	ts := newTestSup(t, Named, nil)
	ts.start(t)
	ts.waitState(t, StateConnected)

	ts.fake.set("die")
	st := ts.waitState(t, StateFailing)
	assert.Contains(t, st.LastError, "exit status 1")
	assert.Contains(t, st.LastError, "the test killed it", "the child's last line explains the exit")
	assert.Equal(t, "https://home.example.com", st.URL, "a named tunnel keeps its address")
	assert.Equal(t, time.Second, <-ts.hook.delays)

	// A user's own config in the private HOME is gone at the next start.
	home := filepath.Join(ts.dir, "home")
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".cloudflared"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".cloudflared", "config.yml"), []byte("url: x\n"), 0o600))

	ts.hook.gate <- time.Time{}
	st = ts.waitState(t, StateConnected)
	assert.Empty(t, st.LastError)
	runs := ts.waitRuns(t, 2)
	assert.Zero(t, runs[1].HomeEntries)
}

func TestSupervisorBackoff(t *testing.T) {
	var now atomic.Int64
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ts := newTestSup(t, Named, func(o *SupervisorOptions) {
		o.Clock = func() time.Time { return base.Add(time.Duration(now.Load())) }
	})
	ts.fake.set("exit-now")
	ts.start(t)

	// 1 s, doubling, capped at 60 s.
	for _, want := range []time.Duration{1, 2, 4, 8, 16, 32, 60, 60} {
		assert.Equal(t, want*time.Second, <-ts.hook.delays)
		ts.hook.gate <- time.Time{}
	}
	assert.Equal(t, 60*time.Second, <-ts.hook.delays)
	ts.fake.unset("exit-now")
	ts.hook.gate <- time.Time{}
	ts.waitState(t, StateConnected)

	// A child that stayed up for a while starts the backoff over.
	now.Add(int64(5 * time.Minute))
	ts.fake.set("die")
	assert.Equal(t, time.Second, <-ts.hook.delays)
	ts.hook.gate <- time.Time{}
	ts.waitState(t, StateConnected)

	// One that died young keeps the long delay.
	ts.fake.set("exit-now")
	ts.fake.set("die")
	assert.Equal(t, 2*time.Second, <-ts.hook.delays)
}

func TestSupervisorProbe(t *testing.T) {
	type call struct{ url string }
	calls := make(chan call)
	var n atomic.Int32
	ts := newTestSup(t, Named, func(o *SupervisorOptions) {
		o.Probe = func(_ context.Context, url string) error {
			calls <- call{url}
			if n.Add(1) < 3 {
				return errors.New("not yet")
			}
			return nil
		}
	})
	ts.start(t)

	assert.Equal(t, call{"https://home.example.com"}, <-calls)
	st := ts.Status()
	assert.Equal(t, StateProbing, st.State)
	assert.Equal(t, "https://home.example.com", st.URL)
	<-calls
	assert.Equal(t, StateProbing, ts.Status().State)
	assert.Contains(t, ts.Status().LastError, "not yet")
	<-calls
	st = ts.waitState(t, StateConnected)
	assert.Empty(t, st.LastError)
}

// The hostname comes from cloudflared's output, and the metrics server confirms it (review R-6).
func TestSupervisorQuickReadsTheHostnameFromTheOutput(t *testing.T) {
	ts := newTestSup(t, Quick, nil)
	ts.start(t)

	assert.Equal(t, "https://example-1.trycloudflare.com", <-ts.urls)
	st := ts.waitState(t, StateConnected)
	assert.Equal(t, "https://example-1.trycloudflare.com", st.URL)
	ts.waitLogged(t, "cloudflared's metrics server confirms the quick tunnel's hostname", "url",
		"https://example-1.trycloudflare.com")

	r := ts.fake.runs()[0]
	require.Len(t, r.Args, 6)
	assert.Equal(t, []string{"tunnel", "--no-autoupdate", "--metrics"}, r.Args[:3])
	assert.Regexp(t, `^127\.0\.0\.1:[1-9][0-9]*$`, r.Args[3])
	assert.Equal(t, []string{"--url", "http://127.0.0.1:8080"}, r.Args[4:])
	assert.Equal(t, filepath.Join(ts.dir, "home"), r.env("HOME"), "no ~/.cloudflared of the user can reach a quick tunnel")
	assert.Len(t, r.Env, 2)

	// A restart makes a new hostname: the status shows none while the child is down, OnURL fires again.
	ts.fake.set("die")
	st = ts.waitState(t, StateFailing)
	assert.Empty(t, st.URL)
	assert.Equal(t, time.Second, <-ts.hook.delays)
	ts.hook.gate <- time.Time{}
	assert.Equal(t, "https://example-2.trycloudflare.com", <-ts.urls)
	st = ts.waitState(t, StateConnected)
	assert.Equal(t, "https://example-2.trycloudflare.com", st.URL)
	assert.Empty(t, st.LastError)
	assert.Empty(t, ts.urls)
	ts.waitLogged(t, "cloudflared's metrics server confirms the quick tunnel's hostname", "url",
		"https://example-2.trycloudflare.com")
}

// Without a metrics server the output alone is enough; the confirmation gives up and says so.
func TestSupervisorQuickWithoutMetrics(t *testing.T) {
	ts := newTestSup(t, Quick, nil)
	ts.fake.set("no-metrics")
	ts.start(t)
	// The log also names api.trycloudflare.com; it is not the tunnel.
	assert.Equal(t, "https://example-1.trycloudflare.com", <-ts.urls)
	assert.Equal(t, "https://example-1.trycloudflare.com", ts.waitState(t, StateConnected).URL)
	assert.Contains(t, ts.log.String(), "https://api.trycloudflare.com/tunnel", "the output is logged whole")
	ts.waitLogged(t, "cloudflared's metrics server did not confirm the quick tunnel's hostname")
	assert.Empty(t, ts.urls, "one hostname per run is announced once")
}

// Another program holds the metrics port and answers with its own quick tunnel (review R-6): its host is never
// published, the one cloudflared printed is, and the mismatch is logged.
func TestSupervisorQuickIgnoresAnotherProgramOnTheMetricsPort(t *testing.T) {
	other := quickTunnelServer(t, "other.trycloudflare.com")
	ts := newTestSup(t, Quick, func(o *SupervisorOptions) { o.MetricsAddr = other.addr })
	ts.fake.set("no-metrics") // the fake finds the port taken and serves no metrics of its own
	ts.start(t)

	assert.Equal(t, "https://example-1.trycloudflare.com", <-ts.urls)
	ts.waitLogged(t, "the metrics port names another quick tunnel than cloudflared's output; ignored, another program "+
		"may hold the port", "url", "https://example-1.trycloudflare.com", "metrics_url", "https://other.trycloudflare.com")
	assert.Equal(t, "https://example-1.trycloudflare.com", ts.waitState(t, StateConnected).URL)
	assert.Positive(t, other.hits.Load())
	assert.Empty(t, ts.urls, "the other program's host is never announced")
}

// A hostname that only the metrics port names is never published: OnURL does not fire and the tunnel stays starting
// (review R-6).
func TestSupervisorQuickNeedsTheOutput(t *testing.T) {
	ts := newTestSup(t, Quick, nil)
	ts.fake.set("no-log-url")
	ts.start(t)

	addr := ts.waitRuns(t, 1)[0].Args[3]
	eventually(t, "the fake's metrics server", func() bool {
		u, ok := readQuickHostname(t.Context(), &http.Client{Timeout: time.Second}, addr)
		return ok && u == "https://example-1.trycloudflare.com"
	})
	assert.Never(t, func() bool { return len(ts.urls) > 0 || ts.Status().URL != "" }, 200*time.Millisecond,
		10*time.Millisecond, "a host only the metrics port claims is not published")
	assert.Equal(t, StateStarting, ts.Status().State)
}

// fakeMetrics is a /quicktunnel server of another program, on loopback.
type fakeMetrics struct {
	addr string
	hits atomic.Int64
}

func quickTunnelServer(t *testing.T, host string) *fakeMetrics {
	t.Helper()
	m := &fakeMetrics{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/quicktunnel" {
			http.NotFound(w, r)
			return
		}
		m.hits.Add(1)
		_, _ = fmt.Fprintf(w, `{"hostname":%q}`, host)
	}))
	t.Cleanup(srv.Close)
	m.addr = srv.Listener.Addr().String()
	return m
}

func TestSupervisorQuickProbe(t *testing.T) {
	var urls []string
	var mu sync.Mutex
	ts := newTestSup(t, Quick, func(o *SupervisorOptions) {
		o.Probe = func(_ context.Context, url string) error {
			mu.Lock()
			defer mu.Unlock()
			urls = append(urls, url)
			return nil
		}
	})
	ts.start(t)
	ts.waitState(t, StateConnected)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"https://example-1.trycloudflare.com"}, urls)
}

func TestSupervisorSinceUsesTheClock(t *testing.T) {
	var now atomic.Int64
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ts := newTestSup(t, Named, func(o *SupervisorOptions) {
		o.Clock = func() time.Time { return base.Add(time.Duration(now.Add(int64(time.Second)))) }
	})
	before := ts.Status().Since
	ts.start(t)
	st := ts.waitState(t, StateConnected)
	assert.True(t, st.Since.After(before))
	assert.Equal(t, time.UTC, st.Since.Location())
}

func TestSupervisorStopsWithItsContext(t *testing.T) {
	ts := newTestSup(t, Named, nil)
	ctx, cancel := context.WithCancel(t.Context())
	require.NoError(t, ts.Start(ctx))
	ts.waitState(t, StateConnected)
	cancel()
	ts.waitState(t, StateStopped)
	ts.Stop()
}

func TestSupervisorStartFails(t *testing.T) {
	// No cloudflared.
	ts := newTestSup(t, Named, func(o *SupervisorOptions) { o.Binary = "no-such-cloudflared-binary" })
	require.ErrorContains(t, ts.Start(t.Context()), "not installed")

	// A directory nothing was connected in.
	ts = newTestSup(t, Named, func(o *SupervisorOptions) { o.Dir = t.TempDir() })
	require.ErrorContains(t, ts.Start(t.Context()), "connect a domain first")
	require.NoError(t, os.WriteFile(filepath.Join(ts.dir, ConfigFile), []byte("x"), 0o600))
	require.ErrorContains(t, ts.Start(t.Context()), "connect a domain first")
	assert.Equal(t, StateStopped, ts.Status().State)

	// Twice.
	ts = newTestSup(t, Named, nil)
	ts.start(t)
	require.ErrorContains(t, ts.Start(t.Context()), "already started")
}

func TestNewSupervisorValidates(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		o    SupervisorOptions
		want string
	}{
		{name: "no mode", o: SupervisorOptions{Dir: dir}, want: "Mode"},
		{name: "no dir", o: SupervisorOptions{Mode: Named}, want: "Dir"},
		{name: "quick without a service", o: SupervisorOptions{Mode: Quick, Dir: dir}, want: "Service"},
		{name: "service on two lines", o: SupervisorOptions{Mode: Quick, Dir: dir, Service: "http://a\nb"}, want: "Service"},
		{name: "public metrics", o: SupervisorOptions{Mode: Quick, Dir: dir, Service: "http://a:1", MetricsAddr: "0.0.0.0:0"}, want: "loopback"},
		{name: "metrics host name", o: SupervisorOptions{Mode: Quick, Dir: dir, Service: "http://a:1", MetricsAddr: "example.com:1"}, want: "loopback"},
		{name: "metrics without a port", o: SupervisorOptions{Mode: Quick, Dir: dir, Service: "http://a:1", MetricsAddr: "127.0.0.1"}, want: "host:port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSupervisor(tt.o)
			require.ErrorContains(t, err, tt.want)
		})
	}
	s, err := NewSupervisor(SupervisorOptions{Mode: Quick, Dir: dir, Service: "http://127.0.0.1:8080", MetricsAddr: "127.0.0.1:20241"})
	require.NoError(t, err)
	assert.Equal(t, "cloudflared", s.o.Binary)
}

func TestQuickURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"example.trycloudflare.com", "https://example.trycloudflare.com"},
		{"  Example-One-Two.trycloudflare.com\n", "https://example-one-two.trycloudflare.com"},
		{"https://example.trycloudflare.com", "https://example.trycloudflare.com"},
		{"api.trycloudflare.com", ""},
		{"trycloudflare.com", ""},
		{"example.trycloudflare.com.evil.example", ""},
		{"evil.example", ""},
		{"example.trycloudflare.com/path", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got, ok := quickURL(tt.in)
		assert.Equal(t, tt.want != "", ok, tt.in)
		assert.Equal(t, tt.want, got, tt.in)
	}
}

func TestMetricsAddr(t *testing.T) {
	a, err := metricsAddr("")
	require.NoError(t, err)
	b, err := metricsAddr("127.0.0.1:0")
	require.NoError(t, err)
	assert.Regexp(t, `^127\.0\.0\.1:[1-9][0-9]*$`, a)
	assert.Regexp(t, `^127\.0\.0\.1:[1-9][0-9]*$`, b)
	fixed, err := metricsAddr("127.0.0.1:20241")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:20241", fixed)
}

// A cloudflared that never prints "Registered tunnel connection" still connects through the probe.
func TestSupervisorNamedProbeDoesNotWaitForTheLog(t *testing.T) {
	var n atomic.Int32
	ts := newTestSup(t, Named, func(o *SupervisorOptions) {
		o.Probe = func(_ context.Context, url string) error {
			if url != "https://home.example.com" {
				return errors.New("wrong url " + url)
			}
			if n.Add(1) < 2 {
				return errors.New("not yet")
			}
			return nil
		}
	})
	ts.fake.set("no-register")
	ts.start(t)
	st := ts.waitState(t, StateConnected)
	assert.Equal(t, "https://home.example.com", st.URL)
	assert.Empty(t, st.LastError)
	assert.NotContains(t, ts.log.String(), "Registered tunnel connection")
	assert.GreaterOrEqual(t, int(n.Load()), 2)
}

// Without a probe, a child that stays up for the grace period is connected even when its log is silent.
func TestSupervisorNamedWithoutProbeConnectsAfterAGrace(t *testing.T) {
	ts := newTestSup(t, Named, nil)
	ts.namedGrace = 20 * time.Millisecond
	ts.fake.set("no-register")
	ts.start(t)
	assert.Equal(t, StateConnected, ts.waitState(t, StateConnected).State)

	// A child that dies inside the grace period never counts as connected.
	ts2 := newTestSup(t, Named, nil)
	ts2.namedGrace = time.Hour
	ts2.fake.set("no-register")
	ts2.fake.set("exit-now")
	ts2.start(t)
	ts2.waitState(t, StateFailing)
	assert.NotEqual(t, StateConnected, ts2.Status().State)
}
