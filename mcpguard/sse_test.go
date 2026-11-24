package mcpguard

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSEStateKnowsTheEventBoundaries(t *testing.T) {
	tests := []struct {
		stream   string
		boundary bool
	}{
		{"", true},
		{"data: a", false},
		{"data: a\n", false},
		{"data: a\n\n", true},
		{"data: a\r\n", false},
		{"data: a\r\n\r\n", true},
		{"data: a\r\n\r", true},
		{"data: a\r", false},
		{"data: a\r\r", true},
		{"data: a\n\r\n", true},
		{": comment\n\n", true},
		{"\n", true},
		{"\r\n", true},
		{"data: a\n\ndata: b", false},
		{"data: a\n\ndata: b\nid: 2\n", false},
		{"data: a\n\ndata: b\nid: 2\n\n", true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.boundary, sseBoundary.feed([]byte(tt.stream)).atBoundary(), "%q", tt.stream)
	}
	// Chunk boundaries do not matter.
	whole := "data: a\r\n\r\ndata: b\r\n"
	for cut := range len(whole) {
		s := sseBoundary.feed([]byte(whole[:cut])).feed([]byte(whole[cut:]))
		assert.Equal(t, sseBoundary.feed([]byte(whole)), s, "cut at %d", cut)
	}
}

// fakeTimer is an idleTimer the test fires by hand.
type fakeTimer struct {
	c chan time.Time
}

func (f *fakeTimer) C() <-chan time.Time { return f.c }
func (f *fakeTimer) Reset()              {}
func (f *fakeTimer) Stop()               {}

// recorder is a flushWriter that reports every write.
type recorder struct {
	mu        sync.Mutex
	out       strings.Builder
	flushes   int
	writes    chan string
	fail      error // every write fails with it
	failFlush error // every flush fails with it
}

func newRecorder() *recorder { return &recorder{writes: make(chan string, 64)} }

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return 0, r.fail
	}
	r.out.Write(p)
	r.writes <- string(p)
	return len(p), nil
}

func (r *recorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushes++
	return r.failFlush
}

func (r *recorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.out.String()
}

func TestCopySSEPingsOnlyBetweenEvents(t *testing.T) {
	pr, pw := io.Pipe()
	timer := &fakeTimer{c: make(chan time.Time)}
	w := newRecorder()
	result := make(chan error, 1)
	go func() { result <- copySSE(context.Background(), w, pr, timer) }()

	tick := func() { timer.c <- time.Now() }
	send := func(s string) {
		_, err := pw.Write([]byte(s))
		require.NoError(t, err)
		assert.Equal(t, s, wait(t, w.writes, "the chunk"), "every chunk goes out as it comes")
	}

	tick()
	assert.Equal(t, pingFrame, wait(t, w.writes, "a ping before the first event"))
	send("data: par")
	tick() // inside an event: no ping
	send("t\n\n")
	tick()
	assert.Equal(t, pingFrame, wait(t, w.writes, "a ping after the event"))
	send("data: x\r\n")
	tick() // a field line ended, the event did not
	send("\r")
	tick()
	assert.Equal(t, pingFrame, wait(t, w.writes, "a ping after a CR blank line"))
	require.NoError(t, pw.Close())
	require.NoError(t, wait(t, result, "the end of the stream"))

	assert.Equal(t, pingFrame+"data: part\n\n"+pingFrame+"data: x\r\n\r"+pingFrame, w.String())
	assert.Equal(t, 7, w.flushes, "a flush after every write")
}

func TestCopySSEEnds(t *testing.T) {
	t.Run("with the context", func(t *testing.T) {
		pr, pw := io.Pipe()
		defer pw.Close()
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- copySSE(ctx, newRecorder(), pr, &fakeTimer{c: make(chan time.Time)}) }()
		cancel()
		require.ErrorIs(t, wait(t, result, "copySSE to return"), context.Canceled)
	})

	t.Run("with a read error", func(t *testing.T) {
		pr, pw := io.Pipe()
		boom := errors.New("connection reset")
		result := make(chan error, 1)
		go func() {
			result <- copySSE(context.Background(), newRecorder(), pr, &fakeTimer{c: make(chan time.Time)})
		}()
		require.NoError(t, pw.CloseWithError(boom))
		require.ErrorIs(t, wait(t, result, "copySSE to return"), boom)
	})

	t.Run("with a write error", func(t *testing.T) {
		pr, pw := io.Pipe()
		defer pw.Close()
		w := newRecorder()
		w.fail = errors.New("client gone")
		result := make(chan error, 1)
		go func() { result <- copySSE(context.Background(), w, pr, &fakeTimer{c: make(chan time.Time)}) }()
		go func() { _, _ = pw.Write([]byte("data: a\n\n")) }()
		require.ErrorIs(t, wait(t, result, "copySSE to return"), w.fail)
	})

	t.Run("with a flush error", func(t *testing.T) {
		pr, pw := io.Pipe()
		defer pw.Close()
		w := newRecorder()
		w.failFlush = errors.New("cannot flush")
		timer := &fakeTimer{c: make(chan time.Time)}
		result := make(chan error, 1)
		go func() { result <- copySSE(context.Background(), w, pr, timer) }()
		timer.c <- time.Now()
		require.ErrorIs(t, wait(t, result, "copySSE to return"), w.failFlush)
	})
}

// noFlush is a ResponseWriter that cannot flush.
type noFlush struct{ h http.Header }

func (n noFlush) Header() http.Header       { return n.h }
func (noFlush) Write(p []byte) (int, error) { return len(p), nil }
func (noFlush) WriteHeader(int)             {}

func TestRelayRefusesAWriterThatCannotFlush(t *testing.T) {
	g := newHarness(t, harnessOptions{}).guard
	w := noFlush{h: http.Header{"Content-Type": {"text/event-stream"}}}
	err := g.Relay(t.Context(), w, http.StatusOK, strings.NewReader("data: a\n\n"))
	require.ErrorIs(t, err, http.ErrNotSupported, "its events would never arrive")

	w = noFlush{h: http.Header{"Content-Type": {"application/json"}}}
	require.NoError(t, g.Relay(t.Context(), w, http.StatusOK, strings.NewReader("{}")), "a plain answer needs no flush")
}

// readEvent reads one event (up to a blank line) of an SSE stream.
func readEvent(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		require.NoError(t, err, "read so far %q", b.String())
		if line == "\n" {
			return b.String()
		}
		b.WriteString(line)
	}
}

// sseHandler starts an event stream; the test goes on in body.
func sseHandler(body func(w http.ResponseWriter, f http.Flusher, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		f.Flush()
		body(w, f, r)
	}
}

func TestRelayStreamsEventsAsTheyCome(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	gotFirst := make(chan struct{})
	h.upstream.handle(sseHandler(func(w http.ResponseWriter, f http.Flusher, _ *http.Request) {
		_, _ = io.WriteString(w, "id: 1\ndata: one\n\n")
		f.Flush()
		select {
		case <-gotFirst:
		case <-time.After(failsafe):
			return
		}
		_, _ = io.WriteString(w, "id: 2\ndata: two\n\n")
	}))
	req := h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", strings.NewReader(`{"jsonrpc":"2.0"}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := h.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, []string{"no-cache, no-store"}, resp.Header.Values("Cache-Control"))
	assert.Equal(t, "no", resp.Header.Get("X-Accel-Buffering"))
	assert.Equal(t, guardCSP, resp.Header.Get("Content-Security-Policy"))

	r := bufio.NewReader(resp.Body)
	assert.Equal(t, "id: 1\ndata: one\n", readEvent(t, r), "the first event arrives while the server still streams")
	close(gotFirst)
	assert.Equal(t, "id: 2\ndata: two\n", readEvent(t, r))
	_, err = r.ReadByte()
	require.ErrorIs(t, err, io.EOF)
}

func TestRelayPingsAnIdleStream(t *testing.T) {
	h := newHarness(t, harnessOptions{ping: 10 * time.Millisecond})
	release := make(chan struct{})
	h.upstream.handle(sseHandler(func(w http.ResponseWriter, _ http.Flusher, _ *http.Request) {
		select {
		case <-release:
		case <-time.After(failsafe):
			return
		}
		_, _ = io.WriteString(w, "data: done\n\n")
	}))
	req := h.request(t, http.MethodGet, "/mcp/hello", "Bearer tok-alice", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := h.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	r := bufio.NewReader(resp.Body)
	assert.Equal(t, ": ping\n", readEvent(t, r), "the silent stream gets a ping")
	close(release)
	for {
		ev := readEvent(t, r)
		if ev == ": ping\n" {
			continue // more pings may come before the event
		}
		assert.Equal(t, "data: done\n", ev)
		break
	}
}

func TestRelayPassesTheServersStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"an accepted notification", http.StatusAccepted, ""},
		{"an unknown session", http.StatusNotFound, `{"jsonrpc":"2.0","error":{"code":-32001,"message":"no session"}}`},
		{"a bad request", http.StatusBadRequest, `{"jsonrpc":"2.0","error":{"code":-32600,"message":"bad"}}`},
		{"no SSE stream here", http.StatusMethodNotAllowed, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{})
			h.upstream.handle(func(w http.ResponseWriter, _ *http.Request) {
				if tt.body != "" {
					w.Header().Set("Content-Type", "application/json")
				}
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			})
			a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", strings.NewReader(`{}`)))
			assert.Equal(t, tt.status, a.status)
			assert.Equal(t, tt.body, string(a.body))
			assert.Equal(t, []string{"no-store"}, a.header.Values("Cache-Control"))
		})
	}
}

func TestClientGoneCancelsTheServer(t *testing.T) {
	t.Run("while it streams", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		cancelled := make(chan struct{})
		h.upstream.handle(sseHandler(func(w http.ResponseWriter, f http.Flusher, r *http.Request) {
			_, _ = io.WriteString(w, "data: one\n\n")
			f.Flush()
			<-r.Context().Done()
			close(cancelled)
		}))
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		req := h.request(t, http.MethodGet, "/mcp/hello", "Bearer tok-alice", nil).WithContext(ctx)
		resp, err := h.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, "data: one\n", readEvent(t, bufio.NewReader(resp.Body)))
		cancel()
		wait(t, cancelled, "the server's request to be cancelled")
	})

	t.Run("before it answers", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		arrived, cancelled := make(chan struct{}), make(chan struct{})
		h.upstream.handle(func(_ http.ResponseWriter, r *http.Request) {
			close(arrived)
			<-r.Context().Done()
			close(cancelled)
		})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		req := h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", strings.NewReader(`{}`)).WithContext(ctx)
		errc := make(chan error, 1)
		go func() {
			resp, err := h.client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
			errc <- err
		}()
		wait(t, arrived, "the call to reach the server")
		cancel()
		wait(t, cancelled, "the server's request to be cancelled")
		require.ErrorIs(t, wait(t, errc, "the client to give up"), context.Canceled)
	})
}
