package mcpguard

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"
)

// pingFrame is what Relay writes into an idle event stream: a comment line and a blank line, which every SSE parser
// skips.
const pingFrame = ": ping\n\n"

// Relay sends an MCP server's answer to the assistant: status, then body as it comes. The caller has put the headers
// that pass on w already (ResponseHeaders). An event stream (Content-Type text/event-stream) gets Cache-Control
// "no-cache, no-store" and X-Accel-Buffering "no", its status and headers go out at once, every chunk is flushed as
// it arrives, and a stream that stays silent for the ping interval between two events gets ": ping" (Cloudflare cuts
// an answer that sends nothing for 100 s). Relay returns at the end of body (nil), on a read or write error, or, for
// an event stream, when ctx ends; ctx is the assistant's request's, so the caller tells a client that went away by
// ctx.Err(). The caller closes body.
func (g *Guard) Relay(ctx context.Context, w http.ResponseWriter, status int, body io.Reader) error {
	h := w.Header()
	if !isEventStream(h.Get("Content-Type")) {
		w.WriteHeader(status)
		_, err := io.Copy(w, body)
		return err
	}
	h.Set("Cache-Control", "no-cache, no-store")
	h.Set("X-Accel-Buffering", "no") // a reverse proxy in front of the application must not hold events back
	w.WriteHeader(status)
	fw := responseFlusher{w: w, rc: http.NewResponseController(w)}
	if err := fw.Flush(); err != nil { // the status and the headers go out at once
		return err
	}
	return copySSE(ctx, fw, body, newIdleTimer(g.ping))
}

func isEventStream(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "text/event-stream"
}

// flushWriter is where an event stream goes.
type flushWriter interface {
	io.Writer
	Flush() error
}

// responseFlusher flushes an http.ResponseWriter through its ResponseController, which finds the Flush of a wrapped
// writer too (Gin's, a request logger's). A writer that cannot flush is an error: its events would never arrive.
type responseFlusher struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (f responseFlusher) Write(p []byte) (int, error) { return f.w.Write(p) }
func (f responseFlusher) Flush() error                { return f.rc.Flush() }

// idleTimer fires when an event stream has been silent for the ping interval; tests drive a fake one.
type idleTimer interface {
	C() <-chan time.Time
	Reset() // the stream just carried bytes: start the interval again
	Stop()
}

type realTimer struct {
	t *time.Timer
	d time.Duration
}

func newIdleTimer(d time.Duration) idleTimer { return &realTimer{t: time.NewTimer(d), d: d} }

func (r *realTimer) C() <-chan time.Time { return r.t.C }
func (r *realTimer) Reset()              { r.t.Reset(r.d) }
func (r *realTimer) Stop()               { r.t.Stop() }

// copySSE copies an event stream to the client as it comes, flushing every chunk at once. When the stream stands
// between two events and stays silent until idle fires, it writes pingFrame. Inside an event it never writes, as a
// comment there would change the event. It returns at the end of the stream (nil), on a read, write or flush error,
// or when ctx ends.
func copySSE(ctx context.Context, w flushWriter, body io.Reader, idle idleTimer) error {
	defer idle.Stop()
	chunks := make(chan chunk)
	next := make(chan struct{})
	done := make(chan struct{})
	defer close(done)
	go readChunks(body, chunks, next, done)

	state := sseBoundary
	for {
		select {
		case ch := <-chunks:
			if len(ch.data) > 0 {
				if _, err := w.Write(ch.data); err != nil {
					return err
				}
				if err := w.Flush(); err != nil {
					return err
				}
				state = state.feed(ch.data)
				idle.Reset()
			}
			if ch.err != nil {
				if errors.Is(ch.err, io.EOF) {
					return nil
				}
				return ch.err
			}
			next <- struct{}{}
		case <-idle.C():
			if state.atBoundary() {
				if _, err := io.WriteString(w, pingFrame); err != nil {
					return err
				}
				if err := w.Flush(); err != nil {
					return err
				}
				state = sseBoundary
			}
			idle.Reset()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

type chunk struct {
	data []byte
	err  error
}

// readChunks reads r into out one chunk at a time, and waits on next before it reuses its buffer, until r ends or
// done closes. Closing r is what ends a pending read.
func readChunks(r io.Reader, out chan<- chunk, next, done <-chan struct{}) {
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		select {
		case out <- chunk{data: buf[:n], err: err}:
		case <-done:
			return
		}
		if err != nil {
			return
		}
		select {
		case <-next:
		case <-done:
			return
		}
	}
}

// sseState follows an event stream byte by byte, only to tell whether it stands between two events, the one place
// where a comment changes no event. A line ends with CRLF, LF or CR (the WHATWG rules for server-sent events).
type sseState uint8

const (
	sseBoundary   sseState = iota // nothing yet, or a blank line just ended: between two events
	sseBoundaryCR                 // as sseBoundary, after a CR that an LF may still complete
	sseLineEnd                    // a field line just ended: inside an event
	sseLineEndCR                  // as sseLineEnd, after a CR that an LF may still complete
	sseInLine                     // inside a line
)

func (s sseState) atBoundary() bool { return s == sseBoundary || s == sseBoundaryCR }

func (s sseState) feed(p []byte) sseState {
	for _, b := range p {
		s = s.next(b)
	}
	return s
}

func (s sseState) next(b byte) sseState {
	switch b {
	case '\n':
		switch s {
		case sseInLine, sseLineEndCR: // a field line ends, or the LF of its CRLF
			return sseLineEnd
		default: // a blank line ends, or the LF of its CRLF
			return sseBoundary
		}
	case '\r':
		if s == sseInLine {
			return sseLineEndCR
		}
		return sseBoundaryCR // after a line end, a CR ends a blank line
	default:
		return sseInLine
	}
}
