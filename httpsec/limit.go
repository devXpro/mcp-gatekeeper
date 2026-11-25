package httpsec

import (
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// MaxBody is the default cap on a request body. An application's own, smaller limit (Family Hub's MCP gateway) stays
// below it, so that limit's own 413 still answers.
const MaxBody = 2 << 20

// BodyReadTimeout is how long a client may take to send a request body (review GK-17). The server has no
// ReadTimeout, which would cut long answers, so without it a body sent a byte at a time holds the connection, and on
// an MCP door the caller's in-flight place, for as long as the client likes.
const BodyReadTimeout = 30 * time.Second

// BodyLimit refuses a declared body above limit at once with 413 {"error":"invalid"} and caps the rest while it is
// read (the reader then fails with *http.MaxBytesError). The client has BodyReadTimeout from the start of the request
// to send the body (BodyDeadline): a read after that fails with an error that wraps os.ErrDeadlineExceeded, which the
// handler answers as it answers any body it cannot read (mcpguard.ReadBody: 408).
func BodyLimit(limit int64) func(http.Handler) http.Handler {
	return bodyLimit(limit, BodyReadTimeout)
}

func bodyLimit(limit int64, timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				WriteError(w, http.StatusRequestEntityTooLarge, CodeInvalid, "request body too large")
				return
			}
			if r.Body != nil && r.Body != http.NoBody {
				r.Body = &deadlineBody{ReadCloser: http.MaxBytesReader(w, r.Body, limit), lift: BodyDeadline(w, timeout)}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BodyDeadline gives the client of w until d from now to send the rest of its request body: a read after that fails
// with an error that wraps os.ErrDeadlineExceeded. The handler calls lift once it has read the whole body, and only
// then: on HTTP/1.1 the deadline is the connection's, and one still set when it passes would end the request's context
// in the middle of a long answer (an event stream); left in place after a failed read, it lets the server give up on
// the rest of the body at once instead of waiting for it. A writer that cannot set deadlines (a test recorder) gets
// none, and lift does nothing.
func BodyDeadline(w http.ResponseWriter, d time.Duration) (lift func()) {
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(d)); err != nil {
		return func() {}
	}
	return sync.OnceFunc(func() { _ = rc.SetReadDeadline(time.Time{}) })
}

// deadlineBody lifts the body's read deadline when the body has been read to its end.
type deadlineBody struct {
	io.ReadCloser
	lift func()
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		b.lift()
	}
	return n, err
}
