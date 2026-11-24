package httpsec

import "net/http"

// recorder wraps a ResponseWriter to remember the status, the size and whether the answer has started, which the
// request log and the recovery need. It keeps flushing working (server-sent events) and exposes the wrapped writer
// to http.ResponseController through Unwrap.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

// record returns w as a recorder, wrapping it unless it already is one.
func record(w http.ResponseWriter) *recorder {
	if rec, ok := w.(*recorder); ok {
		return rec
	}
	return &recorder{ResponseWriter: w, status: http.StatusOK}
}

func (r *recorder) WriteHeader(code int) {
	// 1xx answers (except 101) are informational: the real answer follows.
	if !r.wrote && (code >= http.StatusOK || code == http.StatusSwitchingProtocols) {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Flush sends what is buffered so far, as http.Flusher says; the headers go out with it.
func (r *recorder) Flush() {
	r.wrote = true
	_ = http.NewResponseController(r.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the real writer (Hijack, deadlines).
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
