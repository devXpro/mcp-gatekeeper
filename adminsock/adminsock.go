// Package adminsock is an application's admin socket: its operator commands (Family Hub's `hub admin …`) run inside
// the application process and are reached over a unix socket. Packages and the application add commands to one
// Registry; a Server serves them while the application runs, and CLI is the client side for the application's
// command line.
//
// # The registry
//
// A Registry holds the commands by name. Any package adds its own with Registry.Add — package auth adds setup-link
// and reset-access when auth.Options.Admin is set, and an application adds its own (Family Hub: status, legacy keys,
// cloudflare connect, …):
//
//	reg := adminsock.NewRegistry()
//	a, err := auth.New(auth.Options{…, Admin: reg})              // setup-link, reset-access
//	err = reg.Add(adminsock.Command{Name: "status", Summary: "…", Run: status})
//	srv, err := adminsock.New(adminsock.Options{Path: "data/admin.sock", Logger: log, Registry: reg})
//	err = srv.Start(ctx); defer srv.Stop(ctx)
//
// A name is one or more lower-case words ("setup-link", "legacy-key import"); "help" belongs to the CLI. Add refuses
// a bad or repeated name, or a command without Run, and then adds none of the commands it was given. Commands may be
// added before or after Start: the server looks them up per request.
//
// # Who may use it
//
// The socket file is 0600 and the server also checks the peer's uid (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS;
// other platforms refuse every peer): only the application's own user and root get in, so a mode slip alone does not
// open it to others. Whoever gets in is the server operator: commands need no passkey, no session and no step-up.
//
// # The wire
//
// HTTP/1.1 over the socket:
//
//	GET  /v1/commands  → 200 [{"name","usage","summary","stdin"}]
//	POST /v1/run {"command","args","stdin"}
//	                   → 200 application/x-ndjson: one {"out":"…"} frame per write of the command, then a final
//	                     {"done":true} or {"error":"<code>","message":"…"} frame;
//	                     400 or 404 {"error":"<code>","message":"…"} when it cannot start
//
// Output streams while the command runs, so a command can print a URL and wait for the operator (Family Hub's
// `cloudflare connect`). It goes to the operator's terminal only: the server never logs a command's arguments,
// standard input or output, only its name, its result code and how long it took.
package adminsock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

const (
	// MaxStdin caps the standard input the CLI sends along for a command that reads it.
	MaxStdin = 64 << 10
	// maxRequest caps a run request: the arguments plus the standard input in base64.
	maxRequest = 1 << 20
	// maxSocketPath is the longest socket path every platform takes: sun_path holds 104 bytes on macOS (108 on Linux),
	// the terminating NUL included.
	maxSocketPath = 103
)

// ErrUsage marks a command error the operator caused: wrong arguments. The CLI then exits with 2.
var ErrUsage = errors.New("usage")

// Command is one admin command.
type Command struct {
	// Name is one or more lower-case words, e.g. "setup-link" or "legacy-key import".
	Name string
	// Usage shows the arguments after the name, e.g. "--module <id> --person <id> --label <label>".
	Usage string
	// Summary is one line for the CLI's help.
	Summary string
	// Stdin makes the CLI read its standard input (at most MaxStdin bytes) and send it along.
	Stdin bool
	// Run does the work. What it writes to inv.Out reaches the operator's terminal as it is written. An error ends
	// the command with its text as the message; errors wrapping ErrUsage, core.ErrConflict or core.ErrNotFound get
	// the codes invalid, conflict and not_found. Error texts are shown, never logged: keep secrets out of them anyway.
	Run func(ctx context.Context, inv Invocation) error
}

// Invocation is one run of a command.
type Invocation struct {
	Args  []string  // the words after the command name; never nil
	Stdin []byte    // the CLI's standard input when Command.Stdin is set, else nil
	Out   io.Writer // the operator's terminal; nothing written here is logged
}

// CommandInfo describes a command to the CLI.
type CommandInfo struct {
	Name    string `json:"name"`
	Usage   string `json:"usage,omitempty"`
	Summary string `json:"summary"`
	Stdin   bool   `json:"stdin,omitempty"`
}

var commandName = regexp.MustCompile(`^[a-z][a-z0-9-]*( [a-z][a-z0-9-]*)*$`)

// Registry is the set of commands a Server serves. It is safe for concurrent use.
type Registry struct {
	mu   sync.RWMutex
	cmds map[string]Command
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{cmds: map[string]Command{}} }

// Add checks the commands (names of lower-case words, unique here and among the registered ones, none called "help",
// a Run each) and registers them, all or none.
func (r *Registry) Add(cmds ...Command) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[string]bool, len(cmds))
	for _, c := range cmds {
		switch {
		case !commandName.MatchString(c.Name):
			return fmt.Errorf("adminsock: command name %q is not lower-case words", c.Name)
		case c.Name == "help":
			return errors.New(`adminsock: "help" is the CLI's own command`)
		case c.Run == nil:
			return fmt.Errorf("adminsock: command %q has no Run", c.Name)
		}
		if _, dup := r.cmds[c.Name]; dup || seen[c.Name] {
			return fmt.Errorf("adminsock: command %q is registered twice", c.Name)
		}
		seen[c.Name] = true
	}
	for _, c := range cmds {
		r.cmds[c.Name] = c
	}
	return nil
}

// Commands lists the registered commands, sorted by name; never nil.
func (r *Registry) Commands() []CommandInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]CommandInfo, 0, len(r.cmds))
	for _, c := range r.cmds {
		list = append(list, CommandInfo{Name: c.Name, Usage: c.Usage, Summary: c.Summary, Stdin: c.Stdin})
	}
	slices.SortFunc(list, func(a, b CommandInfo) int { return strings.Compare(a.Name, b.Name) })
	return list
}

func (r *Registry) lookup(name string) (Command, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.cmds[name]
	return c, ok
}

// Options is what New needs.
type Options struct {
	// Path is the socket file, at most 103 bytes (macOS's sun_path). Its directory is made 0700 when missing.
	Path string
	// Logger gets the server's own lines; nil discards.
	Logger *slog.Logger
	// Registry holds the commands; nil serves an empty one (Server.Registry returns it).
	Registry *Registry
}

// Server serves a registry's commands on the socket.
type Server struct {
	path    string
	log     *slog.Logger
	reg     *Registry
	handler http.Handler

	mu     sync.Mutex
	srv    *http.Server
	cancel context.CancelFunc // cancels the running commands at Stop
	done   chan struct{}      // closed when Serve returned
}

// New checks the options and returns a server for the socket at o.Path. Start listens.
func New(o Options) (*Server, error) {
	if o.Path == "" {
		return nil, errors.New("adminsock: no socket path")
	}
	if len(o.Path) > maxSocketPath {
		return nil, fmt.Errorf("adminsock: socket path %s is longer than %d bytes", o.Path, maxSocketPath)
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	reg := o.Registry
	if reg == nil {
		reg = NewRegistry()
	}
	s := &Server{path: o.Path, log: log, reg: reg}
	s.handler = s.routes()
	return s, nil
}

// Registry is the registry the server serves.
func (s *Server) Registry() *Registry { return s.reg }

// Handler serves the wire protocol; Start serves it on the socket. Tests use it directly.
func (s *Server) Handler() http.Handler { return s.handler }

// Start listens on the socket (0600) and serves in the background. A socket file left by a process that is gone is
// replaced; one that still answers, or a path that is not a socket, is refused and left alone.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return errors.New("adminsock: already started")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("adminsock: %w", err)
	}
	if err := clearStale(ctx, s.path); err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", s.path)
	if err != nil {
		return fmt.Errorf("adminsock: listen: %w", err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("adminsock: %w", err)
	}
	base, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})
	s.srv = &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return base },
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelError),
	}
	srv, done := s.srv, s.done
	go func() {
		defer close(done)
		if err := srv.Serve(&peerListener{Listener: ln, log: s.log, uidOf: peerUID}); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("adminsock: serve", slog.Any("error", err))
		}
	}()
	s.log.Info("adminsock: listening", slog.String("socket", s.path), slog.Int("commands", len(s.reg.Commands())))
	return nil
}

// Stop cancels the running commands, closes the socket and removes its file.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	srv, cancel, done := s.srv, s.cancel, s.done
	s.srv = nil
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	cancel()
	err := srv.Shutdown(ctx)
	if err != nil {
		_ = srv.Close()
	}
	<-done
	if rmErr := os.Remove(s.path); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) && err == nil {
		err = rmErr
	}
	return err
}

// clearStale removes a socket file nobody answers on.
func clearStale(ctx context.Context, path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("adminsock: %w", err)
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("adminsock: %s exists and is not a socket", path)
	}
	dctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var d net.Dialer
	if c, err := d.DialContext(dctx, "unix", path); err == nil {
		_ = c.Close()
		return fmt.Errorf("adminsock: something already answers on %s", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("adminsock: %w", err)
	}
	return nil
}

// peerListener accepts only connections from processes of the application's own user or root.
type peerListener struct {
	net.Listener
	log   *slog.Logger
	uidOf func(net.Conn) (int, error) // peerUID; tests swap it
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := l.uidOf(c)
		if err == nil && allowedUID(uid) {
			return c, nil
		}
		attrs := []any{slog.Int("uid", uid)}
		if err != nil {
			attrs = append(attrs, slog.Any("error", err))
		}
		l.log.Warn("adminsock: refused a connection from another user", attrs...)
		_ = c.Close()
	}
}

// allowedUID reports whether a peer of this uid may use the socket: the application's own user, or root, who can
// read its data dir anyway.
func allowedUID(uid int) bool { return uid >= 0 && (uid == 0 || uid == os.Getuid()) }

// The wire.

type runRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Stdin   []byte   `json:"stdin,omitempty"` // base64 in JSON
}

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// frame is one line of a run's answer: output, or the result at the end.
type frame struct {
	Out     *string `json:"out,omitempty"`
	Done    bool    `json:"done,omitempty"`
	Error   string  `json:"error,omitempty"`
	Message string  `json:"message,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":"internal","message":"internal error"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/commands", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, s.reg.Commands())
	})
	mux.HandleFunc("POST /v1/run", s.run)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found", Message: "the admin socket serves /v1/commands and /v1/run"})
	})
	return s.recover(mux)
}

// recover answers a request whose handler panicked with 500 internal; the panic's value is not logged.
func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				if err, ok := p.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(p)
				}
				s.log.Error("adminsock: a request panicked")
				writeJSON(w, http.StatusInternalServerError, errorBody{Error: "internal", Message: "internal error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) run(w http.ResponseWriter, r *http.Request) {
	var req runRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequest))
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid", Message: "the request is not a run request"})
		return
	}
	cmd, ok := s.reg.lookup(req.Command)
	switch {
	case !ok:
		writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found", Message: fmt.Sprintf("unknown command %q", req.Command)})
		return
	case !cmd.Stdin && len(req.Stdin) > 0:
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid", Message: cmd.Name + " reads no standard input"})
		return
	case len(req.Stdin) > MaxStdin:
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid", Message: "the standard input is over 64 KiB"})
		return
	}
	out := &frameWriter{w: w, rc: http.NewResponseController(w)}
	inv := Invocation{Args: req.Args, Out: out}
	if inv.Args == nil {
		inv.Args = []string{}
	}
	if cmd.Stdin {
		inv.Stdin = req.Stdin
		if inv.Stdin == nil {
			inv.Stdin = []byte{}
		}
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = out.rc.Flush()

	start := time.Now()
	err := s.call(r.Context(), cmd, inv)
	result := frame{Done: true}
	if err != nil {
		result = frame{Error: errorCode(err), Message: err.Error()}
	}
	out.finish(result)
	code := "done"
	if err != nil {
		code = result.Error
	}
	s.log.Info("adminsock: command", slog.String("command", cmd.Name), slog.String("result", code),
		slog.Duration("took", time.Since(start)))
}

// call runs a command, turning a panic into an error so the stream still ends with a result frame. The panic's
// value is not logged (it may quote the command's data); the stack is.
func (s *Server) call(ctx context.Context, cmd Command, inv Invocation) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("adminsock: a command panicked", slog.String("command", cmd.Name),
				slog.String("stack", string(debug.Stack())))
			err = errors.New("the command failed unexpectedly")
		}
	}()
	return cmd.Run(ctx, inv)
}

// errorCode is the wire code of a command error.
func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrUsage):
		return "invalid"
	case errors.Is(err, core.ErrConflict):
		return "conflict"
	case errors.Is(err, core.ErrNotFound):
		return "not_found"
	}
	return "failed"
}

// errFinished is what a write after the result frame gets: a goroutine the command left running.
var errFinished = errors.New("adminsock: the command has finished")

// frameWriter sends every write as one output frame, at once; finish sends the result frame and ends the stream.
type frameWriter struct {
	mu       sync.Mutex
	w        http.ResponseWriter
	rc       *http.ResponseController
	finished bool
}

func (w *frameWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return 0, errFinished
	}
	text := string(p)
	if err := w.frame(frame{Out: &text}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *frameWriter) finish(result frame) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finished = true
	_ = w.frame(result) // a client that went away misses its result; nothing else to do
}

// frame writes one line and flushes it; w.mu is held.
func (w *frameWriter) frame(f frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if _, err := w.w.Write(append(b, '\n')); err != nil {
		return err
	}
	_ = w.rc.Flush() // a writer that cannot flush still gets the frame, at the end
	return nil
}
