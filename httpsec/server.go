package httpsec

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

const (
	// ReadHeaderTimeout bounds reading a request's headers.
	ReadHeaderTimeout = 10 * time.Second
	// IdleTimeout closes keep-alive connections that sit idle.
	IdleTimeout = 2 * time.Minute
	// MaxHeaderBytes caps the request headers.
	MaxHeaderBytes = 64 << 10
	// ShutdownGrace is how long a stop waits for the requests in flight.
	ShutdownGrace = 10 * time.Second
)

// ServerOptions are the listener of Server.
type ServerOptions struct {
	Listen  string       // e.g. ":8080"
	Handler http.Handler // usually New's
	Logger  *slog.Logger // nil discards
}

// Server is an http.Server with the timeouts the gatekeeper wants. It has a ReadHeaderTimeout but no ReadTimeout or
// WriteTimeout, which would cut server-sent event streams that run as long as a tool does.
type Server struct {
	srv  *http.Server
	addr string
	log  *slog.Logger

	ln   net.Listener
	done chan struct{}
}

// NewServer returns a server for o.Handler on o.Listen; Start runs it.
func NewServer(o ServerOptions) (*Server, error) {
	if o.Listen == "" {
		return nil, errors.New("httpsec: Listen is empty")
	}
	if o.Handler == nil {
		return nil, errors.New("httpsec: Handler is nil")
	}
	log := o.Logger
	if log == nil {
		log = discard()
	}
	return &Server{
		addr: o.Listen,
		log:  log,
		srv: &http.Server{
			Addr:              o.Listen,
			Handler:           o.Handler,
			ReadHeaderTimeout: ReadHeaderTimeout,
			IdleTimeout:       IdleTimeout,
			MaxHeaderBytes:    MaxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
		},
	}, nil
}

// Start listens (so a port in use fails the start) and serves in the background.
func (s *Server) Start(ctx context.Context) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("httpsec: listen on %s: %w", s.addr, err)
	}
	s.ln = ln
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("serve", slog.Any("error", err))
		}
	}()
	s.log.Info("listening", slog.String("addr", ln.Addr().String()))
	return nil
}

// Addr is the address the server listens on (useful after Listen ":0"); nil before Start.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Stop lets the requests in flight finish for ShutdownGrace at most (or until ctx ends), then closes what is left:
// long event streams, so the rest of the application still has time to stop.
func (s *Server) Stop(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, ShutdownGrace)
	defer cancel()
	err := s.srv.Shutdown(ctx)
	if err != nil {
		_ = s.srv.Close()
	}
	if s.done != nil {
		<-s.done
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		s.log.Warn("stopped with requests still open")
		return nil
	}
	return err
}
