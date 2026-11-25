package cloudflare

import (
	"context"
	"errors"
	"io"
)

// Names of the steps of the connect flow, in order.
const (
	StepLogin  = "login"  // cloudflared prints the authorization link; the operator opens it and picks the zone
	StepTunnel = "tunnel" // the tunnel is created (or the directory's own is reused)
	StepDNS    = "dns"    // the hostname is pointed at the tunnel
	StepConfig = "config" // config.yml and tunnel.json are written, the account certificate is deleted
)

// Step is one report of an asynchronous connect (Connector.Start).
//
// A step is reported when it begins ({Name}), once more with LoginURL as soon as cloudflared prints the link (only the
// login step), and when it ends: {Name, Done: true}, or {Name, Done: true, Err: err} when it failed, which ends the
// whole flow.
type Step struct {
	Name     string
	LoginURL string
	Done     bool
	Err      error
}

// reporter turns the phases of connect into Steps. A nil fn reports nothing.
type reporter struct {
	fn  func(Step)
	cur string
}

func (r *reporter) send(s Step) {
	if r.fn != nil {
		r.fn(s)
	}
}

func (r *reporter) begin(name string) {
	r.cur = name
	r.send(Step{Name: name})
}

func (r *reporter) loginURL(u string) { r.send(Step{Name: r.cur, LoginURL: u}) }

func (r *reporter) done() { r.send(Step{Name: r.cur, Done: true}) }

// fail reports the error against the step it happened in; an error before the first step is reported as the login.
func (r *reporter) fail(err error) {
	if r.cur == "" {
		r.cur = StepLogin
	}
	r.send(Step{Name: r.cur, Done: true, Err: err})
}

// Flow is a connect running in the background.
type Flow struct {
	cancel context.CancelFunc
	done   chan struct{}
	rec    Record
	err    error
}

// Done is closed when the flow has ended, in success or not.
func (f *Flow) Done() <-chan struct{} { return f.done }

// Wait blocks until the flow has ended and returns what Connect would.
func (f *Flow) Wait() (Record, error) {
	<-f.done
	return f.rec, f.err
}

// Cancel stops the flow: cloudflared is killed and the temporary HOME with the account certificate is removed.
func (f *Flow) Cancel() { f.cancel() }

// Start runs the flow of Connect in the background, so a web page or a command can follow it: progress is called for
// every Step, in order and never concurrently, and the authorization link comes as soon as cloudflared prints it.
// progress runs on the flow's own goroutine and should return quickly; it may be nil.
//
// A bad hostname or a flow already running (Connect or Start) is returned at once. ctx bounds the whole flow;
// Flow.Cancel stops it too. The connector runs one flow at a time until Wait returns or Done is closed.
func (c *Connector) Start(ctx context.Context, o ConnectOptions, progress func(Step)) (*Flow, error) {
	if !c.mu.TryLock() {
		return nil, errors.New("another `cloudflare connect` is running")
	}
	if _, err := normalizeHost(o.Hostname); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	f := &Flow{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer func() {
			cancel()
			c.mu.Unlock() // released before Done is closed, so the next Start after Wait never races it
			close(f.done)
		}()
		f.rec, f.err = c.connect(ctx, o, io.Discard, progress)
	}()
	return f, nil
}
