package cloudflare

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// Mode is how the Supervisor runs cloudflared.
type Mode string

// The two modes.
const (
	// Named runs the tunnel the Connector made: `cloudflared tunnel --no-autoupdate --config <Dir>/config.yml run`.
	Named Mode = "named"
	// Quick runs a quick tunnel, no account and no domain: `cloudflared tunnel --no-autoupdate --metrics <addr>
	// --url <Service>`. Its hostname is random and changes at every start, and is read from cloudflared's own output
	// only; it is "for trying" (no uptime promise, no Server-Sent Events, 200 requests in flight).
	Quick Mode = "quick"
)

// State is where the Supervisor's tunnel stands.
type State string

// The states.
const (
	StateStarting  State = "starting"  // cloudflared was started (named: with a Probe this lasts an instant) or has no hostname yet (quick)
	StateProbing   State = "probing"   // the public URL is known and Probe has not passed yet
	StateConnected State = "connected" // the tunnel is up (and the probe passed, when there is one)
	StateFailing   State = "failing"   // cloudflared exited; a restart is waiting for its backoff
	StateStopped   State = "stopped"   // not started, or Stop was called
)

// Restart backoff and the other timing defaults.
const (
	MinBackoff = time.Second
	MaxBackoff = time.Minute

	// stableAfter is how long a child must stay up for the next failure to start the backoff over.
	stableAfter  = time.Minute
	pollEvery    = 500 * time.Millisecond // between the reads of /quicktunnel that confirm the hostname
	confirmTries = 20                     // reads of /quicktunnel before the confirmation gives up
	probeEvery   = 2 * time.Second        // between the probes of one run
	probeTimeout = 15 * time.Second
	stopWait     = 5 * time.Second // SIGTERM first, SIGKILL after this
	// namedGrace is how long a named child without a Probe must stay up to count as connected, when its log never
	// says "Registered tunnel connection".
	namedGrace = 5 * time.Second
)

var (
	// quickHostRe is a quick tunnel's hostname. trycloudflare.com is on the Public Suffix List; "api" is Cloudflare's
	// own service name, which cloudflared prints in its log.
	quickHostRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com$`)
	quickLogURLRe = regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)
	registeredRe  = regexp.MustCompile(`Registered tunnel connection`)
)

// Status is a snapshot of the Supervisor.
type Status struct {
	State State `json:"state"`
	// URL is the public address, https://<host>: the named tunnel's hostname, or the quick tunnel's current one
	// (empty while cloudflared has not announced it yet).
	URL string `json:"url,omitempty"`
	// Since is when State last changed.
	Since time.Time `json:"since"`
	// LastError is the last failure (cloudflared exited, or the probe failed); it clears when the tunnel connects.
	LastError string `json:"lastError,omitempty"`
}

// SupervisorOptions configure a Supervisor.
type SupervisorOptions struct {
	// Mode is Named or Quick. Required.
	Mode Mode
	// Binary is the cloudflared to run, a name looked up in PATH or a path; "" is "cloudflared".
	Binary string
	// Dir is the tunnel directory of the Connector (Named: it holds config.yml, credentials.json and tunnel.json).
	// The child's private HOME is Dir/home. Required.
	Dir string
	// Service is where a quick tunnel sends the traffic, e.g. http://127.0.0.1:8080. Quick only, required there.
	Service string
	// MetricsAddr is the loopback address of a quick tunnel's metrics server; "" is 127.0.0.1:0, a free port picked at
	// each start. Quick only. Its /quicktunnel only confirms the hostname cloudflared printed (a log line either way):
	// another local program could hold the port, so the hostname is never taken from there.
	MetricsAddr string
	// Probe checks the public URL end to end (an application typically fetches a well-known path through it). While it
	// fails the state is probing and its error is the LastError; nil means "connected as soon as cloudflared says so".
	Probe func(ctx context.Context, publicURL string) error
	// OnURL is called when a quick tunnel's hostname appears in cloudflared's output or changes (every restart makes a
	// new one), with https://<host>. It runs on the supervisor's goroutine and should return quickly. Named mode never
	// calls it.
	OnURL func(url string)
	// Log receives cloudflared's output, line by line: the application's rotating writer. nil discards it.
	Log io.Writer
	// Logger receives the supervisor's own events; nil discards them.
	Logger *slog.Logger
	// Clock is the source of Status.Since; nil is time.Now.
	Clock core.Clock
}

// Supervisor runs one cloudflared child and keeps it up, with restarts on a backoff from MinBackoff to MaxBackoff.
//
// The child gets a private empty HOME (Dir/home, 0700), so a ~/.cloudflared of the user can never change or block
// it, and a minimal environment: HOME and the PATH of the binary. No secret is ever put in its arguments; a named
// tunnel reads its credentials file.
type Supervisor struct {
	o      SupervisorOptions
	logger *slog.Logger
	clock  core.Clock

	// Timing, set by tests.
	minBackoff, maxBackoff, stable time.Duration
	poll, probeGap, namedGrace     time.Duration
	after                          func(time.Duration) <-chan time.Time

	mu       sync.Mutex
	st       Status
	started  bool
	announce string // the last URL OnURL was called with
	cancel   context.CancelFunc
	done     chan struct{}
}

// NewSupervisor validates o. cloudflared itself is looked for in Start.
func NewSupervisor(o SupervisorOptions) (*Supervisor, error) {
	if o.Mode != Named && o.Mode != Quick {
		return nil, fmt.Errorf("cloudflare: Mode %q is neither %q nor %q", o.Mode, Named, Quick)
	}
	if o.Dir == "" {
		return nil, errors.New("cloudflare: Dir is empty")
	}
	if o.Mode == Quick {
		if s := strings.TrimSpace(o.Service); s == "" || strings.ContainsAny(o.Service, "\r\n") {
			return nil, errors.New("cloudflare: Service must be one line, e.g. http://127.0.0.1:8080")
		}
		if _, err := metricsAddr(o.MetricsAddr); err != nil {
			return nil, err
		}
	}
	if o.Binary == "" {
		o.Binary = "cloudflared"
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	logger := o.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	s := &Supervisor{
		o: o, logger: logger, clock: clock,
		minBackoff: MinBackoff, maxBackoff: MaxBackoff, stable: stableAfter, poll: pollEvery, probeGap: probeEvery, namedGrace: namedGrace,
		after: time.After,
	}
	s.st = Status{State: StateStopped, Since: clock()}
	return s, nil
}

// Status returns a snapshot.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

// Start checks that cloudflared (and, for Named, the connected tunnel) is there, then runs the child in the
// background until ctx ends or Stop is called. A Supervisor starts once.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("cloudflare: the supervisor was already started")
	}
	bin, err := exec.LookPath(s.o.Binary)
	if err != nil {
		return fmt.Errorf("cloudflared is not installed here: %w", err)
	}
	if s.o.Mode == Named {
		if _, err := s.namedURL(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	s.started, s.cancel, s.done = true, cancel, make(chan struct{})
	s.setLocked(StateStarting, "", "")
	go s.loop(ctx, bin)
	return nil
}

// Stop ends the child (SIGTERM, then a kill after a few seconds), waits for it and leaves the state stopped.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// namedURL is the hostname the tunnel directory was connected for, as https://<host>.
func (s *Supervisor) namedURL() (string, error) {
	if _, err := os.Stat(filepath.Join(s.o.Dir, ConfigFile)); err != nil {
		return "", fmt.Errorf("no tunnel is connected in %s (%s is missing): connect a domain first", s.o.Dir, ConfigFile)
	}
	rec, err := ReadRecord(s.o.Dir)
	if err != nil {
		return "", err
	}
	if rec.Hostname == "" {
		return "", fmt.Errorf("%s of %s has no hostname: connect a domain first", RecordFile, s.o.Dir)
	}
	return "https://" + rec.Hostname, nil
}

// setLocked changes the state, URL and error; "" keeps the error, "-" clears it. It stamps Since on a state change.
func (s *Supervisor) setLocked(state State, url, lastErr string) {
	if s.st.State != state {
		s.st.State, s.st.Since = state, s.clock()
	}
	s.st.URL = url
	switch lastErr {
	case "":
	case "-":
		s.st.LastError = ""
	default:
		s.st.LastError = lastErr
	}
}

func (s *Supervisor) set(state State, url, lastErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setLocked(state, url, lastErr)
}

// loop runs the child again and again, until ctx ends.
func (s *Supervisor) loop(ctx context.Context, bin string) {
	defer close(s.done)
	defer s.set(StateStopped, "", "")
	delay := s.minBackoff
	for {
		began := s.clock()
		err := s.runOnce(ctx, bin)
		if ctx.Err() != nil {
			return
		}
		msg := "cloudflared exited"
		if err != nil {
			msg = err.Error()
		}
		s.logger.Warn("cloudflared exited", "mode", string(s.o.Mode), "err", msg, "restart_in", delay.String())
		if s.clock().Sub(began) >= s.stable {
			delay = s.minBackoff
		}
		url := ""
		if s.o.Mode == Named {
			url, _ = s.namedURL()
		}
		s.set(StateFailing, url, msg)
		select {
		case <-ctx.Done():
			return
		case <-s.after(delay):
		}
		delay = min(delay*2, s.maxBackoff)
	}
}

// runOnce runs one child to its end and returns why it ended.
func (s *Supervisor) runOnce(ctx context.Context, bin string) error {
	home, err := s.privateHome()
	if err != nil {
		return err
	}
	var args []string
	var metrics, namedURL string
	switch s.o.Mode {
	case Named:
		if namedURL, err = s.namedURL(); err != nil {
			return err
		}
		args = []string{"tunnel", "--no-autoupdate", "--config", filepath.Join(s.o.Dir, ConfigFile), "run"}
	case Quick:
		if metrics, err = metricsAddr(s.o.MetricsAddr); err != nil {
			return err
		}
		args = []string{"tunnel", "--no-autoupdate", "--metrics", metrics, "--url", s.o.Service}
	}

	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	cmd := exec.CommandContext(runCtx, bin, args...) //nolint:gosec // G204: the binary is the operator's, the arguments are built here
	cmd.Env = []string{"HOME=" + home, "PATH=" + filepath.Dir(bin)}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopWait
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	s.set(StateStarting, "", "")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start cloudflared: %w", err)
	}
	s.logger.Info("cloudflared started", "mode", string(s.o.Mode), "pid", cmd.Process.Pid)

	// The first sign of a public address: the log (named: "Registered tunnel connection", an extra signal; quick: the
	// hostname, its only source). The buffer holds one; the others find it full and move on.
	ready := make(chan string, 1)
	logged := make(chan string, 1) // quick: the hostname of the output, for the metrics check
	signal := func(url string) {
		for _, ch := range []chan string{ready, logged} {
			select {
			case ch <- url:
			default:
			}
		}
	}
	var wg sync.WaitGroup
	var last lastSeen
	wg.Go(func() { s.pump(pr, &last, namedURL, signal) })
	if s.o.Mode == Quick {
		wg.Go(func() { s.confirmQuick(runCtx, metrics, logged) })
	}
	if s.o.Mode == Named {
		// The address is known from the config, so nothing waits on cloudflared's log text. With a Probe the probe
		// decides at once; without one, the log line (see pump) or a child that stays up for a few seconds does.
		if s.o.Probe != nil {
			signal(namedURL)
		} else {
			wg.Go(func() {
				select {
				case <-runCtx.Done():
				case <-time.After(s.namedGrace):
					signal(namedURL)
				}
			})
		}
	}
	wg.Go(func() { s.watch(runCtx, ready) })

	werr := cmd.Wait()
	_ = pw.Close()
	stop()
	wg.Wait()
	if werr == nil {
		werr = errors.New("exit status 0")
	}
	if l := last.get(); l != "" {
		return fmt.Errorf("%w: %s", werr, l)
	}
	return werr
}

// lastSeen keeps the last non-empty line of the child's output for the error message.
type lastSeen struct {
	mu sync.Mutex
	s  string
}

func (l *lastSeen) set(s string) {
	l.mu.Lock()
	l.s = s
	l.mu.Unlock()
}

func (l *lastSeen) get() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.s
}

// pump copies the child's output to Log, line by line, and looks for the sign of the public address in it.
func (s *Supervisor) pump(r io.Reader, last *lastSeen, namedURL string, signal func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		_, _ = io.WriteString(s.o.Log, line+"\n")
		if strings.TrimSpace(line) != "" {
			last.set(strings.TrimSpace(line))
		}
		switch s.o.Mode {
		case Named:
			if registeredRe.MatchString(line) {
				signal(namedURL)
			}
		case Quick:
			for _, m := range quickLogURLRe.FindAllString(line, -1) {
				if u, ok := quickURL(m); ok {
					signal(u)
					break
				}
			}
		}
	}
	_, _ = io.Copy(io.Discard, r) // a line too long for the scanner must not block cloudflared
}

// confirmQuick checks the hostname cloudflared printed (the first on logged) against GET /quicktunnel on the metrics
// address, and only logs the result. The output is the only source of the hostname: the child's pipe is private,
// while the metrics port is a loopback port that another local program could have bound in the instant between
// metricsAddr and cloudflared's own bind (review R-6), so whatever it claims is compared, never published.
func (s *Supervisor) confirmQuick(ctx context.Context, addr string, logged <-chan string) {
	var want string
	select {
	case <-ctx.Done():
		return
	case want = <-logged:
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	for range confirmTries {
		if got, ok := readQuickHostname(ctx, client, addr); ok {
			if got == want {
				s.logger.Info("cloudflared's metrics server confirms the quick tunnel's hostname", "url", want)
			} else {
				s.logger.Warn("the metrics port names another quick tunnel than cloudflared's output; ignored, another "+
					"program may hold the port", "url", want, "metrics_url", got, "metrics", addr)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.poll):
		}
	}
	s.logger.Info("cloudflared's metrics server did not confirm the quick tunnel's hostname", "url", want, "metrics", addr)
}

// readQuickHostname does GET /quicktunnel on the metrics server: {"hostname":"…"}.
func readQuickHostname(ctx context.Context, client *http.Client, addr string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/quicktunnel", http.NoBody)
	if err != nil {
		return "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var v struct {
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&v); err != nil {
		return "", false
	}
	return quickURL(v.Hostname)
}

// quickURL turns a quick tunnel hostname (bare, or as a https URL) into https://<host>; anything that is not a
// <name>.trycloudflare.com host, and the "api" host, is refused.
func quickURL(s string) (string, bool) {
	host := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "https://")))
	if !quickHostRe.MatchString(host) || strings.HasPrefix(host, "api.") {
		return "", false
	}
	return "https://" + host, true
}

// watch waits for the public address of one run, publishes it and probes it.
func (s *Supervisor) watch(ctx context.Context, ready <-chan string) {
	var url string
	select {
	case <-ctx.Done():
		return
	case url = <-ready:
	}
	if s.o.Probe != nil {
		s.set(StateProbing, url, "")
	} else {
		s.set(StateConnected, url, "-")
	}
	if s.o.Mode == Quick {
		s.announceURL(url)
	}
	for s.o.Probe != nil {
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		err := s.o.Probe(pctx, url)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			s.set(StateConnected, url, "-")
			return
		}
		s.set(StateProbing, url, "the public URL does not answer yet: "+err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.probeGap):
		}
	}
}

// announceURL calls OnURL when url differs from the last one announced.
func (s *Supervisor) announceURL(url string) {
	s.mu.Lock()
	changed := url != s.announce
	s.announce = url
	s.mu.Unlock()
	if changed && s.o.OnURL != nil {
		s.o.OnURL(url)
	}
}

// privateHome makes Dir/home empty with mode 0700: the child's HOME.
func (s *Supervisor) privateHome() (string, error) {
	if err := os.MkdirAll(s.o.Dir, 0o700); err != nil {
		return "", err
	}
	home := filepath.Join(s.o.Dir, "home")
	if err := os.RemoveAll(home); err != nil {
		return "", fmt.Errorf("cannot empty the private HOME of cloudflared: %w", err)
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		return "", err
	}
	return home, nil
}

// metricsAddr returns a loopback host:port for the metrics server; port 0 (the default) becomes a free port.
func metricsAddr(want string) (string, error) {
	if want == "" {
		want = "127.0.0.1:0"
	}
	host, port, err := net.SplitHostPort(want)
	if err != nil {
		return "", fmt.Errorf("cloudflare: MetricsAddr %q is not host:port: %w", want, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("cloudflare: MetricsAddr %q must be a loopback IP address", want)
	}
	if port != "0" {
		return want, nil
	}
	l, err := net.Listen("tcp", want)
	if err != nil {
		return "", fmt.Errorf("cloudflare: no free metrics port: %w", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr, nil
}
