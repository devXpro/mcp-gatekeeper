// Package cloudflare creates an application's Cloudflare Tunnel with the cloudflared CLI, the way findmy-mcp-bridge
// does (src/tunnel.mjs), with no Cloudflare API token. Family Hub's `hub admin cloudflare connect` is a thin command
// over Connector.Connect:
//
//  1. `cloudflared tunnel login` prints an authorization link; the operator opens it and picks the zone. cloudflared
//     then saves the account certificate (cert.pem) in a temporary HOME.
//  2. `cloudflared tunnel create` makes the tunnel and writes its credentials into the tunnel directory, unless the
//     directory already holds a tunnel of an earlier run, which is reused.
//  3. `cloudflared tunnel route dns` points the hostname at the tunnel (a CNAME), replacing a record only with
//     ConnectOptions.OverwriteDNS (--overwrite-dns).
//  4. config.yml and tunnel.json are written into the tunnel directory (0600).
//  5. The account certificate is deleted, whatever happened: only the tunnel's own credentials stay.
//
// The cloudflared service of the application's stack runs the tunnel from that directory, mounted at the same path.
// The cloudflared binary is reached through Runner, so tests (and applications that run it elsewhere) inject their
// own.
package cloudflare

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Files inside the tunnel directory.
const (
	ConfigFile      = "config.yml"
	CredentialsFile = "credentials.json"
	RecordFile      = "tunnel.json"
)

// Timeouts of the cloudflared steps.
const (
	LoginTimeout   = 15 * time.Minute // a hard cap: cloudflared itself stops waiting for the operator after a few minutes
	CommandTimeout = 2 * time.Minute
)

var (
	hostnameRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	namePrefixRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	tunnelIDRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	loginURLRe   = regexp.MustCompile(`https://dash\.cloudflare\.com/\S+`)
	existsRe     = regexp.MustCompile(`(?i)already exists|already configured`)
)

// ErrHostname marks a hostname the command refuses.
var ErrHostname = errors.New("bad hostname")

// Runner runs the cloudflared CLI.
type Runner interface {
	// Run runs cloudflared with args in exactly the environment env, calls line (when not nil) with every line of its
	// output as it comes, and returns the whole output. A non-zero exit is an error.
	Run(ctx context.Context, env, args []string, line func(string)) (string, error)
}

// ExecRunner runs the cloudflared binary at Binary (a name looked up in PATH, or a path).
type ExecRunner struct {
	Binary string
}

// Run implements Runner.
func (r ExecRunner) Run(ctx context.Context, env, args []string, line func(string)) (string, error) {
	bin, err := exec.LookPath(r.Binary)
	if err != nil {
		return "", fmt.Errorf("cloudflared is not installed here: %w", err)
	}
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: fixed binary, arguments checked by the caller
	cmd.Env = env
	cmd.WaitDelay = 5 * time.Second
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return "", err
	}
	var out strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			out.WriteString(sc.Text() + "\n")
			if line != nil {
				line(sc.Text())
			}
		}
		_, _ = io.Copy(io.Discard, pr) // a line too long for the scanner must not block cloudflared
	}()
	err = cmd.Wait()
	_ = pw.Close()
	<-done
	return out.String(), err
}

// Record is tunnel.json: which tunnel the directory holds and where it points.
type Record struct {
	Name     string `json:"name"`
	ID       string `json:"id"`
	Hostname string `json:"hostname,omitempty"`
}

// ReadRecord reads tunnel.json of dir; a missing file is the zero Record and no error.
func ReadRecord(dir string) (Record, error) {
	b, err := os.ReadFile(filepath.Join(dir, RecordFile)) //nolint:gosec // G304: the operator's own directory
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, nil
	}
	if err != nil {
		return Record{}, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return Record{}, fmt.Errorf("%s is broken: %w", RecordFile, err)
	}
	return r, nil
}

// DefaultNamePrefix starts the name of a tunnel the connector creates, when Options.NamePrefix is empty.
const DefaultNamePrefix = "mcp-gatekeeper-"

// Options configure a Connector.
type Options struct {
	// Runner runs cloudflared; nil is ExecRunner{Binary: "cloudflared"}.
	Runner Runner
	// Dir is the tunnel directory, the same path in the application and in cloudflared. Required.
	Dir string
	// Service is where the tunnel sends the traffic, e.g. http://fh-hub:8080. Required.
	Service string
	// TempDir is where the temporary HOME is made; "" is os.TempDir.
	TempDir string
	// NamePrefix starts the tunnel's name (the prefix and the host with dashes, e.g. "family-hub-hub-example-com");
	// "" is DefaultNamePrefix. An application keeps its value: it is the name of tunnels already created.
	NamePrefix string
	// StartHint is printed last, how to start the tunnel (e.g. "docker compose restart cloudflared"); "" prints
	// nothing.
	StartHint string
}

// Connector runs the connect flow.
type Connector struct {
	runner     Runner
	dir        string
	service    string
	tempDir    string
	namePrefix string
	startHint  string

	mu sync.Mutex
}

// New validates o and returns a Connector.
func New(o Options) (*Connector, error) {
	if o.Dir == "" {
		return nil, errors.New("cloudflare: Dir is empty")
	}
	if strings.TrimSpace(o.Service) == "" || strings.ContainsAny(o.Service, "\r\n") {
		return nil, errors.New("cloudflare: Service must be one line, e.g. http://app:8080")
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{Binary: "cloudflared"}
	}
	if o.NamePrefix == "" {
		o.NamePrefix = DefaultNamePrefix
	}
	if !namePrefixRe.MatchString(o.NamePrefix) {
		return nil, fmt.Errorf("cloudflare: NamePrefix %q must be lower-case letters, digits and dashes", o.NamePrefix)
	}
	return &Connector{
		runner: o.Runner, dir: o.Dir, service: o.Service, tempDir: o.TempDir, namePrefix: o.NamePrefix,
		startHint: o.StartHint,
	}, nil
}

// ConnectOptions are the choices of one connect.
type ConnectOptions struct {
	Hostname     string
	OverwriteDNS bool
}

// Dir is the tunnel directory.
func (c *Connector) Dir() string { return c.dir }

// Connect runs the whole flow, printing progress and the authorization link to out.
func (c *Connector) Connect(ctx context.Context, o ConnectOptions, out io.Writer) (Record, error) {
	if !c.mu.TryLock() {
		return Record{}, errors.New("another `cloudflare connect` is running")
	}
	defer c.mu.Unlock()
	host := strings.ToLower(strings.TrimSpace(o.Hostname))
	if len(host) > 253 || !hostnameRe.MatchString(host) {
		return Record{}, fmt.Errorf("%w: %q is not a full host name, e.g. hub.example.com", ErrHostname, o.Hostname)
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return Record{}, err
	}

	// The account certificate lives only in this temporary HOME, removed on every way out.
	home, err := os.MkdirTemp(c.tempDir, "cloudflared-")
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = os.RemoveAll(home) }()
	cert := filepath.Join(home, ".cloudflared", "cert.pem")
	env := []string{"HOME=" + home, "TUNNEL_ORIGIN_CERT=" + cert, "PATH=" + home}

	// 1. Login.
	_, _ = fmt.Fprintf(out, "Step 1/4: authorize Cloudflare. Open the link below, sign in and pick the zone of %s.\n", host)
	lctx, cancel := context.WithTimeout(ctx, LoginTimeout)
	shown := false
	lout, err := c.runner.Run(lctx, env, []string{"tunnel", "login"}, func(l string) {
		if m := loginURLRe.FindString(l); m != "" && !shown {
			shown = true
			_, _ = fmt.Fprintf(out, "\n  %s\n\nWaiting for the authorization. cloudflared gives up after a few minutes "+
				"(about four); then run this command again for a fresh link.\n", m)
		}
	})
	cancel()
	if err != nil || !exists(cert) {
		return Record{}, fmt.Errorf("the Cloudflare authorization did not complete (the link lives a few minutes): %s",
			lastLine(lout, err))
	}
	_, _ = fmt.Fprintln(out, "Authorized.")

	// 2. The tunnel.
	rec, err := c.tunnel(ctx, env, host, out)
	if err != nil {
		return Record{}, err
	}

	// 3. DNS.
	_, _ = fmt.Fprintf(out, "Step 3/4: point %s at the tunnel.\n", host)
	args := []string{"tunnel", "route", "dns"}
	if o.OverwriteDNS {
		args = append(args, "--overwrite-dns")
	}
	if dout, err := c.run(ctx, env, append(args, rec.ID, host)...); err != nil {
		if existsRe.MatchString(dout) {
			return Record{}, fmt.Errorf("%s already has a DNS record; run again with --overwrite-dns to point it at this tunnel", host)
		}
		return Record{}, fmt.Errorf("could not add the DNS record: %s", lastLine(dout, err))
	}

	// 4. Config.
	rec.Hostname = host
	if err := c.writeRecord(rec); err != nil {
		return Record{}, err
	}
	if err := writeFile(filepath.Join(c.dir, ConfigFile), []byte(c.config(rec))); err != nil {
		return Record{}, err
	}
	_, _ = fmt.Fprintf(out, "Step 4/4: wrote %s.\n", filepath.Join(c.dir, ConfigFile))

	if err := os.Remove(cert); err != nil {
		return Record{}, fmt.Errorf("could not delete the account certificate: %w", err)
	}
	_, _ = fmt.Fprintln(out, "Deleted the Cloudflare account certificate; only the tunnel's own credentials stay.")
	_, _ = fmt.Fprintf(out, "Done: tunnel %s (%s) serves https://%s.\n", rec.Name, rec.ID, host)
	if c.startHint != "" {
		_, _ = fmt.Fprintf(out, "Start it: %s\n", c.startHint)
	}
	return rec, nil
}

// tunnel reuses the tunnel the directory holds, or creates one.
func (c *Connector) tunnel(ctx context.Context, env []string, host string, out io.Writer) (Record, error) {
	rec, err := ReadRecord(c.dir)
	if err != nil {
		return Record{}, err
	}
	creds := filepath.Join(c.dir, CredentialsFile)
	if rec.ID != "" && exists(creds) {
		_, _ = fmt.Fprintf(out, "Step 2/4: reusing tunnel %s (%s).\n", rec.Name, rec.ID)
		return rec, nil
	}
	name := c.namePrefix + strings.ReplaceAll(host, ".", "-")
	_, _ = fmt.Fprintf(out, "Step 2/4: create tunnel %s.\n", name)
	if cout, err := c.run(ctx, env, "tunnel", "create", "--credentials-file", creds, name); err != nil {
		if existsRe.MatchString(cout) {
			return Record{}, fmt.Errorf("the Cloudflare account already has a tunnel named %s, but its credentials are "+
				"not in %s: restore %s there, or delete that tunnel in the Cloudflare dashboard "+
				"(Zero Trust → Networks → Tunnels) and run this again", name, c.dir, CredentialsFile)
		}
		return Record{}, fmt.Errorf("could not create the tunnel: %s", lastLine(cout, err))
	}
	if err := os.Chmod(creds, 0o600); err != nil {
		return Record{}, fmt.Errorf("the tunnel was created but its credentials are missing: %w", err)
	}
	var cj struct {
		TunnelID string `json:"TunnelID"`
	}
	b, err := os.ReadFile(creds) //nolint:gosec // G304: the path is built here
	if err == nil {
		err = json.Unmarshal(b, &cj)
	}
	if err != nil || !tunnelIDRe.MatchString(cj.TunnelID) {
		return Record{}, fmt.Errorf("cannot read the tunnel id from %s", creds)
	}
	rec = Record{Name: name, ID: cj.TunnelID}
	return rec, c.writeRecord(rec)
}

func (c *Connector) run(ctx context.Context, env []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()
	return c.runner.Run(ctx, env, args, nil)
}

func (c *Connector) writeRecord(r Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(c.dir, RecordFile), append(b, '\n'))
}

// config is cloudflared's config.yml. Every value is checked (host, tunnel id) or the operator's own (service).
func (c *Connector) config(r Record) string {
	return strings.Join([]string{
		"tunnel: " + r.ID,
		"credentials-file: " + filepath.Join(c.dir, CredentialsFile),
		"no-autoupdate: true",
		"ingress:",
		"  - hostname: " + r.Hostname,
		"    service: " + c.service,
		"  - service: http_status:404",
		"",
	}, "\n")
}

// writeFile replaces path atomically with mode 0600.
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// lastLine is the last non-empty line of cloudflared's output, for an error message.
func lastLine(out string, err error) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if l := strings.TrimSpace(lines[len(lines)-1]); l != "" {
		return l
	}
	if err != nil {
		return err.Error()
	}
	return "unknown error"
}
