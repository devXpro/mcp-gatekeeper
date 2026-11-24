package adminsock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"text/tabwriter"
)

// Client talks to a running application over its admin socket.
type Client struct {
	path string
	app  string // what serves the socket, in error messages
	base string // the URL the requests name, e.g. "http://hub"; only the socket matters, but errors quote it
	hc   *http.Client
}

// hostLabel is an application name that can name the requests' host.
var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NewClient returns a client for the socket at path. It has no timeout of its own: commands may wait for the
// operator; cancel the context instead.
func NewClient(path string) *Client { return newClient(path, "") }

// newClient is NewClient naming the application in its errors ("" says "server"). The requests' host is the
// application's name when it can be one (Family Hub's errors have always quoted http://hub/v1/…), else "admin".
func newClient(path, app string) *Client {
	base := "http://admin"
	if hostLabel.MatchString(app) {
		base = "http://" + app
	}
	if app == "" {
		app = "server"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		DisableKeepAlives: true,
	}
	return &Client{path: path, app: app, base: base, hc: &http.Client{Transport: tr}}
}

// RemoteError is a refusal or a failure the server reported for a command.
type RemoteError struct {
	Code    string // invalid, conflict, not_found, failed or internal
	Message string
}

func (e *RemoteError) Error() string { return e.Message }

// Commands lists the server's commands, sorted by name.
func (c *Client) Commands(ctx context.Context) ([]CommandInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/commands", http.NoBody)
	if err != nil {
		return nil, err
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, c.remoteError(res)
	}
	var list []CommandInfo
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("adminsock: the %s answered nonsense: %w", c.app, err)
	}
	return list, nil
}

// Run runs a command and copies its output to out as it arrives. A failure the server reports is a *RemoteError.
func (c *Client) Run(ctx context.Context, name string, args []string, stdin []byte, out io.Writer) error {
	body, err := json.Marshal(runRequest{Command: name, Args: args, Stdin: stdin})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/run", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return c.remoteError(res)
	}
	dec := json.NewDecoder(res.Body)
	for {
		var f frame
		if err := dec.Decode(&f); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("the %s ended the command without a result", c.app)
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("adminsock: reading the command's output: %w", err)
		}
		switch {
		case f.Out != nil:
			if _, err := io.WriteString(out, *f.Out); err != nil {
				return err
			}
		case f.Done:
			return nil
		case f.Error != "":
			return &RemoteError{Code: f.Error, Message: f.Message}
		}
	}
}

func (c *Client) remoteError(res *http.Response) error {
	var eb errorBody
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&eb); err != nil || eb.Error == "" {
		return &RemoteError{Code: "internal", Message: fmt.Sprintf("the %s answered %s", c.app, res.Status)}
	}
	return &RemoteError{Code: eb.Error, Message: eb.Message}
}

// Exit codes of CLI.Run.
const (
	ExitOK     = 0
	ExitFailed = 1
	ExitUsage  = 2
)

// CLI is the operator's side of the socket, for the application's command line (Family Hub: `hub admin <args…>`
// is CLI{Socket: <data dir>/admin.sock, Prog: "hub admin", App: "hub",
// Hint: "Is the hub running? Run this inside its container."}.Run(…)).
type CLI struct {
	Socket string // the socket's path
	Prog   string // how the operator runs it, in usage lines and errors, e.g. "hub admin"; "" is "admin"
	App    string // what serves the socket, in errors, e.g. "hub"; "" is "server"
	Hint   string // a line printed when the socket does not answer; "" prints none
}

// Run finds the command among the running server's (the longest name that the arguments start with), sends the
// remaining arguments and, for a command that reads it, the standard input; it streams the output to stdout and
// errors to stderr, and returns the exit code: ExitOK, ExitFailed or ExitUsage. No arguments, or "help", lists the
// commands.
func (cli CLI) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	prog := cli.Prog
	if prog == "" {
		prog = "admin"
	}
	c := newClient(cli.Socket, cli.App)
	cmds, err := c.Commands(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: cannot reach the %s on %s: %v\n", prog, c.app, cli.Socket, err)
		if cli.Hint != "" {
			_, _ = fmt.Fprintln(stderr, cli.Hint)
		}
		return ExitFailed
	}
	if len(args) == 0 || len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		w, code := stdout, ExitOK
		if len(args) == 0 {
			w, code = stderr, ExitUsage
		}
		printHelp(w, prog, cmds)
		return code
	}
	cmd, rest, ok := match(cmds, args)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "%s: unknown command %q; `%s help` lists them\n", prog, strings.Join(args, " "), prog)
		return ExitUsage
	}
	var in []byte
	if cmd.Stdin {
		if stdin == nil {
			stdin = strings.NewReader("")
		}
		in, err = io.ReadAll(io.LimitReader(stdin, MaxStdin+1))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %s: reading the standard input: %v\n", prog, cmd.Name, err)
			return ExitFailed
		}
		if len(in) > MaxStdin {
			_, _ = fmt.Fprintf(stderr, "%s %s: the standard input is over 64 KiB\n", prog, cmd.Name)
			return ExitUsage
		}
	}
	if err := c.Run(ctx, cmd.Name, rest, in, stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %s: %v\n", prog, cmd.Name, err)
		if re, ok := errors.AsType[*RemoteError](err); ok && re.Code == "invalid" {
			return ExitUsage
		}
		return ExitFailed
	}
	return ExitOK
}

// match returns the command with the longest name the arguments start with, and the arguments after it.
func match(cmds []CommandInfo, args []string) (CommandInfo, []string, bool) {
	var (
		best  CommandInfo
		words int
	)
	for _, c := range cmds {
		name := strings.Fields(c.Name)
		if len(name) <= words || len(name) > len(args) {
			continue
		}
		if strings.Join(args[:len(name)], " ") == strings.Join(name, " ") {
			best, words = c, len(name)
		}
	}
	if words == 0 {
		return CommandInfo{}, nil, false
	}
	return best, args[words:], true
}

func printHelp(w io.Writer, prog string, cmds []CommandInfo) {
	_, _ = fmt.Fprintf(w, "Usage: %s <command> [arguments]\n", prog)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Commands:")
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	for _, c := range cmds {
		line := c.Name
		if c.Usage != "" {
			line += " " + c.Usage
		}
		if c.Stdin {
			line += " < input"
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\n", line, c.Summary)
	}
	_ = tw.Flush()
}
