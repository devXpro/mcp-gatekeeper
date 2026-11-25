package cloudflare

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startedFlow starts a flow against the fake binary and sends every Step to the returned channel.
func startedFlow(t *testing.T, c *Connector, host string) (*Flow, chan Step) {
	t.Helper()
	steps := make(chan Step, 32)
	flow, err := c.Start(t.Context(), ConnectOptions{Hostname: host}, func(s Step) { steps <- s })
	require.NoError(t, err)
	t.Cleanup(func() { flow.Cancel(); <-flow.Done() })
	return flow, steps
}

func newFakeConnector(t *testing.T, f *fakeBin) *Connector {
	t.Helper()
	c, err := New(Options{Runner: ExecRunner{Binary: f.Bin}, Dir: filepath.Join(t.TempDir(), "tunnel"),
		Service: "http://127.0.0.1:8080", TempDir: t.TempDir(), NamePrefix: "home-"})
	require.NoError(t, err)
	return c
}

func TestStartSurfacesTheLoginLinkBeforeTheFlowEnds(t *testing.T) {
	f := newFakeBin(t)
	c := newFakeConnector(t, f)
	flow, steps := startedFlow(t, c, "Home.Example.com")

	// The link arrives while cloudflared still waits for the operator.
	assert.Equal(t, Step{Name: StepLogin}, <-steps)
	link := <-steps
	assert.Equal(t, StepLogin, link.Name)
	assert.Contains(t, link.LoginURL, "https://dash.cloudflare.com/argotunnel")
	assert.False(t, link.Done)
	select {
	case <-flow.Done():
		t.Fatal("the flow ended before the operator authorized")
	default:
	}

	f.set("login-release")
	rec, err := flow.Wait()
	require.NoError(t, err)
	assert.Equal(t, Record{Name: "home-home-example-com", ID: tunnelID, Hostname: "home.example.com"}, rec)

	close(steps)
	var got []Step
	for s := range steps {
		got = append(got, s)
	}
	assert.Equal(t, []Step{
		{Name: StepLogin, Done: true},
		{Name: StepTunnel}, {Name: StepTunnel, Done: true},
		{Name: StepDNS}, {Name: StepDNS, Done: true},
		{Name: StepConfig}, {Name: StepConfig, Done: true},
	}, got)

	// The same files and permissions as Connect leaves, and no certificate behind.
	cfg, err := os.ReadFile(filepath.Join(c.dir, ConfigFile))
	require.NoError(t, err)
	assert.Contains(t, string(cfg), "hostname: home.example.com")
	if runtime.GOOS != "windows" {
		for _, name := range []string{ConfigFile, CredentialsFile, RecordFile} {
			assert.Equal(t, os.FileMode(0o600), mode(t, filepath.Join(c.dir, name)), name)
		}
	}
	noLeftoverHome(t, c)

	// The connector is free again.
	again, err := c.Start(t.Context(), ConnectOptions{Hostname: "home.example.com"}, nil)
	require.NoError(t, err)
	_, err = again.Wait()
	require.NoError(t, err)
}

func TestStartReportsTheFailingStep(t *testing.T) {
	tests := []struct {
		name string
		ctl  []string
		step string
		want string
	}{
		{name: "login", ctl: []string{"login-fail"}, step: StepLogin, want: "authorization did not complete"},
		{name: "no certificate", ctl: []string{"login-release", "no-cert"}, step: StepLogin, want: "authorization did not complete"},
		{name: "create", ctl: []string{"login-release", "create-fail"}, step: StepTunnel, want: "could not create the tunnel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeBin(t)
			for _, name := range tt.ctl {
				f.set(name)
			}
			c := newFakeConnector(t, f)
			flow, steps := startedFlow(t, c, "home.example.com")
			_, err := flow.Wait()
			require.ErrorContains(t, err, tt.want)

			close(steps)
			var last Step
			for s := range steps {
				last = s
			}
			assert.Equal(t, tt.step, last.Name)
			assert.True(t, last.Done)
			require.Error(t, last.Err)
			assert.Equal(t, err.Error(), last.Err.Error())
			noLeftoverHome(t, c)
			assert.NoFileExists(t, filepath.Join(c.dir, ConfigFile))
		})
	}
}

func TestStartRefusesWhatConnectRefuses(t *testing.T) {
	f := newFakeBin(t)
	c := newFakeConnector(t, f)

	_, err := c.Start(t.Context(), ConnectOptions{Hostname: "home"}, nil)
	require.ErrorIs(t, err, ErrHostname)
	assert.True(t, c.mu.TryLock(), "a refused hostname leaves the connector free")
	c.mu.Unlock()

	flow, _ := startedFlow(t, c, "home.example.com")
	_, err = c.Start(t.Context(), ConnectOptions{Hostname: "home.example.com"}, nil)
	require.ErrorContains(t, err, "another")
	_, err = c.Connect(t.Context(), ConnectOptions{Hostname: "home.example.com"}, os.Stderr)
	require.ErrorContains(t, err, "another")
	flow.Cancel()
}

func TestStartCancel(t *testing.T) {
	f := newFakeBin(t)
	c := newFakeConnector(t, f)
	flow, steps := startedFlow(t, c, "home.example.com")
	<-steps // login begins
	<-steps // the link
	flow.Cancel()
	_, err := flow.Wait()
	require.Error(t, err)
	noLeftoverHome(t, c)

	// A cancelled parent context stops it as well.
	ctx, cancel := context.WithCancel(t.Context())
	second, err := c.Start(ctx, ConnectOptions{Hostname: "home.example.com"}, nil)
	require.NoError(t, err)
	cancel()
	_, err = second.Wait()
	require.Error(t, err)
}

// An existing DNS record is a sentinel for Connect and Start, with the message the command printed before.
func TestDNSRecordExists(t *testing.T) {
	const msg = "home.example.com already has a DNS record; run again with --overwrite-dns to point it at this tunnel"
	f := newFakeBin(t)
	f.set("login-release")
	f.set("dns-exists")
	c := newFakeConnector(t, f)

	_, err := c.Connect(t.Context(), ConnectOptions{Hostname: "home.example.com"}, io.Discard)
	require.ErrorIs(t, err, ErrDNSRecordExists)
	assert.EqualError(t, err, msg)
	assert.NoFileExists(t, filepath.Join(c.dir, ConfigFile))

	flow, steps := startedFlow(t, c, "home.example.com")
	_, err = flow.Wait()
	require.ErrorIs(t, err, ErrDNSRecordExists)
	assert.EqualError(t, err, msg)
	close(steps)
	var last Step
	for s := range steps {
		last = s
	}
	assert.Equal(t, StepDNS, last.Name)
	require.ErrorIs(t, last.Err, ErrDNSRecordExists)

	// With the overwrite flag the same record is replaced; other DNS failures are not this sentinel.
	flow, err = c.Start(t.Context(), ConnectOptions{Hostname: "home.example.com", OverwriteDNS: true}, nil)
	require.NoError(t, err)
	_, err = flow.Wait()
	require.NoError(t, err)
	f.unset("login-release")
	f.set("login-fail")
	_, err = c.Connect(t.Context(), ConnectOptions{Hostname: "home.example.com"}, io.Discard)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrDNSRecordExists)
}
