package cloudflare

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// builtFake is the fake cloudflared of testdata/fakecloudflared, built once for the package's tests.
var builtFake string

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	dir, err := os.MkdirTemp("", "fakecloudflared-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	builtFake = filepath.Join(dir, "fakecloudflared")
	build := exec.Command("go", "build", "-o", builtFake, "./testdata/fakecloudflared") //nolint:gosec // G204: fixed arguments
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "cannot build the fake cloudflared: %v\n%s", err, out)
		return 1
	}
	return m.Run()
}

// fakeBin is one copy of the fake cloudflared with its own control directory.
type fakeBin struct {
	t   *testing.T
	Bin string
	ctl string
}

func newFakeBin(t *testing.T) *fakeBin {
	t.Helper()
	dir := t.TempDir()
	f := &fakeBin{t: t, Bin: filepath.Join(dir, "cloudflared"), ctl: filepath.Join(dir, "control")}
	require.NoError(t, os.Mkdir(f.ctl, 0o700))
	src, err := os.Open(builtFake) //nolint:gosec // G304: the path of the binary TestMain built
	require.NoError(t, err)
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(f.Bin, os.O_CREATE|os.O_WRONLY, 0o700) //nolint:gosec // G302: an executable test binary
	require.NoError(t, err)
	_, err = io.Copy(dst, src)
	require.NoError(t, err)
	require.NoError(t, dst.Close())
	return f
}

// set creates a control file; unset removes it.
func (f *fakeBin) set(name string) {
	f.t.Helper()
	require.NoError(f.t, os.WriteFile(filepath.Join(f.ctl, name), nil, 0o600))
}

func (f *fakeBin) unset(name string) {
	f.t.Helper()
	require.NoError(f.t, os.Remove(filepath.Join(f.ctl, name)))
}

// run is one start of a tunnel, as the fake recorded it.
type fakeRun struct {
	N           int      `json:"n"`
	Args        []string `json:"args"`
	Env         []string `json:"env"`
	HomeEntries int      `json:"homeEntries"`
	Pid         int      `json:"pid"`
}

func (r fakeRun) env(key string) string { return envValue(r.Env, key) }

func (f *fakeBin) runs() []fakeRun {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.ctl, "runs.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(f.t, err)
	var out []fakeRun
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r fakeRun
		require.NoError(f.t, json.Unmarshal([]byte(l), &r))
		out = append(out, r)
	}
	return out
}

// eventually polls cond until it holds or ten seconds pass.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
