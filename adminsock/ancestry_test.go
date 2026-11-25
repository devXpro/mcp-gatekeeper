package adminsock

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProc is one process of a fake process table.
type fakeProc struct {
	ppid int
	name string
}

func fakeLookup(table map[int]fakeProc) procLookup {
	return func(pid int) (int, string, bool) {
		p, ok := table[pid]
		return p.ppid, p.name, ok
	}
}

// The chain names up to three ancestors, nearest first, and ends quietly where the table does (review R-5).
func TestAncestry(t *testing.T) {
	desktop := map[int]fakeProc{
		500: {ppid: 41, name: "/home/user/app/bin/app"},
		41:  {ppid: 40, name: "/bin/zsh"},
		40:  {ppid: 12, name: "login"}, // a process of another user: its short name only
		12:  {ppid: 1, name: "/usr/bin/terminal"},
		1:   {ppid: 0, name: "/sbin/launchd"},
	}
	for _, tc := range []struct {
		name  string
		table map[int]fakeProc
		pid   int
		want  string
	}{
		{name: "three ancestors at most", table: desktop, pid: 500,
			want: "/bin/zsh (pid 41) < login (pid 40) < /usr/bin/terminal (pid 12)"},
		{name: "a short chain ends at pid 0", table: desktop, pid: 12, want: "/sbin/launchd (pid 1)"},
		{name: "the first process has no parent", table: desktop, pid: 1, want: ""},
		{name: "the peer itself is gone", table: desktop, pid: 999, want: ""},
		{name: "a parent that is gone ends the chain", pid: 500, want: "/bin/sh (pid 41)",
			table: map[int]fakeProc{500: {ppid: 41}, 41: {ppid: 40, name: "/bin/sh"}}},
		{name: "a parent without a name ends the chain", pid: 500, want: "/bin/sh (pid 41)",
			table: map[int]fakeProc{500: {ppid: 41}, 41: {ppid: 40, name: "/bin/sh"}, 40: {ppid: 1}}},
		{name: "a loop ends the chain", pid: 500, want: "/bin/a (pid 41) < /bin/b (pid 40)",
			table: map[int]fakeProc{500: {ppid: 41}, 41: {ppid: 40, name: "/bin/a"}, 40: {ppid: 41, name: "/bin/b"}}},
		{name: "a parent of itself", pid: 500, want: "",
			table: map[int]fakeProc{500: {ppid: 500, name: "/bin/a"}}},
		{name: "in a container the CLI's parent is pid 0", pid: 77, want: "",
			table: map[int]fakeProc{77: {ppid: 0, name: "/usr/local/bin/hub"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ancestry(tc.pid, fakeLookup(tc.table)))
		})
	}
}

func TestParseProcStat(t *testing.T) {
	for _, tc := range []struct {
		line string
		ppid int
		comm string
		ok   bool
	}{
		{line: "4242 (bash) S 4241 4242 4241 34816 4300 4194304 1 2 3", ppid: 4241, comm: "bash", ok: true},
		{line: "4242 (a (b) c) R 17 4242", ppid: 17, comm: "a (b) c", ok: true},
		{line: "1 (init) S 0 1 1 0 -1", ppid: 0, comm: "init", ok: true},
		{line: "4242 (bash) S", ok: false},
		{line: "4242 (bash) S x", ok: false},
		{line: "4242 bash S 1", ok: false},
		{line: "", ok: false},
	} {
		ppid, comm, ok := parseProcStat([]byte(tc.line + "\n"))
		assert.Equal(t, tc.ok, ok, tc.line)
		if tc.ok {
			assert.Equal(t, tc.ppid, ppid, tc.line)
			assert.Equal(t, tc.comm, comm, tc.line)
		}
	}
}

// The real chain of this test process: its parent (the go command, under go test) comes first, and every link
// names an existing executable or a short command name.
func TestPeerChainOfThisProcess(t *testing.T) {
	chain := peerChain(os.Getpid())
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		assert.Empty(t, chain)
		return
	}
	require.NotEmpty(t, chain)
	t.Logf("peer chain: %s", chain)
	links := strings.Split(chain, " < ")
	require.LessOrEqual(t, len(links), chainDepth)
	first := fmt.Sprintf(" (pid %d)", os.Getppid())
	require.True(t, strings.HasSuffix(links[0], first), "the nearest ancestor is the parent: %q", chain)
	for _, l := range links {
		open := strings.LastIndex(l, " (pid ")
		require.Positive(t, open, l)
		if name := l[:open]; filepath.IsAbs(name) {
			assert.FileExists(t, name)
		}
	}
}
