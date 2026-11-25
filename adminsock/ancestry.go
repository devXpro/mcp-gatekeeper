package adminsock

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// chainDepth is how many ancestors of the peer process the chain names.
const chainDepth = 3

// procLookup tells, for one process, its parent's pid and a name for it: its executable path when the kernel shows it,
// else its short command name. ok is false when the process is gone or cannot be read.
type procLookup func(pid int) (ppid int, name string, ok bool)

// ancestry names up to chainDepth ancestors of pid, nearest first, as "<name> (pid N)" joined by " < " (e.g. the
// shell, then the terminal). Best effort: a parent that cannot be read, pid 0 and a loop end the chain; "" when the
// first parent is already unknown.
func ancestry(pid int, lookup procLookup) string {
	ppid, _, ok := lookup(pid)
	seen := map[int]bool{pid: true}
	var links []string
	for ok && ppid > 0 && !seen[ppid] && len(links) < chainDepth {
		next, name, found := lookup(ppid)
		if !found || name == "" {
			break
		}
		links = append(links, fmt.Sprintf("%s (pid %d)", name, ppid))
		seen[ppid] = true
		ppid = next
	}
	return strings.Join(links, " < ")
}

// parseProcStat reads the parent pid and the command name out of a Linux /proc/<pid>/stat line:
// "pid (comm) state ppid …". The command name may itself hold spaces and parentheses, so it ends at the last ')'.
func parseProcStat(b []byte) (ppid int, comm string, ok bool) {
	open, end := bytes.IndexByte(b, '('), bytes.LastIndexByte(b, ')')
	if open < 0 || end < open {
		return 0, "", false
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 2 {
		return 0, "", false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil || ppid < 0 {
		return 0, "", false
	}
	return ppid, string(b[open+1 : end]), true
}
