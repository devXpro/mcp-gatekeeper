package adminsock

import (
	"errors"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// peerUID returns the user id of the process on the other end of a unix socket connection (SO_PEERCRED).
func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		var cred *unix.Ucred
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credErr == nil {
			uid = int(cred.Uid)
		}
	}); err != nil {
		return -1, err
	}
	return uid, credErr
}

// peerProcess returns the pid of the process on the other end (SO_PEERCRED) and the path of its executable
// (/proc/<pid>/exe). Best effort: 0 and "" when unknown.
func peerProcess(c net.Conn) (int, string) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, ""
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, ""
	}
	pid := 0
	if err := raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			pid = int(cred.Pid)
		}
	}); err != nil || pid <= 0 {
		return 0, ""
	}
	return pid, exePath(pid)
}

// exePath reads the executable path of pid from /proc.
func exePath(pid int) string {
	path, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ""
	}
	return path
}

// peerChain names up to three ancestors of pid (ancestry).
func peerChain(pid int) string { return ancestry(pid, procInfo) }

// procInfo reads one process from /proc/<pid>/stat: its parent, and its executable path (exePath) or, when /proc does
// not show that (a process of another user), its short command name.
func procInfo(pid int) (int, string, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, "", false
	}
	ppid, comm, ok := parseProcStat(b)
	if !ok {
		return 0, "", false
	}
	name := exePath(pid)
	if name == "" {
		name = comm
	}
	return ppid, name, true
}
