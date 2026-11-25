package adminsock

import (
	"bytes"
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the user id of the process on the other end of a unix socket connection (LOCAL_PEERCRED).
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
		var cred *unix.Xucred
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr == nil {
			uid = int(cred.Uid)
		}
	}); err != nil {
		return -1, err
	}
	return uid, credErr
}

// peerProcess returns the pid of the process on the other end (LOCAL_PEERPID) and the path of its executable (the
// exec path at the head of sysctl kern.procargs2, which the kernel gives a process of the same user or root). Best
// effort: 0 and "" when unknown.
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
		if v, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
			pid = v
		}
	}); err != nil || pid <= 0 {
		return 0, ""
	}
	return pid, exePath(pid)
}

// exePath reads the executable path of pid from kern.procargs2: a 32-bit argc, then the path, NUL-terminated.
func exePath(pid int) string {
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(b) <= 4 {
		return ""
	}
	path, _, _ := bytes.Cut(b[4:], []byte{0})
	return string(path)
}

// peerChain names up to three ancestors of pid (ancestry).
func peerChain(pid int) string { return ancestry(pid, procInfo) }

// procInfo reads one process from sysctl kern.proc.pid: its parent, and its executable path (exePath) or, when the
// kernel does not show that (a process of another user, e.g. root's login), its short command name.
func procInfo(pid int) (int, string, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(kp.Proc.P_pid) != pid {
		return 0, "", false
	}
	name := exePath(pid)
	if name == "" {
		name = unix.ByteSliceToString(kp.Proc.P_comm[:])
	}
	return int(kp.Eproc.Ppid), name, true
}
