//go:build unix

package sqlitestore

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByProcessUser reports whether the file belongs to the user the process runs as.
func ownedByProcessUser(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(os.Geteuid())
}
