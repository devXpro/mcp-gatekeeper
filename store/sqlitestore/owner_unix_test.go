//go:build unix

package sqlitestore

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// dirInfo is a directory as os.Stat would show it, owned by uid.
type dirInfo struct{ uid uint32 }

func (dirInfo) Name() string       { return "data" }
func (dirInfo) Size() int64        { return 0 }
func (dirInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o755 }
func (dirInfo) ModTime() time.Time { return time.Time{} }
func (dirInfo) IsDir() bool        { return true }
func (d dirInfo) Sys() any         { return &syscall.Stat_t{Uid: d.uid} }

// Whether a directory is the database's own to chmod (review R-8): the process user's, holding only its files.
func TestSharedDir(t *testing.T) {
	me := uint32(os.Geteuid()) //nolint:gosec // G115: a uid fits
	db := []string{"app.db", "app.db-wal", "app.db-shm", "app.db-journal"}
	for _, tc := range []struct {
		name  string
		info  fs.FileInfo
		names []string
		want  string
	}{
		{name: "empty and mine", info: dirInfo{uid: me}, want: ""},
		{name: "only the database's files", info: dirInfo{uid: me}, names: db, want: ""},
		{name: "another user's", info: dirInfo{uid: me + 1}, names: db, want: "it belongs to another user"},
		{name: "another file", info: dirInfo{uid: me}, names: []string{"app.db", "config.yaml"},
			want: "it holds other files (config.yaml)"},
		{name: "another database", info: dirInfo{uid: me}, names: []string{"other.db"},
			want: "it holds other files (other.db)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sharedDir(tc.info, tc.names, "app.db"))
		})
	}
}
