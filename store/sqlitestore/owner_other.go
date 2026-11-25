//go:build !unix

package sqlitestore

import "io/fs"

// ownedByProcessUser cannot tell a file's owner on this platform, where a chmod only toggles the read-only bit anyway:
// the "nothing but the database's files" rule alone decides.
func ownedByProcessUser(fs.FileInfo) bool { return true }
