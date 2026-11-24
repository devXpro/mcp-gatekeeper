package sqlitestore_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/store"
	"github.com/devXpro/mcp-gatekeeper/store/sqlitestore"
	"github.com/devXpro/mcp-gatekeeper/store/storetest"
)

// open returns a new store on a file in the test's temporary directory.
func open(t *testing.T, o sqlitestore.Options) *sqlitestore.Store {
	t.Helper()
	if o.Path == "" {
		o.Path = filepath.Join(t.TempDir(), "gatekeeper.db")
	}
	s, err := sqlitestore.Open(t.Context(), o)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T, cascades ...store.Cascade) store.Store {
		return open(t, sqlitestore.Options{Cascades: cascades})
	})
}
