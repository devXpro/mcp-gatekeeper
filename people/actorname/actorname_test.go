package actorname_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/people/actorname"
	"github.com/devXpro/mcp-gatekeeper/people/internal/memstore"
)

func TestStampAndSplit(t *testing.T) {
	st := memstore.New()
	ctx := context.Background()
	require.NoError(t, st.Accounts().Create(ctx, core.Account{ID: "acc_1", Name: "A", CreatedAt: time.Now()}))
	require.NoError(t, st.People().Create(ctx, core.Person{ID: "per_1", AccountID: "acc_1", Name: "Alice",
		Role: core.RoleOwner, CreatedAt: time.Now()}))

	orig := map[string]string{"k": "v"}
	got := actorname.Stamp(ctx, st.People(), core.AuditEntry{Actor: "per_1", Action: "x", Detail: orig})
	assert.Equal(t, map[string]string{"k": "v", actorname.Key: "Alice"}, got.Detail)
	assert.Equal(t, map[string]string{"k": "v"}, orig, "the caller's map is untouched")

	name, detail := actorname.Split(got)
	assert.Equal(t, "Alice", name)
	assert.Equal(t, map[string]string{"k": "v"}, detail)

	// No actor, an unknown actor and an entry that already has a name stay as they are.
	for _, e := range []core.AuditEntry{
		{Action: "system"},
		{Actor: "per_ghost", Action: "x"},
		{Actor: "per_1", Action: "x", Detail: map[string]string{actorname.Key: "Old"}},
	} {
		assert.Equal(t, e, actorname.Stamp(ctx, st.People(), e))
	}
	name, detail = actorname.Split(core.AuditEntry{})
	assert.Empty(t, name)
	assert.NotNil(t, detail)
}
