package storetest

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func testAudit(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	var want []core.AuditEntry
	for i := range 7 {
		e := core.AuditEntry{At: now, AccountID: "acc_a", Actor: "per_a", Action: fmt.Sprintf("test.n%d", i), Target: "t",
			Detail: map[string]string{"i": fmt.Sprint(i)}, IP: "203.0.113.5"}
		if i%2 == 1 {
			e.AccountID = "" // a system event
		}
		require.NoError(t, s.Audit().Append(ctx, e))
		want = append(want, e)
	}
	// Account a has entries 0, 2, 4, 6; newest first, two per page.
	p1, err := s.Audit().ListByAccount(ctx, "acc_a", "", 2)
	require.NoError(t, err)
	require.Len(t, p1, 2)
	assert.Equal(t, []string{"test.n6", "test.n4"}, []string{p1[0].Action, p1[1].Action})
	assert.NotEmpty(t, p1[0].ID, "the store assigns the id")
	got := p1[0]
	got.ID = ""
	assert.Equal(t, want[6], got, "an entry reads back as written")

	p2, err := s.Audit().ListByAccount(ctx, "acc_a", p1[1].ID, 2)
	require.NoError(t, err)
	require.Len(t, p2, 2)
	assert.Equal(t, []string{"test.n2", "test.n0"}, []string{p2[0].Action, p2[1].Action})
	p3, err := s.Audit().ListByAccount(ctx, "acc_a", p2[1].ID, 2)
	require.NoError(t, err)
	assert.Empty(t, p3)

	sys, err := s.Audit().ListSystem(ctx, "", 10)
	require.NoError(t, err)
	require.Len(t, sys, 3)
	assert.Equal(t, []string{"test.n5", "test.n3", "test.n1"}, []string{sys[0].Action, sys[1].Action, sys[2].Action})
	for _, e := range sys {
		assert.Empty(t, e.AccountID)
	}
	sys2, err := s.Audit().ListSystem(ctx, sys[0].ID, 10)
	require.NoError(t, err)
	assert.Len(t, sys2, 2, "the system list pages the same way")

	other, err := s.Audit().ListByAccount(ctx, "acc_other", "", 10)
	require.NoError(t, err)
	assert.Empty(t, other)

	// The ids are distinct.
	all, err := s.Audit().ListByAccount(ctx, "acc_a", "", 10)
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, e := range append(all, sys...) {
		ids[e.ID] = true
	}
	assert.Len(t, ids, 7)

	// Append ignores the caller's id, and the optional fields may be empty.
	bare := core.AuditEntry{ID: "chosen-by-caller", At: now, Action: "test.bare"}
	require.NoError(t, s.Audit().Append(ctx, bare))
	sys, err = s.Audit().ListSystem(ctx, "", 1)
	require.NoError(t, err)
	require.Len(t, sys, 1)
	assert.NotEqual(t, "chosen-by-caller", sys[0].ID)
	assert.Equal(t, "test.bare", sys[0].Action)
	assert.Empty(t, sys[0].Detail)
	assert.Empty(t, sys[0].Actor)
	assert.Empty(t, sys[0].Target)
	assert.Empty(t, sys[0].IP)

	_, err = s.Audit().ListByAccount(ctx, "acc_a", "not-an-id", 2)
	assert.Error(t, err, "a cursor that is not an audit id is an error")
	_, err = s.Audit().ListSystem(ctx, "zz", 2)
	assert.Error(t, err)
}

func testAuditLimits(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	require.NoError(t, s.Tx(ctx, func(ctx context.Context) error {
		for i := range 1001 {
			if err := s.Audit().Append(ctx, core.AuditEntry{At: now, AccountID: "acc_a", Action: fmt.Sprintf("test.n%d", i)}); err != nil {
				return err
			}
		}
		return nil
	}))
	for _, tt := range []struct {
		limit, want int
	}{{0, 50}, {-1, 50}, {7, 7}, {1000, 1000}, {5000, 1000}} {
		list, err := s.Audit().ListByAccount(ctx, "acc_a", "", tt.limit)
		require.NoError(t, err)
		assert.Len(t, list, tt.want, "limit %d", tt.limit)
	}
	list, err := s.Audit().ListByAccount(ctx, "acc_a", "", 3)
	require.NoError(t, err)
	assert.Equal(t, []string{"test.n1000", "test.n999", "test.n998"}, []string{list[0].Action, list[1].Action, list[2].Action})
}
