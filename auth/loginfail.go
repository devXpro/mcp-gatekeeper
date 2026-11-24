package auth

import (
	"context"
	"strconv"
	"sync"
	"time"

	"net/http"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// Failed sign-ins are system audit entries that anybody on the internet can cause, so they are coalesced (T2.R L8):
// at most one auth.login.fail entry per address group (an IPv4 address or an IPv6 /64) a minute, whose detail
// "count" is the number of failures since the group's previous entry. The first failure of a quiet group is written
// at once; the ones after it in the same minute are counted and written with the group's next failure after the
// minute, or by the flush that runs every minute (and on Stop). The entry's IP is the address group.
const (
	failWindow    = time.Minute
	maxFailGroups = maxBuckets // more groups than this in one minute share one entry without an address
	failOverflow  = "*"        // the group of that overflow
)

// failedLogins counts the failures of every address group that failed in the last minute.
type failedLogins struct {
	mu sync.Mutex
	m  map[string]*failCount
}

type failCount struct {
	until   time.Time // the end of the minute that the group's last entry opened
	pending int       // failures since that entry
}

// failedSince is what one group's entry reports.
type failedSince struct {
	group string
	count int
}

func newFailedLogins() *failedLogins { return &failedLogins{m: map[string]*failCount{}} }

// note counts one failure of group and reports whether an entry is due now, with its group (the overflow one when the
// map is full) and count.
func (f *failedLogins) note(group string, now time.Time) (failedSince, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.m[group]; !ok && len(f.m) >= maxFailGroups {
		f.dropQuietLocked(now)
		if len(f.m) >= maxFailGroups {
			group = failOverflow
		}
	}
	w, ok := f.m[group]
	if !ok {
		f.m[group] = &failCount{until: now.Add(failWindow)}
		return failedSince{group: group, count: 1}, true
	}
	if now.Before(w.until) {
		w.pending++
		return failedSince{}, false
	}
	n := w.pending + 1
	w.until, w.pending = now.Add(failWindow), 0
	return failedSince{group: group, count: n}, true
}

// dropQuietLocked forgets the groups whose minute is over and that have nothing to report. f.mu is held.
func (f *failedLogins) dropQuietLocked(now time.Time) {
	for g, w := range f.m {
		if !now.Before(w.until) && w.pending == 0 {
			delete(f.m, g)
		}
	}
}

// due takes the groups whose minute is over (every group, with all) and returns those with failures to report.
func (f *failedLogins) due(now time.Time, all bool) []failedSince {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []failedSince
	for g, w := range f.m {
		if !all && now.Before(w.until) {
			continue
		}
		if w.pending > 0 {
			out = append(out, failedSince{group: g, count: w.pending})
		}
		delete(f.m, g)
	}
	return out
}

// loginFailed answers a sign-in that did not verify and audits it as a system event: the person is not known for sure,
// and an attacker must not be able to fill a family's audit. The entry is coalesced per address group.
func (a *Auth) loginFailed(w http.ResponseWriter, r *http.Request) {
	now := a.now()
	if f, ok := a.fails.note(addressKey(a.clientIP(r)), now); ok {
		a.auditLoginFails(r.Context(), now, f)
	}
	a.fail(w, r, errNotVerified)
}

// flushLoginFails writes the counted failures of the groups whose minute is over, or of every group with all.
func (a *Auth) flushLoginFails(ctx context.Context, all bool) {
	now := a.now()
	for _, f := range a.fails.due(now, all) {
		a.auditLoginFails(ctx, now, f)
	}
}

func (a *Auth) auditLoginFails(ctx context.Context, at time.Time, f failedSince) {
	ip := f.group
	if ip == failOverflow {
		ip = ""
	}
	a.audit(ctx, core.AuditEntry{At: at, Action: "auth.login.fail", IP: ip,
		Detail: map[string]string{"count": strconv.Itoa(f.count)}})
}
