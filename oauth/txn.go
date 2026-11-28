package oauth

import (
	"sync"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// txn is an authorization request waiting for the consent screen: it lives in memory for 10 minutes and is used
// once, by approve or deny.
type txn struct {
	clientID    core.ClientID
	clientKind  core.ClientKind
	assistant   core.Assistant
	clientName  string
	redirectURI string
	state       string
	challenge   string
	scope       string // the scope a grant gets
	resource    core.ResourceID
	resourceURL string // the resource's canonical RFC 8707 resource
	startedFrom string // where the browser came from: startedAssistant, startedElsewhere, startedUnknown or startedApp
	group       string // the client address group of authorize (addressKey)
	binding     []byte // the sha256 of the browser's binding cookie; nil while binding is off
	expiresAt   time.Time
	seq         uint64 // the order of arrival, set by the store
}

// txnStore keeps the transactions of the process: at most max in all, perGroup of one client address group and
// perClient of one DCR client (T2.R M1). A new transaction always gets in. Over a bound, the oldest transaction of
// that address group or client goes; in a full store, the oldest of the address group holding the most. A flood
// from a few addresses, or with a few clients, only ever pushes out its own transactions.
type txnStore struct {
	mu                       sync.Mutex
	max, perGroup, perClient int
	seq                      uint64
	items                    map[string]txn
}

func newTxnStore(limit, perGroup, perClient int) *txnStore {
	return &txnStore{max: limit, perGroup: perGroup, perClient: perClient, items: map[string]txn{}}
}

// add keeps t under a new id, making room as the bounds say.
func (s *txnStore) add(t txn, now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, x := range s.items {
		if !now.Before(x.expiresAt) {
			delete(s.items, id)
		}
	}
	s.makeRoom(func(x txn) bool { return x.group == t.group }, s.perGroup)
	if t.clientKind == core.ClientDCR {
		s.makeRoom(func(x txn) bool { return x.clientID == t.clientID }, s.perClient)
	}
	for len(s.items) >= s.max {
		largest := s.largestGroup()
		if !s.evictOldest(func(x txn) bool { return x.group == largest }) {
			break
		}
	}
	s.seq++
	t.seq = s.seq
	id := core.NewID(core.PrefixTxn)
	s.items[id] = t
	return id
}

// makeRoom drops the oldest transactions that match until fewer than limit do. s.mu is held.
func (s *txnStore) makeRoom(match func(txn) bool, limit int) {
	n := 0
	for _, x := range s.items {
		if match(x) {
			n++
		}
	}
	for ; n >= limit; n-- {
		if !s.evictOldest(match) {
			return
		}
	}
}

// evictOldest drops the oldest transaction that matches and reports whether there was one. s.mu is held.
func (s *txnStore) evictOldest(match func(txn) bool) bool {
	oldest, found := "", false
	for id, x := range s.items {
		if match(x) && (!found || x.seq < s.items[oldest].seq) {
			oldest, found = id, true
		}
	}
	delete(s.items, oldest)
	return found
}

// largestGroup is the address group holding the most transactions; of groups holding as many, the one with the
// oldest transaction. s.mu is held.
func (s *txnStore) largestGroup() string {
	type tally struct {
		n      int
		oldest uint64
	}
	groups := map[string]tally{}
	for _, x := range s.items {
		g := groups[x.group]
		if g.n == 0 || x.seq < g.oldest {
			g.oldest = x.seq
		}
		g.n++
		groups[x.group] = g
	}
	var (
		largest string
		top     tally
	)
	for name, g := range groups {
		if g.n > top.n || (g.n == top.n && g.oldest < top.oldest) {
			largest, top = name, g
		}
	}
	return largest
}

// get returns the live transaction id.
func (s *txnStore) get(id string, now time.Time) (txn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.items[id]
	if ok && !now.Before(t.expiresAt) {
		delete(s.items, id)
		return txn{}, false
	}
	return t, ok
}

// take removes and returns the live transaction id: of two calls, one gets it.
func (s *txnStore) take(id string, now time.Time) (txn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.items[id]
	delete(s.items, id)
	if !ok || !now.Before(t.expiresAt) {
		return txn{}, false
	}
	return t, true
}

// restore puts back a transaction that take returned but whose approval was refused before anything was written,
// so it can be answered again.
func (s *txnStore) restore(id string, t txn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[id] = t
}
