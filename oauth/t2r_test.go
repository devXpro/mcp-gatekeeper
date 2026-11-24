package oauth

// The proofs of concept of Family Hub's security review T2.R, turned into regression tests: each walks the attack of
// its PoC and asserts that it fails now.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestT2R_ConsentLinkPhishing is H1. The attacker registers a client with the per-connector callback of a ChatGPT
// connector of their own, starts the flow in their own browser, and sends the /consent?txn=… link to Bob, who is
// signed in. The PoC got Bob's tokens for notes. Now the link is refused in Bob's browser; the authorize-link
// variant, which starts in his own browser, warns and asks for a fresh passkey; and with RefuseConnectorCallback the
// attacker's client cannot register at all.
func TestT2R_ConsentLinkPhishing(t *testing.T) {
	h := newHarness(t)
	const attackerCallback = "https://chatgpt.com/connector/oauth/attacker-controlled-connector"
	attacker := h.registerDCR(attackerCallback, authNone)
	_, challenge := newPKCE()
	authorizeURL := "/oauth/authorize?" + authorizeParams(attacker, "notes", challenge).Encode()

	// The attacker's browser, without any session, starts the flow and keeps the consent link.
	w := h.doIn(newBrowser(), httptest.NewRequest(http.MethodGet, authorizeURL, nil))
	require.Equal(t, http.StatusFound, w.Code)
	txnID, ok := strings.CutPrefix(w.Header().Get("Location"), "/consent?txn=")
	require.True(t, ok)

	// 1. Bob opens the link in his browser, where he is signed in: the screen, Allow and Deny are all refused.
	bobBrowser := newBrowser()
	for _, call := range []struct{ method, path string }{
		{http.MethodGet, "/api/oauth/txn/" + txnID},
		{http.MethodPost, "/api/oauth/txn/" + txnID + "/approve"},
		{http.MethodPost, "/api/oauth/txn/" + txnID + "/deny"},
	} {
		w := h.consentIn(bobBrowser, call.method, call.path, "bob")
		assert.Equal(t, http.StatusForbidden, w.Code, call.path)
		assert.Equal(t, "other_browser", errorOf(t, w), call.path)
	}
	assert.Empty(t, h.store.grantList(), "no grant of Bob's for the attacker's client")
	assert.Zero(t, h.store.codeCount(), "no code went to the attacker's callback")

	// 2. The authorize link instead: Bob's own browser starts the transaction, opened from a messenger.
	r := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	r.Header.Set("Sec-Fetch-Site", "none")
	w = h.doIn(bobBrowser, r)
	require.Equal(t, http.StatusFound, w.Code)
	linked, _ := strings.CutPrefix(w.Header().Get("Location"), "/consent?txn=")
	var view txnView
	v := h.consentIn(bobBrowser, http.MethodGet, "/api/oauth/txn/"+linked, "bob")
	require.Equal(t, http.StatusOK, v.Code, v.Body.String())
	decode(t, v, &view)
	assert.Equal(t, "elsewhere", view.StartedFrom, "the screen warns in red")
	assert.Equal(t, "dcr", string(view.ClientKind), "and marks the client's name as self-declared")
	assert.False(t, view.AlreadyGranted)
	// Bob signed in a while ago: his Allow asks for his passkey first, so the phished click is a Face ID prompt.
	h.sessions.setStale("bob", true)
	w = h.consentIn(bobBrowser, http.MethodPost, "/api/oauth/txn/"+linked+"/approve", "bob")
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "step_up_required", errorOf(t, w))
	assert.Empty(t, h.store.grantList())

	// 3. With RefuseConnectorCallback, the mix-up's callback is refused at registration.
	strict := newHarnessWith(t, func(o *Options) { o.RefuseConnectorCallback = true })
	w = strict.registerJSON(map[string]any{"redirect_uris": []string{attackerCallback}})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_redirect_uri", errorOf(t, w))
}

// junkToken sends a token request of a client that does not exist from addr.
func (h *harness) junkToken(addr string) int {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {"cli_aaaaaaaaaaaaaaaa"}}
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = addr
	return h.do(r).Code
}

// TestT2R_TokenTotalBucketDoS is H2. Three addresses of one IPv6 /64 sent 20 junk token requests each, which spent
// the bucket every client shared, and a real refresh from a fourth address got 429. Now the three addresses are one
// /64 bucket, and token and revoke have no shared bucket at all.
func TestT2R_TokenTotalBucketDoS(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authNone)
	tk := h.connect(tc, "alice", "notes")

	statuses := map[int]int{}
	for i := 1; i <= 3; i++ {
		for range 20 {
			statuses[h.junkToken(fmt.Sprintf("[2001:db8:1:2::%x]:443", i))]++
		}
	}
	assert.Equal(t, map[int]int{
		http.StatusUnauthorized: limitPerAddress, http.StatusTooManyRequests: 60 - limitPerAddress,
	}, statuses, "the flood's addresses share the bucket of their /64")

	// Three IPv4 addresses get 20 each, 60 in all: a shared bucket of 60 a minute would be spent now.
	statuses = map[int]int{}
	for i := 1; i <= 3; i++ {
		for range 20 {
			statuses[h.junkToken(fmt.Sprintf("203.0.113.%d:443", i))]++
		}
	}
	assert.Equal(t, map[int]int{http.StatusUnauthorized: 60}, statuses, "no bucket is shared by every address")

	send := func(path string, form url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "198.51.100.7:443" // ChatGPT's egress, never seen before
		return h.do(r)
	}
	w := send("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken},
		"client_id": {tc.id}})
	require.Equal(t, http.StatusOK, w.Code, "the real refresh goes through: %s", w.Body.String())
	var next tokens
	decode(t, w, &next)

	// Revoke the same: more junk from three IPv4 addresses, then the real revoke.
	for i := 1; i <= 3; i++ {
		for range 20 {
			r := httptest.NewRequest(http.MethodPost, "/oauth/revoke",
				strings.NewReader(url.Values{"token": {"x"}, "client_id": {"cli_aaaaaaaaaaaaaaaa"}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.RemoteAddr = fmt.Sprintf("203.0.113.%d:443", i)
			h.do(r)
		}
	}
	w = send("/oauth/revoke", url.Values{"token": {next.RefreshToken}, "client_id": {tc.id}})
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.False(t, h.valid(next.AccessToken, "notes"), "and it revoked")
}

// TestT2R_TxnStoreFill is M1. 1000 authorize requests from one IPv6 /64 filled the pending transactions, and every
// family's next connector got temporarily_unavailable. Now a /64 is one address group that makes 20 a minute and
// keeps its newest 20, and even 50 IPv4 addresses filling the whole store with ChatGPT's shared client id only push
// out their own transactions.
func TestT2R_TxnStoreFill(t *testing.T) {
	h := newHarness(t)
	attacker := h.registerDCR(chatgptCallback, authNone)
	_, challenge := newPKCE()
	q := authorizeParams(attacker, "notes", challenge).Encode()
	attackerBrowser := newBrowser()
	burst := func(n int) map[int]int {
		statuses := map[int]int{}
		for i := 1; i <= n; i++ {
			r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q, nil)
			r.RemoteAddr = fmt.Sprintf("[2001:db8:1:2::%x]:443", i)
			statuses[h.doIn(attackerBrowser, r).Code]++
		}
		return statuses
	}
	assert.Equal(t, map[int]int{http.StatusFound: limitPerAddress, http.StatusTooManyRequests: maxTxns - limitPerAddress},
		burst(maxTxns), "the PoC's burst: one /64 is one address group")
	for range 8 { // the rest of the 10 minutes a transaction lives, at the group's rate
		h.clock.advance(time.Minute)
		assert.Equal(t, map[int]int{http.StatusFound: limitPerAddress}, burst(limitPerAddress))
	}
	assert.Equal(t, maxTxnsPerGroup, h.srv.txns.count(), "the group keeps only its newest 20")

	legit := h.registerDCR(claudeCallback, authNone)
	_, challenge2 := newPKCE()
	w := h.authorize(authorizeParams(legit, "notes", challenge2))
	require.Equal(t, http.StatusFound, w.Code)
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "/consent?txn="), w.Header().Get("Location"))

	// Fifty IPv4 addresses, 20 each, with ChatGPT's client id (shared by all its users, so it has no cap of its own).
	h = newHarness(t)
	pending := h.authorizeFrom("192.0.2.50:1", h.cimdClient(claudeDocument, claudeCallback), "notes")
	shared := h.cimdClient(chatgptDocument, chatgptCallback)
	for i := range maxTxns {
		h.authorizeFrom(fmt.Sprintf("198.18.0.%d:1", 1+i/limitPerAddress), shared, "notes")
	}
	assert.Equal(t, maxTxns, h.srv.txns.count(), "the store is full")
	next := h.authorizeFrom("192.0.2.1:1", h.registerDCR(claudeCallback, authNone), "photos")
	assert.Equal(t, []bool{true, true}, h.live(pending, next),
		"a family's waiting consent stays and the next one gets in")
}
