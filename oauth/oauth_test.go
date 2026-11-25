package oauth

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// validOptions are Options New accepts, with fakes behind them.
func validOptions() Options {
	return Options{
		Site:  core.Site{PublicURL: hubURL, RPID: "hub.example.com", ClientIP: core.ClientIPCloudflare},
		Brand: testBrand, Store: newFakeStore(), Sessions: &fakeSessions{}, Catalog: newFakeCatalog(),
		Paths: core.PerResource{Prefix: "/mcp/"},
	}
}

func TestNew(t *testing.T) {
	srv, err := New(validOptions())
	require.NoError(t, err)
	var (
		_ core.TokenValidator = srv
		_ core.RouteRegistrar = srv
	)
	assert.Equal(t, core.ClientIPCloudflare, srv.ipMode)
	assert.Equal(t, hubURL, srv.issuer)
	assert.Equal(t, "__Host-fh_txn", srv.txnCookie)
	assert.Equal(t, "family-hub", srv.realm)
	assert.Equal(t, []string{"module", "hub"}, []string{srv.noun, srv.app}, "the brand's default words")
	assert.Equal(t, pageMetadataInvalid, srv.badDoc)
	assert.Equal(t, settings{stepUp: true, binding: true, connector: true}, srv.cfg, "the zero switches are the defaults")
	assert.NotNil(t, srv.log, "a nil logger discards")
	assert.False(t, srv.now().IsZero(), "a nil clock is the system's")
	assert.Equal(t, "UTC", srv.now().Location().String())
	srv.RegisterRoutes(http.NewServeMux())

	o := validOptions()
	o.ConsentStepUpOff, o.TxnBindingOff, o.RefuseConnectorCallback = true, true, true
	srv, err = New(o)
	require.NoError(t, err)
	assert.Equal(t, settings{}, srv.cfg, "every switch turned")
}

func TestNewRefusesAPublicURLWithAPath(t *testing.T) {
	_, err := New(Options{Site: core.Site{PublicURL: hubURL + "/hub", ClientIP: core.ClientIPRemote}})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "not an issuer"), err)
}

func TestNewRefusesBadOptions(t *testing.T) {
	tests := []struct {
		name string
		edit func(o *Options)
		want string // a part of the error
	}{
		{"no store", func(o *Options) { o.Store = nil }, "Options.Store"},
		{"no sessions", func(o *Options) { o.Sessions = nil }, "Options.Sessions"},
		{"no catalog", func(o *Options) { o.Catalog = nil }, "Options.Catalog"},
		{"no paths", func(o *Options) { o.Paths = nil }, "Options.Paths"},
		{"no product", func(o *Options) { o.Brand.Product = " " }, "Options.Brand.Product"},
		{"no binding cookie", func(o *Options) { o.Brand.TxnCookie = "" }, "Options.Brand.TxnCookie"},
		{"a binding cookie without __Host-", func(o *Options) { o.Brand.TxnCookie = "fh_txn" }, "__Host-"},
		{"a binding cookie that is no name", func(o *Options) { o.Brand.TxnCookie = "__Host-fh txn" }, "__Host-"},
		{"a single resource whose id no URL can name", func(o *Options) {
			o.Paths = core.SingleResource{At: "/mcp", ID: "Home"}
		}, `"Home"`},
		// core.Site.Validate (review GK-2): an empty or unknown mode would make every client behind a local connector
		// one address.
		{"no client address mode", func(o *Options) { o.Site.ClientIP = "" }, "client address mode"},
		{"an unknown client address mode", func(o *Options) { o.Site.ClientIP = "cloudflare" }, `"cloudflare"`},
		{"an RP ID of another host", func(o *Options) { o.Site.RPID = "other.example.com" }, "RP ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := validOptions()
			tt.edit(&o)
			_, err := New(o)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}

	t.Run("no binding cookie when binding is off", func(t *testing.T) {
		o := validOptions()
		o.TxnBindingOff, o.Brand.TxnCookie = true, ""
		_, err := New(o)
		assert.NoError(t, err)
	})
}

func TestBasicRealm(t *testing.T) {
	for product, want := range map[string]string{
		"Family Hub":        "family-hub",
		"Homie":             "homie",
		" My  Home 2 ":      "my--home-2",
		`Evil" realm=x, ""`: "evil-realmx-",
		"Дом":               "oauth",
	} {
		assert.Equal(t, want, basicRealm(product), product)
	}
}

func TestPageStyleIsAllowedByItsHash(t *testing.T) {
	h := newHarness(t)
	w := h.get("/oauth/authorize", "")
	body := w.Body.String()
	start := strings.Index(body, "<style>")
	end := strings.Index(body, "</style>")
	require.True(t, start >= 0 && end > start, body)
	css := body[start+len("<style>") : end]
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "style-src '"+styleHash(css)+"'")
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'none'")
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
}

// TestPageBytes pins an error page to what Family Hub sent: its title came from the brand's product.
func TestPageBytes(t *testing.T) {
	h := newHarness(t)
	w := h.get("/oauth/authorize", "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Family Hub</title><style>`+pageCSS+`</style></head>
<body><main><h1>Не удалось подключить</h1><p>Запрос на подключение неверен. Начните подключение в ассистенте заново.</p>`+
		`<h1 lang="en">Cannot connect</h1><p lang="en">The connection request is invalid. Start connecting in the assistant again.</p>`+
		`</main></body></html>
`, w.Body.String())
	assert.Equal(t, "max-age=31536000", w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))

	// Another product's name is escaped like any text.
	other := newHarnessWith(t, func(o *Options) { o.Brand.Product = "<Homie>" })
	assert.Contains(t, other.get("/oauth/authorize", "").Body.String(), "<title>&lt;Homie&gt;</title>")
}
