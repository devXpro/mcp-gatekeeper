package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"log/slog"
	"net/http"
)

// pageText is the message of an error page, in Russian and English.
type pageText struct{ RU, EN string }

// Messages of the authorize error pages: errors found before the client's redirect URI is known.
var (
	pageBadRequest = pageText{
		RU: "Запрос на подключение неверен. Начните подключение в ассистенте заново.",
		EN: "The connection request is invalid. Start connecting in the assistant again.",
	}
	pageUnknownClient = pageText{
		RU: "Это подключение не зарегистрировано. Удалите его в ассистенте и добавьте заново.",
		EN: "This connection is not registered. Remove it in the assistant and add it again.",
	}
	pageBadRedirect = pageText{
		RU: "Адрес возврата не зарегистрирован для этого подключения.",
		EN: "This callback was not registered for the connection.",
	}
	pageMetadataFetch = pageText{
		RU: "Не удалось получить описание клиента от ассистента. Попробуйте ещё раз.",
		EN: "The assistant's client description could not be fetched. Try again.",
	}
	pageMetadataInvalid = pageText{
		RU: "Описание клиента от ассистента не подходит этому хабу.",
		EN: "The assistant's client description does not fit this hub.",
	}
	pageRateLimited = pageText{
		RU: "Слишком много попыток. Подождите минуту и попробуйте снова.",
		EN: "Too many attempts. Wait a minute and try again.",
	}
	pageServerError = pageText{
		RU: "На сервере что-то пошло не так. Попробуйте позже.",
		EN: "Something went wrong on the server. Try again later.",
	}
)

// pageData is what the page template shows: the product's name as the title and the message.
type pageData struct {
	Product string
	RU, EN  string
}

// pageCSS is the page's only style. The CSP allows it by its hash, so the page needs no 'unsafe-inline'.
const pageCSS = `body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;` +
	`background:#000;color:#f2f2f2;font:16px -apple-system,system-ui,sans-serif}main{width:min(420px,88vw)}` +
	`h1{font-size:22px;margin:0 0 10px}p{color:#9a9a9a;margin:0 0 24px;line-height:1.45}`

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Product}}</title><style>` + pageCSS + `</style></head>
<body><main><h1>Не удалось подключить</h1><p>{{.RU}}</p><h1 lang="en">Cannot connect</h1><p lang="en">{{.EN}}</p></main></body></html>
`))

// pageCSP lets the page load nothing but its own style.
var pageCSP = "default-src 'none'; style-src '" + styleHash(pageCSS) + "'; base-uri 'none'; form-action 'none'; " +
	"frame-ancestors 'none'"

func styleHash(css string) string {
	sum := sha256.Sum256([]byte(css))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// page answers with an error page, for authorize errors that cannot go back to the client (RFC 6749 §4.1.2.1).
func (s *Server) page(w http.ResponseWriter, status int, text pageText) {
	var b bytes.Buffer
	if err := pageTemplate.Execute(&b, pageData{Product: s.product, RU: text.RU, EN: text.EN}); err != nil {
		s.log.Error("oauth: rendering an error page failed", slog.Any("error", err))
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", pageCSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
