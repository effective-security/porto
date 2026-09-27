package marshal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
)

func BenchmarkWriteJSON_Gzip(b *testing.B) {
	payload := struct{ Data string }{Data: strings.Repeat("x", 4096)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(header.AcceptEncoding, header.Gzip)
	b.ReportAllocs()
	for range b.N {
		WriteJSON(httptest.NewRecorder(), req, payload)
	}
}
