package marshal

import (
	"context"
	"io"
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/limits"
)

type bodyLimitKey struct{}

// LimitRequestBody bounds reads from request bodies. Zero selects
// limits.DefaultMaxRequestBody; a negative value disables the limit.
// It writes no response itself, so it can wrap CORS, correlation, logging
// and metrics middleware without bypassing them: a body whose known
// Content-Length exceeds the limit fails on its first read with
// *http.MaxBytesError without reading any bytes, and other bodies fail once
// they exceed the limit. DecodeBody honors this policy and writes HTTP 413;
// other body readers must handle *http.MaxBytesError themselves.
func LimitRequestBody(next http.Handler, maxBytes int64) http.Handler {
	if maxBytes == 0 {
		maxBytes = limits.DefaultMaxRequestBody
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limitRequestBody(w, r, maxBytes)
		r = r.WithContext(context.WithValue(r.Context(), bodyLimitKey{}, maxBytes))
		next.ServeHTTP(w, r)
	})
}

func limitRequestBody(w http.ResponseWriter, r *http.Request, maxBytes int64) {
	if maxBytes < 0 || r.Body == nil {
		return
	}
	if r.ContentLength > maxBytes {
		r.Body = &oversizedBody{ReadCloser: r.Body, limit: maxBytes}
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
}

// oversizedBody fails every read of a body whose declared length exceeds
// the limit, without reading it; net/http closes the connection when the
// unread remainder is too large to drain.
type oversizedBody struct {
	io.ReadCloser
	limit int64
}

func (b *oversizedBody) Read([]byte) (int, error) {
	return 0, &http.MaxBytesError{Limit: b.limit}
}

func requestTooLarge(err error) error {
	return httperror.RequestTooLarge("request body exceeds the configured limit").WithCause(errors.WithStack(err))
}
