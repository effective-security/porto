package marshal

import (
	"context"
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/limits"
)

type bodyLimitKey struct{}

// LimitRequestBody bounds reads from request bodies, rejecting a known
// oversized Content-Length with HTTP 413 before calling next. Zero selects
// limits.DefaultMaxRequestBody; a negative value disables the limit.
// DecodeBody honors this policy and writes HTTP 413 on overflow, including
// chunked bodies. Other body readers must handle *http.MaxBytesError themselves.
func LimitRequestBody(next http.Handler, maxBytes int64) http.Handler {
	if maxBytes == 0 {
		maxBytes = limits.DefaultMaxRequestBody
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := limitRequestBody(w, r, maxBytes); err != nil {
			WriteJSON(w, r, err)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), bodyLimitKey{}, maxBytes))
		next.ServeHTTP(w, r)
	})
}

func limitRequestBody(w http.ResponseWriter, r *http.Request, maxBytes int64) error {
	if maxBytes < 0 {
		return nil
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
	if r.ContentLength > maxBytes {
		return requestTooLarge(&http.MaxBytesError{Limit: maxBytes})
	}
	return nil
}

func requestTooLarge(err error) error {
	return httperror.RequestTooLarge("request body exceeds the configured limit").WithCause(errors.WithStack(err))
}
