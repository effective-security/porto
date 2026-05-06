package roles

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
)

func Test_enforceCSRFCookieAndHeader(t *testing.T) {
	tok := "same-token-value"

	newPost := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://example.com/api", nil)
		return r
	}

	t.Run("safe_methods_skip", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
			r := httptest.NewRequest(method, "https://example.com/api", nil)
			assert.NoError(t, enforceCSRFCookieAndHeader(r), method)
		}
	})

	t.Run("authorization_header_skips", func(t *testing.T) {
		r := newPost()
		r.Header.Set(header.Authorization, header.Bearer+" x")
		assert.NoError(t, enforceCSRFCookieAndHeader(r))
	})

	t.Run("missing_csrf_header", func(t *testing.T) {
		r := newPost()
		r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
		r.Header.Set("Origin", "https://example.com")
		assert.EqualError(t, enforceCSRFCookieAndHeader(r), "missing X-CSRF-Token header")
	})

	t.Run("missing_csrf_cookie", func(t *testing.T) {
		r := newPost()
		r.Header.Set(csrfHeaderName, tok)
		r.Header.Set("Origin", "https://example.com")
		assert.EqualError(t, enforceCSRFCookieAndHeader(r), "missing csrf_token cookie")
	})

	t.Run("csrf_mismatch", func(t *testing.T) {
		r := newPost()
		r.Header.Set(csrfHeaderName, tok)
		r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "other"})
		r.Header.Set("Origin", "https://example.com")
		assert.EqualError(t, enforceCSRFCookieAndHeader(r), "csrf token mismatch")
	})
	/*
		t.Run("origin_matches_host", func(t *testing.T) {
			r := newPost()
			r.Header.Set(csrfHeaderName, tok)
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
			r.Header.Set("Origin", "https://example.com")
			require.NoError(t, enforceCSRFCookieAndHeader(r))
		})

		t.Run("origin_host_mismatch", func(t *testing.T) {
			r := newPost()
			r.Header.Set(csrfHeaderName, tok)
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
			r.Header.Set("Origin", "https://evil.example")
			assert.EqualError(t, enforceCSRFCookieAndHeader(r), "cross-site request not allowed")
		})

		t.Run("invalid_origin_url", func(t *testing.T) {
			r := newPost()
			r.Header.Set(csrfHeaderName, tok)
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
			r.Header.Set("Origin", "://")
			assert.EqualError(t, enforceCSRFCookieAndHeader(r), "cross-site request not allowed")
		})

		t.Run("no_origin_referer_matches", func(t *testing.T) {
			r := newPost()
			r.Header.Set(csrfHeaderName, tok)
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
			r.Header.Set("Referer", "https://example.com/page")
			require.NoError(t, enforceCSRFCookieAndHeader(r))
		})

		t.Run("no_origin_referer_mismatch", func(t *testing.T) {
			r := newPost()
			r.Header.Set(csrfHeaderName, tok)
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
			r.Header.Set("Referer", "https://evil.example/page")
			assert.EqualError(t, enforceCSRFCookieAndHeader(r), "cross-site request not allowed")
		})

		t.Run("invalid_referer_when_origin_absent", func(t *testing.T) {
			r := newPost()
			r.Header.Set(csrfHeaderName, tok)
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
			r.Header.Set("Referer", "://bad")
			assert.EqualError(t, enforceCSRFCookieAndHeader(r), "cross-site request not allowed")
		})

		t.Run("origin_present_skips_referer_check_even_if_bad_referer", func(t *testing.T) {
			r := newPost()
			r.Header.Set(csrfHeaderName, tok)
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tok})
			r.Header.Set("Origin", "https://example.com")
			r.Header.Set("Referer", "https://evil.example/page")
			require.NoError(t, enforceCSRFCookieAndHeader(r))
		})
	*/
}
