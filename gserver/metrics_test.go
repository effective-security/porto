package gserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/metrics"
	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	metricsTestPrefix = "gservertest"
	// testRoleHeader carries the role headerIdentity maps a request to.
	testRoleHeader = "X-Test-Role"
	// deniedRole makes headerIdentity fail, as a rejected credential does.
	deniedRole = "deny"
	testOrigin = "https://app.test"
)

// headerIdentity is a roles.IdentityProvider that maps testRoleHeader to
// the role, the guest role without it, and fails for deniedRole.
type headerIdentity struct{}

func (headerIdentity) ApplicableForRequest(*http.Request) bool { return true }

func (headerIdentity) IdentityFromRequest(r *http.Request) (identity.Identity, error) {
	role := r.Header.Get(testRoleHeader)
	if role == deniedRole {
		return nil, errors.New("invalid credentials")
	}
	if role == "" {
		role = roles.GuestRoleName
	}
	return identity.NewIdentity(role, "user", "", nil, "", "", identity.MethodNone), nil
}

func (headerIdentity) ApplicableForContext(context.Context) bool { return false }

func (headerIdentity) IdentityFromContext(context.Context, string) (identity.Identity, error) {
	return identity.NewIdentity(roles.GuestRoleName, "", "", nil, "", "", identity.MethodNone), nil
}

// newMetricsSink installs a process-global in-memory metrics sink and
// returns a function that reports the count of every sample and counter
// key, summed over all intervals. Tests that call it must not run in
// parallel.
func newMetricsSink(t *testing.T) func() map[string]int {
	im := metrics.NewInmemSink(time.Minute, 5*time.Minute)
	// Runtime metrics would add samples to the exact comparisons.
	mcfg := metrics.DefaultConfig(metricsTestPrefix)
	mcfg.EnableRuntimeMetrics = false
	_, err := metrics.NewGlobal(mcfg, im)
	require.NoError(t, err)
	return func() map[string]int {
		counts := map[string]int{}
		for _, interval := range im.Data() {
			for k, v := range interval.Samples {
				counts[k] += v.Count
			}
			for k, v := range interval.Counters {
				counts[k] += v.Count
			}
		}
		return counts
	}
}

// requestMetric returns the sample and counter keys of one request.
func requestMetric(labels, role string, count int) map[string]int {
	return map[string]int{
		metricsTestPrefix + "_http_requests_perf;" + labels:                   count,
		metricsTestPrefix + "_http_requests_role;" + labels + ";role=" + role: count,
	}
}

// TestHandlersCountEarlyResponses checks that the HTTP metrics count
// responses produced before the role is known (identity rejections and CORS
// preflights, formerly P-084) as guest, and label the other requests with
// the role the identity mapper returned.
func TestHandlersCountEarlyResponses(t *testing.T) {
	counts := newMetricsSink(t)

	enabled := true
	s := &Server{
		name: "metrics",
		cfg: Config{
			CORS: &CORS{
				Enabled:        &enabled,
				AllowedOrigins: []string{testOrigin},
				AllowedMethods: []string{http.MethodGet},
			},
		},
		identity: headerIdentity{},
	}
	router := restserver.NewRouter(notFoundHandler)
	router.GET("/v1/items/:id", func(w http.ResponseWriter, _ *http.Request, _ restserver.Params) {
		w.WriteHeader(http.StatusOK)
	})
	h := configureHandlers(s, router.Handler())

	serve := func(method, role string, preflight bool) int {
		r := httptest.NewRequest(method, "/v1/items/1", nil)
		if role != "" {
			r.Header.Set(testRoleHeader, role)
		}
		if preflight {
			r.Header.Set(header.Origin, testOrigin)
			r.Header.Set(header.AccessControlRequestMethod, http.MethodGet)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	before := counts()
	assert.Equal(t, http.StatusOK, serve(http.MethodGet, "admin", false))
	assert.Equal(t, http.StatusOK, serve(http.MethodGet, "", false))
	assert.Equal(t, http.StatusUnauthorized, serve(http.MethodGet, deniedRole, false))
	assert.Equal(t, http.StatusNoContent, serve(http.MethodOptions, "admin", true))

	want := map[string]int{}
	for _, m := range []map[string]int{
		requestMetric("verb=GET;status=200;uri=/v1/items/:id", "admin", 1),
		requestMetric("verb=GET;status=200;uri=/v1/items/:id", roles.GuestRoleName, 1),
		requestMetric("verb=GET;status=401;uri=unknown", roles.GuestRoleName, 1),
		requestMetric("verb=OPTIONS;status=204;uri=unknown", roles.GuestRoleName, 1),
	} {
		for k, v := range m {
			want[k] += v
		}
	}
	assert.Equal(t, want, delta(before, counts()))
}

// TestRateLimitRejectionCounted checks that both rate limiter variants
// count their rejections, including those of gRPC calls, which reach the
// limiter on TLS listeners (formerly P-084).
func TestRateLimitRejectionCounted(t *testing.T) {
	counts := newMetricsSink(t)

	enabled := true
	for _, lookups := range [][]string{nil, {rateLookupRemoteAddr}} {
		calls := 0
		h := configureRateLimiter(&RateLimit{
			Enabled:           &enabled,
			RequestsPerSecond: 1,
			HeadersIPLookups:  lookups,
		}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusOK)
		}))
		h = identity.NewTrustedProxyHandler(h, nil)

		before := counts()
		codes := make([]int, 0, 3)
		for _, ct := range []string{"", "", header.ApplicationGRPC} {
			r := httptest.NewRequest(http.MethodPost, "/pkg.Service/Method", nil)
			r.RemoteAddr = "198.51.100.7:123"
			if ct != "" {
				r.Header.Set(header.ContentType, ct)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			codes = append(codes, w.Code)
		}
		assert.Equal(t, []int{http.StatusOK, http.StatusTooManyRequests, http.StatusTooManyRequests}, codes, lookups)
		assert.Equal(t, 1, calls)
		// the admitted request is counted by the handlers behind the limiter
		assert.Equal(t, requestMetric("verb=POST;status=429;uri=unknown", roles.GuestRoleName, 2), delta(before, counts()), lookups)
	}
}

// delta returns the keys whose count grew from before to after, with the
// increase.
func delta(before, after map[string]int) map[string]int {
	d := map[string]int{}
	for k, v := range after {
		if n := v - before[k]; n != 0 {
			d[k] = n
		}
	}
	return d
}
