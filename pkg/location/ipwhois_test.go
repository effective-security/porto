package location_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/location"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// wantFields is the fields query IPWhoIs sends.
	wantFields = "success,message,city,region,country,country_code"
	// locationLogPkg is the package name of the location logger.
	locationLogPkg = "location"
	// movedPath is where the redirects of the test servers point.
	movedPath = "/moved"
	// slowTail is how long TestIPWhoIsReusesConnection holds back the end
	// of its first answer: longer than the transport drains a body closed
	// early (50ms), so that only a drain before Close keeps the connection.
	slowTail = 150 * time.Millisecond
	// tailBytes is the size of the held back end of that answer.
	tailBytes = 10
)

// seen is what a lookup server received.
type seen struct {
	path   string
	fields string
	key    string
	agent  string
	accept string
}

// lookupServer answers every request with status and body and reports the
// request on the returned channel. A redirect points to movedPath, which
// answers a place, so that a client following it gets no status error.
func lookupServer(t *testing.T, status int, body string) (*httptest.Server, <-chan seen) {
	t.Helper()
	requests := make(chan seen, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- seen{
			path:   r.URL.Path,
			fields: r.URL.Query().Get("fields"),
			key:    r.URL.Query().Get("key"),
			agent:  r.Header.Get("User-Agent"),
			accept: r.Header.Get("Accept"),
		}
		if r.URL.Path == movedPath {
			_, _ = w.Write([]byte(`{"success":true,"city":"Moved"}`))
			return
		}
		if status == http.StatusFound {
			w.Header().Set(header.Location, movedPath)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, requests
}

func newIPWhoIs(t *testing.T, cfg location.IPWhoIsConfig) *location.IPWhoIs {
	t.Helper()
	p, err := location.NewIPWhoIs(cfg)
	require.NoError(t, err)
	return p
}

func TestNewIPWhoIs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  location.IPWhoIsConfig
		err  string
	}{
		{name: "defaults"},
		{
			name: "custom",
			cfg: location.IPWhoIsConfig{
				BaseURL:   "http://localhost:8080/geo",
				Timeout:   time.Second,
				UserAgent: "test",
			},
		},
		{
			name: "negative timeout",
			cfg:  location.IPWhoIsConfig{Timeout: -time.Second},
			err:  "invalid location timeout -1s",
		},
		{
			name: "unparsable",
			cfg:  location.IPWhoIsConfig{BaseURL: "http://[::1?key=secret"},
			err:  `invalid location base URL: missing ']' in host`,
		},
		{
			name: "query and password not shown",
			cfg:  location.IPWhoIsConfig{BaseURL: "ftp://user:pass@ipwho.is/geo?key=secret#frag"},
			err:  `invalid location base URL "ftp://user:xxxxx@ipwho.is/geo": expected an http or https URL`,
		},
		{
			name: "scheme",
			cfg:  location.IPWhoIsConfig{BaseURL: "ftp://ipwho.is"},
			err:  `invalid location base URL "ftp://ipwho.is": expected an http or https URL`,
		},
		{
			name: "no host",
			cfg:  location.IPWhoIsConfig{BaseURL: "https://"},
			err:  `invalid location base URL "https:": expected an http or https URL`,
		},
		{
			name: "relative",
			cfg:  location.IPWhoIsConfig{BaseURL: "/geo"},
			err:  `invalid location base URL "/geo": expected an http or https URL`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := location.NewIPWhoIs(tt.cfg)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				assert.Nil(t, p)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, p)
		})
	}
}

func TestIPWhoIsLocation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	google := netip.MustParseAddr("8.8.8.8")

	t.Run("place", func(t *testing.T) {
		t.Parallel()
		srv, requests := lookupServer(t, http.StatusOK,
			`{"success":true,"city":" San Jose ","region":"California","country":"United States","country_code":"US"}`)
		p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL})

		place, err := p.Location(ctx, netip.MustParseAddr("::ffff:8.8.8.8"))
		require.NoError(t, err)
		assert.Equal(t, &location.Place{
			City:        "San Jose",
			Region:      "California",
			Country:     "United States",
			CountryCode: "US",
		}, place)
		assert.Equal(t, seen{
			path:   "/8.8.8.8",
			fields: wantFields,
			agent:  location.DefaultUserAgent,
			accept: "application/json",
		}, <-requests)
	})

	t.Run("base path, query and user agent", func(t *testing.T) {
		t.Parallel()
		srv, requests := lookupServer(t, http.StatusOK, `{"success":true,"country":"France"}`)
		p := newIPWhoIs(t, location.IPWhoIsConfig{
			BaseURL:   srv.URL + "/geo/?key=secret&fields=replaced#frag",
			UserAgent: "test-agent",
		})

		place, err := p.Location(ctx, google)
		require.NoError(t, err)
		assert.Equal(t, &location.Place{Country: "France"}, place)
		assert.Equal(t, seen{
			path:   "/geo/8.8.8.8",
			fields: wantFields,
			key:    "secret",
			agent:  "test-agent",
			accept: "application/json",
		}, <-requests)
	})

	t.Run("ipv6 without zone", func(t *testing.T) {
		t.Parallel()
		srv, requests := lookupServer(t, http.StatusOK, `{"success":true,"city":"Mountain View"}`)
		p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL})

		place, err := p.Location(ctx, netip.MustParseAddr("2001:4860:4860::8888%eth0"))
		require.NoError(t, err)
		assert.Equal(t, &location.Place{City: "Mountain View"}, place)
		assert.Equal(t, "/2001:4860:4860::8888", (<-requests).path)
	})

	t.Run("null names", func(t *testing.T) {
		t.Parallel()
		srv, _ := lookupServer(t, http.StatusOK,
			`{"success":true,"city":null,"region":"California","country":"United States","country_code":null}`)
		p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL})

		place, err := p.Location(ctx, google)
		require.NoError(t, err)
		assert.Equal(t, &location.Place{Region: "California", Country: "United States"}, place)
	})

	t.Run("body at the limit", func(t *testing.T) {
		t.Parallel()
		body := `{"success":true,"country":"Peru"}`
		srv, _ := lookupServer(t, http.StatusOK, body+strings.Repeat(" ", 4096-len(body)))
		p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL})

		place, err := p.Location(ctx, google)
		require.NoError(t, err)
		assert.Equal(t, &location.Place{Country: "Peru"}, place)
	})

	for _, message := range []string{"Reserved range", " invalid IP address "} {
		t.Run("no location "+message, func(t *testing.T) {
			t.Parallel()
			srv, requests := lookupServer(t, http.StatusOK, `{"success":false,"message":"`+message+`"}`)
			p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL})

			place, err := p.Location(ctx, google)
			require.NoError(t, err)
			assert.Nil(t, place)
			assert.Len(t, requests, 1)
		})
	}

	t.Run("not public", func(t *testing.T) {
		t.Parallel()
		srv, requests := lookupServer(t, http.StatusOK, `{"success":true,"city":"Nowhere"}`)
		p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL})

		for _, addr := range []netip.Addr{{}, netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("::1")} {
			place, err := p.Location(ctx, addr)
			require.NoError(t, err)
			assert.Nil(t, place)
		}
		assert.Empty(t, requests)
	})

	for _, tt := range []struct {
		name   string
		status int
		body   string
		err    string
	}{
		{
			name:   "other failure",
			status: http.StatusOK,
			body:   `{"success":false,"message":"Something else"}`,
			err:    `location lookup of 8.8.8.8 failed: "Something else"`,
		},
		{
			name:   "server error",
			status: http.StatusInternalServerError,
			err:    "location lookup of 8.8.8.8 returned status 500",
		},
		{
			name:   "redirect",
			status: http.StatusFound,
			err:    "location lookup of 8.8.8.8 returned status 302",
		},
		{
			name:   "invalid json",
			status: http.StatusOK,
			body:   `{`,
			err:    "unable to decode location of 8.8.8.8: unexpected end of JSON input",
		},
		{
			name:   "too large",
			status: http.StatusOK,
			body:   `{"success":true}` + strings.Repeat(" ", 4096),
			err:    "location of 8.8.8.8 exceeds 4096 bytes",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv, _ := lookupServer(t, tt.status, tt.body)
			p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL})

			place, err := p.Location(ctx, google)
			require.EqualError(t, err, tt.err)
			assert.Nil(t, place)
		})
	}

	t.Run("caller deadline", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		t.Cleanup(srv.Close)
		p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL})

		ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		place, err := p.Location(ctx, google)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, place)
	})

	t.Run("client timeout", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		t.Cleanup(srv.Close)
		p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL, Timeout: 50 * time.Millisecond})

		place, err := p.Location(ctx, google)
		require.Error(t, err)
		var netErr net.Error
		require.ErrorAs(t, err, &netErr)
		assert.True(t, netErr.Timeout())
		assert.Nil(t, place)
	})

	t.Run("unreachable", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close()
		p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL + "?key=secret"})

		place, err := p.Location(ctx, google)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to look up location of 8.8.8.8: ")
		// the URL, with its query, is not repeated
		assert.NotContains(t, fmt.Sprintf("%+v", err), "secret")
		assert.NotContains(t, err.Error(), srv.URL)
		assert.Nil(t, place)
	})
}

// TestIPWhoIsReusesConnection is not parallel: httptest.Server.Close closes
// the idle connections of http.DefaultTransport, which IPWhoIs uses, so a
// test closing its server in parallel would drop the connection counted here.
func TestIPWhoIsReusesConnection(t *testing.T) {
	ctx := context.Background()
	ips := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}

	for _, tt := range []struct {
		name   string
		status int
		body   string
		// err is the error format for the looked up IP; empty for a place
		err string
	}{
		{
			name:   "place",
			status: http.StatusOK,
			body:   `{"success":true,"city":"Mountain View"}`,
		},
		{
			name:   "server error",
			status: http.StatusInternalServerError,
			body:   strings.Repeat("x", 1024),
			err:    "location lookup of %s returned status 500",
		},
		{
			name:   "redirect",
			status: http.StatusFound,
			body:   strings.Repeat("x", 1024),
			err:    "location lookup of %s returned status 302",
		},
		{
			name:   "other failure",
			status: http.StatusOK,
			body:   `{"success":false,"message":"Something else"}`,
			err:    `location lookup of %s failed: "Something else"`,
		},
		{
			name:   "too large",
			status: http.StatusOK,
			body:   `{"success":true}` + strings.Repeat(" ", 4096),
			err:    "location of %s exceeds 4096 bytes",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var conns, requests atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.status == http.StatusFound {
					w.Header().Set(header.Location, movedPath)
				}
				w.WriteHeader(tt.status)
				body := []byte(tt.body)
				if requests.Add(1) == 1 {
					// the end of the first answer comes late, after the
					// lookup has read what it needs
					tail := len(body) - tailBytes
					_, _ = w.Write(body[:tail])
					_ = http.NewResponseController(w).Flush()
					time.Sleep(slowTail)
					body = body[tail:]
				}
				_, _ = w.Write(body)
			}))
			srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					conns.Add(1)
				}
			}
			srv.Start()
			t.Cleanup(srv.Close)
			p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL})

			for _, ip := range ips {
				place, err := p.Location(ctx, netip.MustParseAddr(ip))
				if tt.err == "" {
					require.NoError(t, err)
					assert.NotNil(t, place)
					continue
				}
				require.EqualError(t, err, fmt.Sprintf(tt.err, ip))
				assert.Nil(t, place)
			}
			assert.Equal(t, int32(len(ips)), requests.Load())
			assert.Equal(t, int32(1), conns.Load())
		})
	}
}

func TestIPWhoIsQuota(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set(header.RetryAfter, "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"success":false,"message":"Rate limit exceeded"}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"country":"Chile"}`))
	}))
	t.Cleanup(srv.Close)
	p := newIPWhoIs(t, location.IPWhoIsConfig{BaseURL: srv.URL})
	ctx := context.Background()

	place, err := p.Location(ctx, netip.MustParseAddr("8.8.8.8"))
	// the backoff started before Location returned
	returned := time.Now()
	require.ErrorIs(t, err, location.ErrQuotaExceeded)
	assert.EqualError(t, err, "location lookup of 8.8.8.8 returned status 429, retry after 1s: location lookup quota exceeded")
	assert.Nil(t, place)

	// skipped without a request until Retry-After has passed
	place, err = p.Location(ctx, netip.MustParseAddr("1.1.1.1"))
	require.ErrorIs(t, err, location.ErrQuotaExceeded)
	assert.Contains(t, err.Error(), "location lookup of 1.1.1.1 skipped until ")
	assert.Nil(t, place)
	assert.Equal(t, int32(1), hits.Load())

	time.Sleep(time.Until(returned.Add(1100 * time.Millisecond)))
	place, err = p.Location(ctx, netip.MustParseAddr("1.1.1.1"))
	require.NoError(t, err)
	assert.Equal(t, &location.Place{Country: "Chile"}, place)
	assert.Equal(t, int32(2), hits.Load())
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		value string
		want  time.Duration
	}{
		{value: "", want: time.Minute},
		{value: "soon", want: time.Minute},
		{value: "0", want: time.Minute},
		{value: "-5", want: time.Minute},
		{value: " 30 ", want: 30 * time.Second},
		{value: "86400", want: 24 * time.Hour},
		{value: "9223372036854775807", want: 24 * time.Hour},
		{value: "-10000000000", want: time.Minute},
		{value: "-9223372036854775808", want: time.Minute},
		{value: "99999999999999999999", want: time.Minute},
		{value: now.Add(90 * time.Second).Format(http.TimeFormat), want: 90 * time.Second},
		{value: now.Add(-time.Hour).Format(http.TimeFormat), want: time.Minute},
		{value: now.Add(72 * time.Hour).Format(http.TimeFormat), want: 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, location.RetryAfter(tt.value, now))
		})
	}
}

func TestIPLocation(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/1.1.1.1" {
			_, _ = w.Write([]byte(`{"success":false,"message":"Invalid IP address"}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"city":"Singapore","region":"Singapore","country":"Singapore","country_code":"SG"}`))
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()

	place := location.IPLocation(ctx, srv.URL, netip.MustParseAddr("8.8.8.8"))
	assert.Equal(t, &location.Place{
		City:        "Singapore",
		Region:      "Singapore",
		Country:     "Singapore",
		CountryCode: "SG",
	}, place)
	assert.Equal(t, "Singapore", place.String())

	assert.Nil(t, location.IPLocation(ctx, srv.URL, netip.MustParseAddr("1.1.1.1")))
	assert.Nil(t, location.IPLocation(ctx, srv.URL, netip.MustParseAddr("192.168.1.1")))
	assert.Equal(t, int32(2), hits.Load())
}

// TestIPLocationLogsErrors installs a process-global log formatter, so it is
// not parallel.
func TestIPLocationLogsErrors(t *testing.T) {
	var logs bytes.Buffer
	t.Cleanup(xlog.InstallFormatter(xlog.NewJSONFormatter(&logs)))

	srv, _ := lookupServer(t, http.StatusTooManyRequests, `{"success":false,"message":"Rate limit exceeded"}`)
	ctx := context.Background()
	google := netip.MustParseAddr("8.8.8.8")

	assert.Nil(t, location.IPLocation(ctx, srv.URL, google))
	assert.Nil(t, location.IPLocation(ctx, "ftp://ipwho.is", google))
	// addresses without a location are neither looked up nor logged
	assert.Nil(t, location.IPLocation(ctx, "ftp://ipwho.is", netip.Addr{}))
	assert.Nil(t, location.IPLocation(ctx, "ftp://ipwho.is", netip.MustParseAddr("10.0.0.1")))

	var got []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		entry := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &entry), line)
		if entry["pkg"] == locationLogPkg {
			delete(entry, "time")
			got = append(got, entry)
		}
	}
	assert.Equal(t, []map[string]any{
		{
			"level":  "W",
			"pkg":    locationLogPkg,
			"func":   "IPLocation",
			"reason": "ip_location",
			"ip":     "8.8.8.8",
			"err":    "location lookup of 8.8.8.8 returned status 429, retry after 1m0s: location lookup quota exceeded",
		},
		{
			"level":  "W",
			"pkg":    locationLogPkg,
			"func":   "IPLocation",
			"reason": "ip_location",
			"ip":     "8.8.8.8",
			"err":    `invalid location base URL "ftp://ipwho.is": expected an http or https URL`,
		},
	}, got)
}
