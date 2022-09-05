package telemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/effective-security/metrics"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_RequestMetricsStatusCode(t *testing.T) {
	rm := NewRequestMetrics(nil).(*requestMetrics)

	assert.Equal(t, "200", rm.statusCode(200))
	assert.Equal(t, "500", rm.statusCode(500))
	assert.Equal(t, "700", rm.statusCode(700))
	assert.Equal(t, "0", rm.statusCode(0))
}

func Test_RequestMetrics(t *testing.T) {
	im := metrics.NewInmemSink(time.Minute, time.Minute*5)
	_, err := metrics.NewGlobal(metrics.DefaultConfig("test"), im)
	require.NoError(t, err)

	assertSample := func(key string, expectedCount int) {
		data := im.Data()
		s, exists := data[0].Samples[key]
		if assert.True(t, exists, "sample metric key not found: %s", key) {
			assert.Equal(t, expectedCount, s.Count, "unexpected count for metric %s", key)
		}
	}
	assertCounter := func(key string, expectedCount int) {
		data := im.Data()
		s, exists := data[0].Counters[key]
		if assert.True(t, exists, "counter metric key not found: %s", key) {
			assert.Equal(t, expectedCount, s.Count, "Unexpected count for metric %s", key)
		}
	}

	defer func() {
		md := im.Data()
		if len(md) > 0 {
			for k := range md[0].Gauges {
				t.Log("Gauge:", k)
			}
			for k := range md[0].Counters {
				t.Log("Counter:", k)
			}
			for k := range md[0].Samples {
				t.Log("Sample:", k)
			}
		}
	}()

	handlerStatusCode := 200
	h := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(handlerStatusCode)
		io.WriteString(w, `"Helo World"`)
	}
	rm := NewRequestMetrics(http.HandlerFunc(h))
	req := func(method, uri string, sc int) {
		r, err := http.NewRequest(method, uri, nil)
		require.NoError(t, err)
		r = identity.WithTestIdentity(r, identity.NewIdentity("admin", "10.0.0.1", nil, "", ""))

		w := httptest.NewRecorder()
		handlerStatusCode = sc
		rm.ServeHTTP(w, r)
	}
	req(http.MethodGet, "/", http.StatusOK)
	req(http.MethodGet, "/foo", http.StatusOK)
	req(http.MethodPost, "/", http.StatusOK)
	req(http.MethodPost, "/", http.StatusOK)
	req(http.MethodPost, "/", http.StatusBadRequest)
	req(http.MethodPost, "/bar", http.StatusBadRequest)
	req(http.MethodPost, "/bar", http.StatusBadRequest)

	assertSample("test.http.request.perf;method=GET;role=admin;status=200;uri=/", 1)
	assertSample("test.http.request.perf;method=GET;role=admin;status=200;uri=/foo", 1)
	assertSample("test.http.request.perf;method=POST;role=admin;status=200;uri=/", 2)

	assertCounter("test.http.request.status.successful;method=GET;role=admin;status=200;uri=/", 1)
	assertCounter("test.http.request.status.successful;method=GET;role=admin;status=200;uri=/foo", 1)
	assertCounter("test.http.request.status.successful;method=POST;role=admin;status=200;uri=/", 2)
	assertCounter("test.http.request.status.failed;method=POST;role=admin;status=400;uri=/", 1)
	assertCounter("test.http.request.status.failed;method=POST;role=admin;status=400;uri=/bar", 2)
}
