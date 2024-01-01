package telemetry

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/restserver", "http")

const (
	//This DateFormat is meant to imitate
	prefixLength = len("2006-01-02 15:04:05.000000   | ")
)

func assertRespEqual(t *testing.T, res *httptest.ResponseRecorder, expStatusCode int, expBody string) {
	if expStatusCode != res.Code {
		t.Errorf("Expecting statusCode %d, but got %d", expStatusCode, res.Code)
	}
	if expBody != res.Body.String() {
		t.Errorf("Expecting responseBody %q, but got %q", expBody, res.Body.String())
	}
}

func TestHttp_ResponseCapture(t *testing.T) {
	w := httptest.NewRecorder()
	rc := NewResponseCapture(w)
	var rw http.ResponseWriter = rc // ensure rc can be used as a ResponseWriter
	rw.Header().Add("Content-Type", "text/plain")
	rw.WriteHeader(http.StatusNotFound)
	body := []byte("/foo not found")
	_, _ = rw.Write(body)
	_, _ = rw.Write(body) // write this 2 to ensure we're accumulate bytes written
	if rc.StatusCode() != http.StatusNotFound {
		t.Errorf("ResponseCapture didn't report the expected status code set by the caller, got %d", rc.StatusCode())
	}
	expBodyLen := uint64(len(body)) * 2
	if rc.BodySize() != expBodyLen {
		t.Errorf("Expected BodySize to be %d, but was %d", expBodyLen, rc.BodySize())
	}
	// check that it actually passed onto the delegate ResponseWriter
	assertRespEqual(t, w, http.StatusNotFound, "/foo not found/foo not found")

	rc.Flush()
}

type testHandler struct {
	t            *testing.T
	statusCode   int
	responseBody []byte
}

func (th *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/foo" {
		th.t.Errorf("ultimate handler didn't see correct request")
	}
	w.WriteHeader(th.statusCode)
	w.Write(th.responseBody)
}

func TestHttp_RequestLoggerNullHandler(t *testing.T) {
	assert.Panics(t, func() {
		NewRequestLogger(nil, time.Millisecond, logger)
	})
}

func TestHttp_NoLogger(t *testing.T) {
	testResponseBody := []byte(`Hello World`)
	handler := &testHandler{t, http.StatusBadRequest, testResponseBody}
	h2 := NewRequestLogger(handler, time.Millisecond, nil)
	assert.Equal(t, handler, h2)
}

func TestHttp_RequestLogger(t *testing.T) {
	xlog.TimeNowFn = func() time.Time {
		date, _ := time.Parse("2006-01-02", "2021-04-01")
		return date
	}

	testResponseBody := []byte(`Hello World`)
	handler := &testHandler{t, http.StatusBadRequest, testResponseBody}
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/foo", nil)
	testRemoteIP := "127.0.0.1"
	testRemotePort := "51500"
	r.RemoteAddr = fmt.Sprintf("%v:%v", testRemoteIP, testRemotePort)
	r.ProtoMajor = 1
	r.ProtoMinor = 1

	tw := bytes.Buffer{}
	writer := bufio.NewWriter(&tw)
	xlog.SetFormatter(xlog.NewStringFormatter(writer))

	logHandler := NewRequestLogger(handler, time.Millisecond, logger)
	logHandler.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code, "Status code set by ultimate handler wasn't returned by the logging wrapper")
	require.NotEmpty(t, tw, "A request was processed, but nothing was logged")

	logLine := tw.String()
	// cid is random
	assert.Equal(t, "time=2021-04-01T00:00:00Z level=I pkg=http func=ServeHTTP method=\"GET\" path=\"/foo\" status=400 bytes=11 time=0 remote=\"127.0.0.1:51500\" agent=\"no-agent\"\n", logLine)
}

func TestHttp_RequestLoggerDef(t *testing.T) {
	xlog.TimeNowFn = func() time.Time {
		date, _ := time.Parse("2006-01-02", "2021-04-01")
		return date
	}

	handler := &testHandler{t, http.StatusOK, []byte(`Hello World`)}
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/foo", nil)

	tw := bytes.Buffer{}
	writer := bufio.NewWriter(&tw)
	xlog.SetFormatter(xlog.NewStringFormatter(writer))
	lg := NewRequestLogger(handler, time.Millisecond, logger)
	lg.ServeHTTP(w, r)
	logLine := tw.String()
	// cid is random
	assert.Equal(t, "time=2021-04-01T00:00:00Z level=I pkg=http func=ServeHTTP method=\"GET\" path=\"/foo\" status=200 bytes=11 time=0 agent=\"no-agent\"\n", logLine)
}

func TestHttp_RequestLoggerWithSkip(t *testing.T) {
	tcases := []struct {
		opt   Option
		path  string
		agent string
		exp   bool
	}{
		{WithLoggerSkipPaths(LoggerSkipPaths{{Path: "", Agent: ""}}), "/foo", "", true},
		{WithLoggerSkipPaths(LoggerSkipPaths{{Path: "*", Agent: ""}}), "/foo", "", false},
		{WithLoggerSkipPaths(LoggerSkipPaths{{Path: "*", Agent: "*"}}), "/foo", "Google HB", false},
		{WithLoggerSkipPaths(LoggerSkipPaths{{Path: "", Agent: "*"}}), "/foo", "Google HB", true},
		{WithLoggerSkipPaths(LoggerSkipPaths{{Path: "", Agent: "Google"}}), "/foo", "Google HB", true},
		{WithLoggerSkipPaths(LoggerSkipPaths{{Path: "/foo", Agent: "Google"}}), "/foo", "Google HB", false},
		{WithLoggerSkipPaths(LoggerSkipPaths{{Path: "/bar", Agent: "Google"}}), "/foo", "Google HB", true},
		{WithLoggerSkipPaths(LoggerSkipPaths{{Path: "/foo", Agent: "Google"}}), "/foo", "Prom", true},
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("echo: " + r.URL.Path))
	}

	for _, tc := range tcases {
		w := httptest.NewRecorder()
		tw := bytes.Buffer{}
		writer := bufio.NewWriter(&tw)
		xlog.SetFormatter(xlog.NewStringFormatter(writer))

		lg := NewRequestLogger(http.HandlerFunc(handler), time.Millisecond, logger, tc.opt)
		r, _ := http.NewRequest("GET", tc.path, nil)
		if tc.agent != "" {
			r.Header.Add(header.UserAgent, tc.agent)
		}

		lg.ServeHTTP(w, r)

		logLine := tw.String()
		if tc.exp {
			assert.Contains(t, logLine, tc.path, xlog.EscapedString(tc))
		} else {
			assert.NotContains(t, logLine, tc.path, xlog.EscapedString(tc))
		}
	}
}
