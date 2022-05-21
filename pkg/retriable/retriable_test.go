package retriable_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	clientCertFile string
	clientKeyFile  string
	clientRootFile string
)

// ensure compiles
var _ = interface{}(&retriable.Client{}).(retriable.HTTPClient)
var _ = interface{}(&retriable.Client{}).(retriable.GenericHTTP)

func TestMain(m *testing.M) {
	//xlog.SetGlobalLogLevel(xlog.DEBUG)
	ca1 := testca.NewEntity(
		testca.Authority,
		testca.Subject(pkix.Name{
			CommonName: "[TEST] Root CA One",
		}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	inter1 := ca1.Issue(
		testca.Authority,
		testca.Subject(pkix.Name{
			CommonName: "[TEST] Issuing CA One Level 1",
		}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	srv := inter1.Issue(
		testca.Subject(pkix.Name{
			CommonName: "localhost",
		}),
		testca.ExtKeyUsage(x509.ExtKeyUsageClientAuth),
	)

	tmpDir := filepath.Join(os.TempDir(), "test-retriable")
	os.MkdirAll(tmpDir, os.ModePerm)
	defer os.RemoveAll(tmpDir)

	clientCertFile = filepath.Join(tmpDir, "test-client.pem")
	clientKeyFile = filepath.Join(tmpDir, "test-client.key")
	clientRootFile = filepath.Join(tmpDir, "test-client-rootca.pem")

	err := srv.SaveCertAndKey(clientCertFile, clientKeyFile, true)
	if err != nil {
		panic(err)
	}

	err = ca1.SaveCertAndKey(clientRootFile, "", false)
	if err != nil {
		panic(err)
	}

	rc := m.Run()
	os.Exit(rc)
}

func Test_New(t *testing.T) {
	p := retriable.Policy{
		TotalRetryLimit: 5,
	}

	mutateHook := retriable.WithBeforeSendRequest(func(r *http.Request) *http.Request {
		r.Header.Set("X-Global", "WithBeforeSendRequest")
		return r
	})

	// create without options
	c := retriable.New(mutateHook).WithName("test")
	assert.NotNil(t, c)
	assert.NotNil(t, c.WithPolicy(p))
	assert.NotNil(t, c.WithTLS(nil))
	assert.NotNil(t, c.WithTransport(nil))
	assert.Empty(t, c.CurrentHost())

	// create with options
	c = retriable.New(
		retriable.WithName("test"),
		retriable.WithPolicy(p),
		retriable.WithTLS(nil),
		retriable.WithTransport(nil),
		retriable.WithTimeout(time.Second*300),
	)
	assert.NotNil(t, c)
	c.AddHeader("test", "for client")

	// TLS
	clientTls, err := tlsconfig.NewClientTLSFromFiles(
		clientCertFile,
		clientKeyFile,
		clientRootFile)
	require.NoError(t, err)
	c = retriable.New().WithTLS(clientTls)
	assert.NotNil(t, c)
}

func TestDefaultPolicy(t *testing.T) {
	tcases := []struct {
		expected   bool
		reason     string
		retries    int
		statusCode int
		err        error
	}{
		// 429 is rate limit exceeded
		{false, retriable.LimitExceeded, 0, 429, nil},
		{false, retriable.LimitExceeded, 1, 429, nil},
		{false, retriable.LimitExceeded, 3, 429, nil},
		{false, retriable.LimitExceeded, 4, 429, nil},
		// 503 is service unavailable, which is returned during leader elections
		{true, "unavailable", 0, 503, nil},
		{true, "unavailable", 1, 503, nil},
		{true, "unavailable", 4, 503, nil},
		{false, retriable.LimitExceeded, 5, 503, nil},
		// 502 is bad gateway, which is returned during leader transitions
		{true, "gateway", 0, 502, nil},
		{true, "gateway", 1, 502, nil},
		{true, "gateway", 4, 502, nil},
		{false, retriable.LimitExceeded, 5, 502, nil},
		// regardless of config, other status codes shouldn't get retries
		{false, "success", 0, 200, nil},
		{false, retriable.NonRetriableError, 0, 400, nil},
		{false, retriable.NonRetriableError, 0, 401, nil},
		{false, retriable.NonRetriableError, 0, 402, nil},
		{false, retriable.NonRetriableError, 0, 403, nil},
		{false, retriable.NotFound, 0, 404, nil},
		{false, retriable.NonRetriableError, 0, 430, nil},
		{false, retriable.NonRetriableError, 0, 500, nil},
		// connection
		{true, "connection", 0, 0, errors.New("some error")},
		{true, "connection", 3, 0, errors.New("some error")},
		{false, "connection", 4, 0, errors.New("some error")},
	}

	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)

	p := retriable.DefaultPolicy()
	for _, tc := range tcases {
		t.Run(fmt.Sprintf("%s: %d, %d, %t:", tc.reason, tc.retries, tc.statusCode, tc.expected), func(t *testing.T) {
			res := &http.Response{StatusCode: tc.statusCode}
			should, _, reason := p.ShouldRetry(req, res, tc.err, tc.retries)
			assert.Equal(t, tc.expected, should)
			assert.Equal(t, tc.reason, reason)
		})
	}
}

func Test_Retriable_OK(t *testing.T) {
	h := makeTestHandler(t, "/v1/test", http.StatusOK, `{
		"status": "ok"
	}`)
	server := httptest.NewServer(h)
	defer server.Close()

	client := retriable.New().
		WithHeaders(map[string]string{
			"X-Test-Token": "token1",
		}).
		WithPolicy(retriable.Policy{
			TotalRetryLimit: 2,
			RequestTimeout:  time.Second,
		}).
		WithBeforeSendRequest(func(r *http.Request) *http.Request {
			r.Header.Set("X-Global", "WithBeforeSendRequest")
			return r
		})
	require.NotNil(t, client)

	ctx := context.Background()
	hosts := []string{server.URL}

	client.WithHosts(hosts)
	assert.NotEmpty(t, client.CurrentHost())

	t.Run("GET_RequestURL", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})

		h, status, err := client.RequestURL(ctx,
			http.MethodGet, server.URL+"/v1/test?qq#ff", nil, w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "retriable", h.Get("X-Test-Header"))
		assert.Equal(t, "token1", h.Get("X-Test-Token"))
		assert.Equal(t, "WithBeforeSendRequest", h.Get("X-Global"))
		// test handler modifies the request URL
		//assert.Equal(t, server.URL+"/v1/test?qq#ff", h.Get("X-Request-URL"))
	})

	t.Run("GET", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})

		h, status, err := client.Get(ctx, "/v1/test?qq#ff", w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "retriable", h.Get("X-Test-Header"))
		assert.Equal(t, "token1", h.Get("X-Test-Token"))
		assert.Equal(t, "WithBeforeSendRequest", h.Get("X-Global"))
		// test handler modifies the request URL
		//assert.Equal(t, server.URL+"/v1/test?qq#ff", h.Get("X-Request-URL"))
	})

	t.Run("GET WithTimeout", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		h, status, err := client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "retriable", h.Get("X-Test-Header"))
		assert.Equal(t, "token1", h.Get("X-Test-Token"))
		assert.Equal(t, "WithBeforeSendRequest", h.Get("X-Global"))

		h, status, err = client.RequestURL(ctx, http.MethodGet, server.URL+"/v1/test?qq#ff", nil, w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "retriable", h.Get("X-Test-Header"))
		assert.Equal(t, "token1", h.Get("X-Test-Token"))
		assert.Equal(t, "WithBeforeSendRequest", h.Get("X-Global"))
	})

	t.Run("PUTto", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})
		_, status, err := client.Request(ctx, http.MethodPut, hosts, "/v1/test", []byte("{}"), w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	})
	t.Run("PUT", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})
		_, status, err := client.Put(context.Background(), "/v1/test", []byte("{}"), w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	})
	t.Run("POSTto", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})
		_, status, err := client.Request(ctx, http.MethodPost, hosts, "/v1/test", []byte("{}"), w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	})
	t.Run("POST", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})
		_, status, err := client.Post(context.Background(), "/v1/test", []byte("{}"), w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	})
	t.Run("POST Empty body", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})
		_, status, err := client.Request(ctx, http.MethodPost, hosts, "/v1/test", nil, w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("DELETEto", func(t *testing.T) {
		// override per cal headers
		ctx := retriable.WithHeaders(ctx, map[string]string{
			"X-Test-Token": "token2",
		})

		w := bytes.NewBuffer([]byte{})
		h, status, err := client.Request(ctx, http.MethodDelete, hosts, "/v1/test", nil, w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "token2", h.Get("X-Test-Token"))
	})
	t.Run("DELETE", func(t *testing.T) {
		// override per cal headers
		ctx := retriable.WithHeaders(context.Background(), map[string]string{
			"X-Test-Token": "token2",
		})

		w := bytes.NewBuffer([]byte{})
		h, status, err := client.Delete(ctx, "/v1/test", w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "token2", h.Get("X-Test-Token"))
	})

	t.Run("HEAD", func(t *testing.T) {
		// override per cal headers
		ctx := retriable.WithHeaders(ctx, map[string]string{
			"X-Test-Token": "token2",
		})

		h, status, err := client.HeadTo(ctx, hosts, "/v1/test")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "token2", h.Get("X-Test-Token"))
	})
}

func Test_RetriableWithHeaders(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		headers := map[string]string{
			header.Accept:      r.Header.Get(header.Accept),
			header.ContentType: r.Header.Get(header.ContentType),
			"h1":               r.Header.Get("header1"),
			"h2":               r.Header.Get("header2"),
			"h3":               r.Header.Get("header3"),
			"h4":               r.Header.Get("header4"),
		}

		marshal.WriteJSON(w, r, headers)
	}

	server := httptest.NewServer(http.HandlerFunc(h))
	defer server.Close()

	client := retriable.New()
	require.NotNil(t, client)

	client.WithHeaders(map[string]string{
		"header1": "val1",
		"header2": "val2",
	})

	client.AddHeader("header3", "val3")

	t.Run("clientHeaders", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})

		_, status, err := client.Request(context.Background(), http.MethodGet, []string{server.URL}, "/v1/test", nil, w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var headers map[string]string
		require.NoError(t, json.Unmarshal(w.Bytes(), &headers))

		assert.Equal(t, "val1", headers["h1"])
		assert.Equal(t, "val2", headers["h2"])
		assert.Equal(t, "val3", headers["h3"])
		assert.Empty(t, headers["h4"])
	})

	t.Run("call.setHeader", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})
		// set custom header via request context
		callSpecific := map[string]string{
			"header4": "val4",
		}
		ctx := retriable.WithHeaders(context.Background(), callSpecific)
		_, status, err := client.Request(ctx, http.MethodGet, []string{server.URL}, "/v1/test", nil, w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var headers map[string]string
		require.NoError(t, json.Unmarshal(w.Bytes(), &headers))

		assert.Equal(t, "val1", headers["h1"])
		assert.Equal(t, "val2", headers["h2"])
		assert.Equal(t, "val3", headers["h3"])
		assert.Equal(t, "val4", headers["h4"])
	})

	t.Run("from request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		require.NoError(t, err)
		req.Header.Set("header4", "val4")
		req.Header.Set(header.Accept, "custom")
		req.Header.Set(header.ContentType, "test")

		w := bytes.NewBuffer([]byte{})
		ctx := retriable.PropagateHeadersFromRequest(context.Background(), req, header.Accept, "header4", header.ContentType)

		_, status, err := client.Request(ctx, http.MethodGet, []string{server.URL}, "/v1/test", nil, w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		var headers map[string]string
		require.NoError(t, json.Unmarshal(w.Bytes(), &headers))

		assert.Equal(t, "val4", headers["h4"])
		assert.Equal(t, "custom", headers[header.Accept])
		assert.Equal(t, "test", headers[header.ContentType])
	})
}

func Test_Retriable_StatusNoContent(t *testing.T) {
	h := makeTestHandler(t, "/v1/test", http.StatusNoContent, "")
	server := httptest.NewServer(h)
	defer server.Close()

	client := retriable.New()
	require.NotNil(t, client)

	hosts := []string{server.URL}

	w := bytes.NewBuffer([]byte{})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, status, err := client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, status)
}

func Test_Retriable400(t *testing.T) {
	h := makeTestHandlerWithLimit(t, "/v1/test", 1, http.StatusUnauthorized, `{
		"error": "access denied"
	}`)
	server := httptest.NewServer(h)
	defer server.Close()

	client := retriable.New()
	require.NotNil(t, client)

	hosts := []string{server.URL, server.URL}

	w := bytes.NewBuffer([]byte{})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, status, err := client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, status)
}

func Test_Retriable500(t *testing.T) {
	h := makeTestHandlerWithLimit(t, "/v1/test", 2, http.StatusInternalServerError, `{
		"error": "bug!"
	}`)
	server := httptest.NewServer(h)
	defer server.Close()

	client := retriable.New()
	require.NotNil(t, client)

	hosts := []string{server.URL, server.URL}

	w := bytes.NewBuffer([]byte{})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, status, err := client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
	require.Error(t, err)
	assert.Equal(t, http.StatusInternalServerError, status)
}

func Test_RetriableMulti500Error(t *testing.T) {
	errResponse := `{
	"code": "unexpected",
	"message": "internal server error"
}`

	h := makeTestHandler(t, "/v1/test", http.StatusInternalServerError, errResponse)
	server1 := httptest.NewServer(h)
	defer server1.Close()

	server2 := httptest.NewServer(h)
	defer server2.Close()

	client := retriable.New()
	require.NotNil(t, client)

	hosts := []string{server1.URL, server2.URL}

	w := bytes.NewBuffer([]byte{})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, status, err := client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
	assert.Equal(t, http.StatusInternalServerError, status)
	require.Error(t, err)
	assert.Equal(t, "unexpected: internal server error", err.Error())
}

func Test_RetriableMulti500Custom(t *testing.T) {
	// test with Debug request/response
	xlog.SetGlobalLogLevel(xlog.DEBUG)
	defer xlog.SetGlobalLogLevel(xlog.TRACE)
	errResponse := `{
	"error": "bug!"
}`

	h := makeTestHandler(t, "/v1/test", http.StatusInternalServerError, errResponse)
	server1 := httptest.NewServer(h)
	defer server1.Close()

	server2 := httptest.NewServer(h)
	defer server2.Close()

	client := retriable.New()
	require.NotNil(t, client)

	hosts := []string{server1.URL, server2.URL}

	w := bytes.NewBuffer([]byte{})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, status, err := client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
	assert.Equal(t, http.StatusInternalServerError, status)
	require.Error(t, err)
	assert.Equal(t, errResponse, err.Error())
}

func Test_RetriableTimeout(t *testing.T) {
	h := makeTestHandlerSlow(t, "/v1/test", http.StatusInternalServerError, time.Second, `{
		"error": "bug!"
	}`)
	server1 := httptest.NewServer(h)
	defer server1.Close()

	server2 := httptest.NewServer(h)
	defer server2.Close()

	client := retriable.New()
	require.NotNil(t, client)

	hosts := []string{server1.URL, server2.URL}

	w := bytes.NewBuffer([]byte{})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, status, err := client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
	require.Error(t, err)
	assert.Equal(t, 0, status)
	assert.Contains(t, err.Error(), "unexpected: Get ")
	assert.Contains(t, err.Error(), "context deadline exceeded")
	assert.Contains(t, err.Error(), server1.URL)
	assert.Contains(t, err.Error(), server2.URL)

	// set policy on the client
	client.WithPolicy(retriable.Policy{
		TotalRetryLimit: 2,
		RequestTimeout:  100 * time.Millisecond,
	})
	_, _, err = client.Request(context.Background(), http.MethodGet, hosts, "/v1/test", nil, w)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected: Get ")
	assert.Contains(t, err.Error(), "context deadline exceeded")
	assert.Contains(t, err.Error(), server1.URL)
	assert.Contains(t, err.Error(), server2.URL)
}

func Test_Retriable_WithReadTimeout(t *testing.T) {
	h := makeTestHandler(t, "/v1/test", http.StatusOK, `{
		"status": "ok"
	}`)
	server := httptest.NewServer(h)
	defer server.Close()

	client := retriable.New().
		WithHeaders(map[string]string{
			"X-Test-Token": "token1",
		}).
		WithPolicy(retriable.Policy{
			TotalRetryLimit: 2,
			RequestTimeout:  time.Second,
		}).
		WithTimeout(time.Microsecond * 1)
	require.NotNil(t, client)

	hosts := []string{server.URL}

	t.Run("GET WithTimeout", func(t *testing.T) {
		w := bytes.NewBuffer([]byte{})
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_, _, err := client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Client.Timeout exceeded while awaiting headers")
	})
}

func Test_Retriable_DoWithTimeout(t *testing.T) {
	h := makeTestHandlerSlow(t, "/v1/test/do", http.StatusInternalServerError, 1*time.Second, `{
		"error": "bug"
	}`)
	server1 := httptest.NewServer(h)
	defer server1.Close()

	client := retriable.New()
	require.NotNil(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req, err := http.NewRequest(http.MethodPost, server1.URL+"/v1/test/do", strings.NewReader(`{"test":true}`))
	require.NoError(t, err)
	req = req.WithContext(ctx)

	client.WithPolicy(retriable.Policy{
		TotalRetryLimit: 2,
		RequestTimeout:  100 * time.Millisecond,
	})
	_, err = client.Do(req)
	require.Error(t, err)
	// TODO: different versions of GO return URL in the error as quoted or not
	//exp1 := fmt.Sprintf("Post %s/v1/test/do: context deadline exceeded", server1.URL)
	assert.Contains(t, err.Error(), "context deadline exceeded")
	assert.Contains(t, err.Error(), server1.URL)
}

func Test_Retriable_DoWithRetry(t *testing.T) {
	count := 0
	h := func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		if 2 >= count {
			status = http.StatusServiceUnavailable
		}
		count++
		w.WriteHeader(status)
		io.WriteString(w, fmt.Sprintf(`{"count": "%d"}`, count))
	}

	server1 := httptest.NewServer(http.HandlerFunc(h))
	defer server1.Close()

	client := retriable.New()
	require.NotNil(t, client)

	req, err := http.NewRequest(http.MethodPost, server1.URL+"/v1/test/do", strings.NewReader(`{"test":true}`))
	require.NoError(t, err)

	client.WithPolicy(retriable.Policy{
		TotalRetryLimit: 3,
		RequestTimeout:  1 * time.Second,
		Retries: map[int]retriable.ShouldRetry{
			http.StatusServiceUnavailable: func(_ *http.Request, re_sp *http.Response, _ error, retries int) (bool, time.Duration, string) {
				return (2 >= retries), time.Millisecond, "retry"
			},
		},
	})

	res, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, 4, count)
}

func Test_RetriableBody(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		q, err := ioutil.ReadAll(r.Body)
		if err != nil {
			marshal.WriteJSON(w, r, httperror.Unexpected(err.Error()))
			return
		}
		// write request back
		w.Write(q)
	}

	server := httptest.NewServer(http.HandlerFunc(h))
	defer server.Close()

	client := retriable.New()
	require.NotNil(t, client)

	type response struct {
		Name  string
		Value string
	}

	var resBytes response

	tcases := []struct {
		name string
		req  interface{}
		res  interface{}
	}{
		{
			name: "bytes",
			req:  []byte(`{"Name":"bytes","Value":"obj"}`),
			res:  &resBytes,
		},
		{
			name: "string",
			req:  `{"Name":"string","Value":"obj"}`,
			res:  &resBytes,
		},
		{
			name: "readersekker",
			req:  strings.NewReader(`{"Name":"readersekker","Value":"obj"}`),
			res:  &resBytes,
		},
		{
			name: "reader",
			req:  &reader{s: []byte(`{"Name":"reader","Value":"obj"}`)},
			res:  &resBytes,
		},
		{
			name: "buffer",
			req:  &response{Name: "buffer", Value: "body"},
			res:  bytes.NewBuffer([]byte{}),
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := client.Request(context.Background(), http.MethodPost, []string{server.URL}, "/", tc.req, tc.res)
			require.NoError(t, err)
			switch val := tc.res.(type) {
			case *response:
				assert.Equal(t, tc.name, resBytes.Name)
			case io.Reader:
				err = marshal.Decode(val, &resBytes)
				require.NoError(t, err)
				assert.Equal(t, tc.name, resBytes.Name)
			}
		})
	}
}

type reader struct {
	s        []byte
	i        int64 // current reading index
	prevRune int   // index of previous rune; or < 0
}

// Read implements the io.Reader interface.
func (r *reader) Read(b []byte) (n int, err error) {
	if r.i >= int64(len(r.s)) {
		return 0, io.EOF
	}
	r.prevRune = -1
	n = copy(b, r.s[r.i:])
	r.i += int64(n)
	return
}

func Test_DecodeResponse(t *testing.T) {
	res := http.Response{StatusCode: http.StatusNotFound, Body: ioutil.NopCloser(bytes.NewBufferString(`{"code":"MY_CODE","message":"doesn't exist"}`))}
	c := retriable.New()

	var body map[string]string
	_, sc, err := c.DecodeResponse(&res, &body)
	require.Equal(t, res.StatusCode, sc)
	require.Error(t, err)

	ge, ok := err.(*httperror.Error)
	require.True(t, ok, "Expecting decodeResponse to map a valid error to the Error struct, but was %T %v", err, err)
	assert.Equal(t, "MY_CODE", ge.Code)
	assert.Equal(t, "doesn't exist", ge.Message)
	assert.Equal(t, http.StatusNotFound, ge.HTTPStatus)

	// if the body isn't valid json, we should get returned a json parser error, as well as the body
	invalidResponse := `["foo"}`
	res.Body = ioutil.NopCloser(bytes.NewBufferString(invalidResponse))
	_, _, err = c.DecodeResponse(&res, &body)
	require.Error(t, err)
	assert.Equal(t, invalidResponse, err.Error())

	// error body is valid json, but missing the error field
	res.Body = ioutil.NopCloser(bytes.NewBufferString(`{"foo":"bar"}`))
	_, _, err = c.DecodeResponse(&res, &body)
	assert.Error(t, err)
	assert.Equal(t, "{\"foo\":\"bar\"}", err.Error())

	// statusCode < 300, with a decodeable body
	res.StatusCode = http.StatusOK
	res.Body = ioutil.NopCloser(bytes.NewBufferString(`{"foo":"baz"}`))
	_, sc, err = c.DecodeResponse(&res, &body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, sc)
	assert.Equal(t, "baz", body["foo"], "decodeResponse hasn't correctly decoded the payload, got %+v", body)

	xlog.SetGlobalLogLevel(xlog.TRACE)

	// statusCode < 300, with a parsing error
	res.Body = ioutil.NopCloser(bytes.NewBufferString(`[}`))
	_, sc, err = c.DecodeResponse(&res, &body)
	assert.Equal(t, http.StatusOK, sc, "decodeResponse returned unexpected statusCode, expecting 200")
	assert.Error(t, err)
	assert.Equal(t, "unable to decode body response to (*map[string]string) type: invalid character '}' looking for beginning of value", err.Error())
}

func makeTestHandler(t *testing.T, expURI string, status int, responseBody string) http.Handler {
	h := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expURI, r.URL.Path, "received wrong URI")
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Add("X-Test-Header", "retriable")
		w.Header().Add("X-Test-Token", r.Header.Get("X-Test-Token"))
		w.Header().Add("X-Global", r.Header.Get("X-Global"))
		w.Header().Add("X-Request-URL", r.URL.String())
		w.Header().Add("X-Request-Method", r.Method)
		w.Header().Add(retriable.DefaultReplayNonceHeader, certutil.RandomString(8))
		w.WriteHeader(status)
		io.WriteString(w, responseBody)
	}
	return http.HandlerFunc(h)
}

func makeTestHandlerWithLimit(t *testing.T, expURI string, limit, status int, responseBody string) http.Handler {
	count := 0
	h := func(w http.ResponseWriter, r *http.Request) {
		count++
		assert.LessOrEqual(t, count, limit, "limit exceeded: count=%d, limit=%d", count, limit)
		assert.Equal(t, expURI, r.URL.Path, "received wrong URI")
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Add("X-Test-Header", "retriable")
		w.Header().Add("X-Test-Token", r.Header.Get("X-Test-Token"))
		w.WriteHeader(status)
		io.WriteString(w, responseBody)
	}
	return http.HandlerFunc(h)
}

func makeTestHandlerSlow(t *testing.T, expURI string, status int, delay time.Duration, responseBody string) http.Handler {
	h := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expURI, r.URL.Path, "received wrong URI")
		if status == 0 {
			status = http.StatusOK
		}

		time.Sleep(delay)
		w.WriteHeader(status)
		io.WriteString(w, responseBody)
	}
	return http.HandlerFunc(h)
}
