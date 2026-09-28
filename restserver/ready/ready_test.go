package ready

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type serviceWithReady struct {
	isReady bool
	lock    sync.RWMutex
}

// IsReady returns true when the service is ready to sign
func (s *serviceWithReady) IsReady() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.isReady
}

// SetReady changes the service status whether it is ready to sign
func (s *serviceWithReady) SetReady(ready bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	s.isReady = ready
}

func Test_ServiceStatusVerifier(t *testing.T) {
	handler := testHandler{t, http.StatusOK, []byte("OK")}

	s := new(serviceWithReady)

	sv := NewServiceStatusVerifier(s, &handler)

	req, err := http.NewRequest(http.MethodGet, "/foo", nil)
	res := httptest.NewRecorder()
	require.NoError(t, err)

	sv.ServeHTTP(res, req)
	assert.Equal(t, http.StatusServiceUnavailable, res.Code, "Request should be denied but got HTTP StatusCode %d", res.Code)

	res = httptest.NewRecorder()
	require.NoError(t, err)

	s.SetReady(true)
	sv.ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code, "Request should be allowed but got HTTP StatusCode %d", res.Code)
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
	_, _ = w.Write(th.responseBody)
}

func Test_ServiceStatusVerifier_NotReadyBody(t *testing.T) {
	t.Parallel()
	handler := testHandler{t, http.StatusOK, []byte("OK")}
	sv := NewServiceStatusVerifier(new(serviceWithReady), &handler)

	notReady := func(ctx context.Context) *httptest.ResponseRecorder {
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/foo", nil).WithContext(ctx)
		sv.ServeHTTP(res, req)
		assert.Equal(t, http.StatusServiceUnavailable, res.Code)
		assert.Equal(t, header.ApplicationJSON, res.Header().Get(header.ContentType))
		return res
	}

	res := notReady(context.Background())
	assert.Equal(t, `{"code":"not_ready","message":"the service is not ready yet"}`, res.Body.String())

	// Every response carries its own request ID; the first one is not baked in.
	const requests = 8
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := correlation.WithID(context.Background())
			cid := correlation.ID(ctx)
			res := notReady(ctx)
			assert.Equal(t, fmt.Sprintf(`{"code":"not_ready","request_id":"%s","message":"the service is not ready yet"}`, cid), res.Body.String())
		}()
	}
	wg.Wait()

	res = notReady(context.Background())
	assert.Equal(t, `{"code":"not_ready","message":"the service is not ready yet"}`, res.Body.String())
}
