package ready

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

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
	w.Write(th.responseBody)
}
