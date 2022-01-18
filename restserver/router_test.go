package rest_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	rest "github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	marshal.WriteJSON(w, r, httperror.NotFound("URL: %s", r.URL.Path))
}

type handler struct {
	methods    map[string]int
	parameters map[string]int
}

func (h *handler) handle(w http.ResponseWriter, r *http.Request, p rest.Params) {
	h.methods[r.Method]++
	pv := p.ByName(r.Method)
	if pv != "" {
		h.parameters[pv]++
	}
}

func Test_Router(t *testing.T) {
	router := rest.NewRouter(notFoundHandler)
	h := &handler{
		methods:    map[string]int{},
		parameters: map[string]int{},
	}
	router.GET("/get", h.handle)
	router.GET("/get/:GET", h.handle)
	router.HEAD("/head", h.handle)
	router.OPTIONS("/options", h.handle)
	router.POST("/post", h.handle)
	router.PUT("/put", h.handle)
	router.PATCH("/patch", h.handle)
	router.DELETE("/del", h.handle)
	router.CONNECT("/", h.handle)

	assert.Equal(t, 0, h.methods[http.MethodGet])
	assert.Equal(t, 0, h.methods[http.MethodHead])
	assert.Equal(t, 0, h.methods[http.MethodOptions])
	assert.Equal(t, 0, h.methods[http.MethodPost])
	assert.Equal(t, 0, h.methods[http.MethodPut])
	assert.Equal(t, 0, h.methods[http.MethodPatch])
	assert.Equal(t, 0, h.methods[http.MethodDelete])
	assert.Equal(t, 0, h.methods[http.MethodConnect])

	rh := router.Handler()
	assert.NotNil(t, rh)

	w := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/get/GET", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodGet])

	r, err = http.NewRequest(http.MethodHead, "/head", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodHead])

	r, err = http.NewRequest(http.MethodOptions, "/options", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodOptions])

	r, err = http.NewRequest(http.MethodPost, "/post", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodPost])

	r, err = http.NewRequest(http.MethodPatch, "/patch?OTHER", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodPatch])

	r, err = http.NewRequest(http.MethodDelete, "/del?DELETE", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodDelete])

	r, err = http.NewRequest(http.MethodConnect, "/", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodConnect])

	assert.Equal(t, 1, h.parameters["GET"])
	assert.Equal(t, 0, h.parameters["DELETE"])
	assert.Equal(t, 0, h.parameters["OTHER"])
}
