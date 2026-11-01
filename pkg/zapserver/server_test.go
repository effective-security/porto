package zapserver_test

import (
	"context"
	"testing"

	"github.com/effective-security/porto/pkg/zapserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type echoIn struct {
	Message string `json:"message"`
}

type echoOut struct {
	Reply string `json:"reply"`
}

func TestZapServerInit(t *testing.T) {
	cfg := zapserver.Config{
		AppName:    "test-service",
		ListenAddr: "127.0.0.1:0",
	}

	srv := zapserver.New(cfg)
	require.NotNil(t, srv)
	assert.True(t, srv.IsReady())
	assert.Contains(t, srv.String(), "test-service")
	assert.NotNil(t, srv.App())

	zapserver.RegisterOperation(srv, "/v1/echo", func(ctx context.Context, in *echoIn) (*echoOut, error) {
		return &echoOut{Reply: "echo: " + in.Message}, nil
	})

	zapserver.RegisterGet(srv, "/v1/health", func(ctx context.Context, _ *struct{}) (*struct{ Status string }, error) {
		return &struct{ Status string }{Status: "ok"}, nil
	})
}
