package identity

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestRealIP(t *testing.T) {
	// Create type and function for testing
	type testIP struct {
		name     string
		request  *http.Request
		expected string
	}

	newRequest := func(remoteAddr, xRealIP string, xForwardedFor ...string) *http.Request {
		h := http.Header{}
		h.Set("X-Real-IP", xRealIP)
		for _, address := range xForwardedFor {
			h.Set("X-Forwarded-For", address)
		}

		return &http.Request{
			RemoteAddr: remoteAddr,
			Header:     h,
		}
	}

	// Create test data
	publicAddr1 := "144.12.54.87"
	publicAddr2 := "119.14.55.11"
	localAddr := "127.0.0.0"

	testData := []testIP{
		{
			name:     "No header",
			request:  newRequest(publicAddr1, ""),
			expected: publicAddr1,
		}, {
			name:     "Has X-Forwarded-For",
			request:  newRequest("", "", publicAddr1),
			expected: publicAddr1,
		}, {
			name:     "Has multiple X-Forwarded-For",
			request:  newRequest("", "", localAddr, publicAddr1, publicAddr2),
			expected: publicAddr2,
		}, {
			name:     "Has X-Real-IP",
			request:  newRequest("", publicAddr1),
			expected: publicAddr1,
		},
	}

	// Run test
	for _, v := range testData {
		t.Run(v.name, func(t *testing.T) {
			actual := ClientIPFromRequest(v.request)
			assert.Equal(t, v.expected, actual)
		})
	}
}

func TestClientIPFromGRPC(t *testing.T) {
	ctx := context.Background()
	actual := ClientIPFromGRPC(ctx)
	assert.Equal(t, "", actual)

	publicAddr1 := "144.12.54.87"
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-forwarded-for", publicAddr1))
	actual = ClientIPFromGRPC(ctx)
	assert.Equal(t, publicAddr1, actual)

	publicAddr2 := "119.14.55.11"
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-real-ip", publicAddr2))
	actual = ClientIPFromGRPC(ctx)
	assert.Equal(t, publicAddr2, actual)

	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-forwarded-for", publicAddr1, "x-real-ip", publicAddr2))
	actual = ClientIPFromGRPC(ctx)
	assert.Equal(t, publicAddr1, actual)
}
