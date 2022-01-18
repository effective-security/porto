package header_test

import (
	"testing"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
)

func Test_Headers(t *testing.T) {
	assert.Equal(t, "Accept", header.Accept)
	assert.Equal(t, "application/json", header.ApplicationJSON)
	assert.Equal(t, "application/jose+json", header.ApplicationJoseJSON)
	assert.Equal(t, "application/grpc", header.ApplicationGRPC)
	assert.Equal(t, "application/timestamp-query", header.ApplicationTimestampQuery)
	assert.Equal(t, "application/timestamp-reply", header.ApplicationTimestampReply)
	assert.Equal(t, "Authorization", header.Authorization)
	assert.Equal(t, "Bearer", header.Bearer)
	assert.Equal(t, "Cache-Control", header.CacheControl)
	assert.Equal(t, "Content-Type", header.ContentType)
	assert.Equal(t, "Content-Disposition", header.ContentDisposition)
	assert.Equal(t, "If-Match", header.IfMatch)
	assert.Equal(t, "Replay-Nonce", header.ReplayNonce)
	assert.Equal(t, "text/plain", header.TextPlain)
	assert.Equal(t, "User-Agent", header.UserAgent)
	assert.Equal(t, "X-HostName", header.XHostname)
	assert.Equal(t, "X-Correlation-ID", header.XCorrelationID)
	assert.Equal(t, "X-Device-ID", header.XDeviceID)
	assert.Equal(t, "X-Filename", header.XFilename)
	assert.Equal(t, "X-Forwarded-Proto", header.XForwardedProto)
}
