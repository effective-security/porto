package rpcclient_test

import (
	"net"
	"testing"

	"github.com/effective-security/porto/pkg/rpcclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	_, err := rpcclient.New(&rpcclient.Config{}, true)
	assert.EqualError(t, err, "endpoint is required in client config")

	//serv := grpc.NewServer()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer lis.Close()

	client, err := rpcclient.NewFromURL(lis.Addr().String(), true)
	require.NoError(t, err)

	assert.NotEmpty(t, client.Opts())
	assert.NotNil(t, client.Conn())

	defer client.Close()
}
