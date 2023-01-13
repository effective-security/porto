package rpcclient_test

import (
	"net"
	"testing"

	"github.com/effective-security/porto/pkg/rpcclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	_, err := rpcclient.New(&rpcclient.Config{})
	require.Error(t, err)
	assert.Equal(t, "at least one Endpoint must is required in client config", err.Error())

	//serv := grpc.NewServer()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	client, err := rpcclient.NewFromURL(lis.Addr().String())
	require.NoError(t, err)
	defer client.Close()
}
