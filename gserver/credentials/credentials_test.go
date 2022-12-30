package credentials_test

import (
	"context"
	"testing"

	"github.com/effective-security/porto/gserver/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOauthAccess(t *testing.T) {
	perRPS := credentials.NewOauthAccess("1234")
	assert.True(t, perRPS.RequireTransportSecurity())

	md, err := perRPS.GetRequestMetadata(context.Background(), "url1")
	require.Error(t, err)
	assert.Equal(t, "unable to transfer oauthAccess PerRPCCredentials: AuthInfo is nil", err.Error())
	assert.Empty(t, md)
}

func TestBundle(t *testing.T) {
	b := credentials.NewBundle(credentials.Config{})
	_, _ = b.NewWithMode("noop")
	b.UpdateAuthToken("1234")

	prpc := b.PerRPCCredentials()
	md, err := prpc.GetRequestMetadata(context.Background(), "notused")
	require.NoError(t, err)
	assert.Equal(t, "1234", md[credentials.TokenFieldNameGRPC])

	tc := b.TransportCredentials()
	tc.Info()
	_ = tc.Clone()
	_ = tc.OverrideServerName("localhost")
}
