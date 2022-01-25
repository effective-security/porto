package credentials

import (
	"context"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
)

// oauthAccess supplies PerRPCCredentials from a given token.
type oauthAccess struct {
	token string
}

// NewOauthAccess constructs the PerRPCCredentials using a given token.
func NewOauthAccess(token string) credentials.PerRPCCredentials {
	return oauthAccess{token: token}
}

func (oa oauthAccess) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	ri, _ := credentials.RequestInfoFromContext(ctx)
	if err := credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
		return nil, errors.WithMessagef(err, "unable to transfer oauthAccess PerRPCCredentials")
	}
	return map[string]string{
		TokenFieldNameGRPC: oa.token,
	}, nil
}

func (oa oauthAccess) RequireTransportSecurity() bool {
	return true
}
