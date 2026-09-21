package credentials

import (
	"context"

	"github.com/cockroachdb/errors"
	"google.golang.org/grpc/credentials"
)

// oauthAccess supplies PerRPCCredentials from a given token.
type oauthAccess struct {
	token string
}

// NewOauthAccess returns PerRPCCredentials that send token verbatim as the
// authorization metadata value (include the scheme, e.g. "Bearer x"). RPCs
// fail unless the connection provides PrivacyAndIntegrity security.
func NewOauthAccess(token string) credentials.PerRPCCredentials {
	return oauthAccess{token: token}
}

func (oa oauthAccess) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
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
