// Package credentials implements gRPC transport and per-RPC credentials for
// porto clients and servers.
//
// NewBundle wraps a *tls.Config into a grpccredentials.Bundle whose
// PerRPCCredentials attaches an "authorization" metadata entry to every RPC.
// The token can be set statically with Bundle.UpdateAuthToken, refreshed on
// expiry through a CallerIdentity provider (Bundle.WithCallerIdentity, used for
// AWS STS presigned tokens), and for "DPoP" tokens a proof header is signed per
// call when a dpop.Signer is supplied with Bundle.WithDPoP.
//
//	b := credentials.NewBundle(credentials.Config{TLSConfig: tlsCfg})
//	b.UpdateAuthToken(credentials.Token{TokenType: "Bearer", AccessToken: jwt})
//	conn, err := grpc.NewClient(target,
//		grpc.WithTransportCredentials(b.TransportCredentials()),
//		grpc.WithPerRPCCredentials(b.PerRPCCredentials()))
//
// NewOauthAccess is a simpler PerRPCCredentials that sends a fixed, already
// formatted authorization value and requires a PrivacyAndIntegrity transport.
package credentials
