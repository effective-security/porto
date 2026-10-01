// Package revocation provides a revocation service for JWT tokens.
// It implements jwt.Revocation interface and uses a cache.Provider to store the revoked tokens.
// Example:
//
//	func provideJwt(cfg *config.Configuration, dp dataprotection.Provider, cache cache.Provider) (jwt.Parser, jwt.Signer, error) {
//		var provider jwt.Provider
//		var err error
//		if cfg.Auth.JWT != "" {
//			provider, err = jwt.LoadProvider(cfg.Auth.JWT, nil)
//			if err != nil {
//				return nil, nil, err
//			}
//		}
//		// we encrypt Personal Access Token (pat.),
//		// the accesstoken provider handles both, encrypted PAT and plain JWT
//		at := accesstoken.New(dp, provider)
//		at.SetRevocation(revocation.New(cache))
//		return at, at, nil
//	}
package revocation
