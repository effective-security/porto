// Package mockappcontainer builds a go.uber.org/dig container pre-populated
// with the dependencies gserver needs (config, JWT signer/parser, discovery),
// for use in tests:
//
//	c := mockappcontainer.NewBuilder().
//		WithConfig(&gserver.Config{...}).
//		WithJwtParser(parser).
//		WithDiscovery(discovery.New()).
//		Container()
//
// Each With* call registers a provider; registering the same type twice is
// silently ignored by dig's error being discarded.
package mockappcontainer
