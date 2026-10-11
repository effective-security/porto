// Package location resolves the geographic location (city, region,
// country) of a client IP address, for example to show where a sign-in came
// from.
//
// A Provider answers for one address. IPWhoIs looks it up with the ipwho.is
// JSON API; Cache wraps any Provider, keeps a configured number of answers
// and shares each one between the addresses of a network (an IPv4 /24 or an
// IPv6 /48 by default), so a busy network costs one lookup per TTL. Private,
// loopback, carrier-grade NAT and other special-purpose addresses have no
// location and are never sent to the service (IsPublic).
//
//	func newLocationHandler() (http.HandlerFunc, error) {
//		whois, err := location.NewIPWhoIs(location.IPWhoIsConfig{})
//		if err != nil {
//			return nil, err
//		}
//		locations, err := location.NewCache(whois, location.CacheConfig{Size: 10000})
//		if err != nil {
//			return nil, err
//		}
//		return func(w http.ResponseWriter, r *http.Request) {
//			// on error place is nil; the next call for the network retries
//			place, _ := locations.Location(r.Context(), identity.ClientIPFromRequest(r))
//			fmt.Fprintln(w, place.String()) // "City, Region, Country", or "" when unknown
//		}, nil
//	}
//
// IPLocation is a one-off lookup that logs and drops errors, for callers
// that carry on without a location.
package location
