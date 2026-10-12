package location

import (
	"context"
	"net/netip"
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

// Provider resolves the geographic location of an IP address. IPWhoIs looks
// it up over HTTP; Cache wraps any Provider and shares answers between
// addresses of the same network.
type Provider interface {
	// Location returns the place of addr. It returns nil and a nil error
	// when addr has no location: addr is not public (see IsPublic), or the
	// service does not know it. An error means the lookup failed (network,
	// timeout, quota) and may succeed later. Implementations must be safe
	// for concurrent use.
	Location(ctx context.Context, addr netip.Addr) (*Place, error)
}

// Place is the location a Provider reports for an IP address. Any field
// may be empty.
type Place struct {
	City        string `json:"city,omitempty" yaml:"city,omitempty"`
	Region      string `json:"region,omitempty" yaml:"region,omitempty"`
	Country     string `json:"country,omitempty" yaml:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty" yaml:"country_code,omitempty"`
}

// String returns "City, Region, Country" for display, skipping blank names
// and a name repeated next to itself (a city-state such as Singapore). A
// nil Place returns "".
func (p *Place) String() string {
	if p == nil {
		return ""
	}
	parts := make([]string, 0, 3)
	for _, part := range []string{p.City, p.Region, p.Country} {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if len(parts) > 0 && strings.EqualFold(parts[len(parts)-1], part) {
			continue
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

// clone returns a copy of p, so that callers cannot change a cached answer.
func (p *Place) clone() *Place {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

// globalUnicastIPv6 is the IPv6 global unicast space. Addresses outside it
// (NAT64, IPv4-compatible and other embeddings of IPv4, deprecated
// site-local, discard-only) identify no place, or a private IPv4 one.
var globalUnicastIPv6 = netip.MustParsePrefix("2000::/3")

// nonPublicPrefixes are special-purpose ranges that netip does not classify
// and that identify no place: shared inside a network (carrier-grade NAT),
// reserved, relays and tunnels, or for documentation and benchmarks.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments (Teredo, benchmarking, ORCHID)
	netip.MustParsePrefix("2001:db8::/32"),   // IPv6 documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4, embeds an IPv4 address
	netip.MustParsePrefix("3fff::/20"),       // IPv6 documentation
}

// canonical returns addr in the form Providers look up and cache: an
// IPv4-mapped IPv6 address as IPv4, without an IPv6 zone.
func canonical(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// IsPublic reports whether addr can have a location: a global unicast
// address (in 2000::/3 for IPv6) that is not private (RFC 1918, RFC 4193),
// carrier-grade NAT, or another special-purpose range. An IPv4-mapped IPv6
// address is checked as IPv4 and an IPv6 zone is ignored. Providers return
// no location for other addresses without a lookup.
func IsPublic(addr netip.Addr) bool {
	addr = canonical(addr)
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	if addr.Is6() && !globalUnicastIPv6.Contains(addr) {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// ParsePublicIP parses raw, an IP address, optionally in brackets
// ([IPv6]) or with a port (IPv4:port, [IPv6]:port), and returns it in
// canonical form (IPv4-mapped IPv6 as IPv4, no zone) when it is public (see
// IsPublic). An IPv6 address with a port needs the brackets: without them
// the port reads as the last group of the address. It returns false for
// anything else, including unbalanced brackets, brackets around IPv4 and a
// malformed port, so that such input is not sent to a lookup service.
func ParsePublicIP(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	addr, err := netip.ParseAddr(raw)
	ok := err == nil
	if !ok {
		addr, ok = parseHostAddr(raw)
	}
	if !ok || !IsPublic(addr) {
		return netip.Addr{}, false
	}
	return canonical(addr), true
}

// parseHostAddr parses raw as an address in brackets ([IPv6]) or with a port
// (IPv4:port, [IPv6]:port). Like netip.ParseAddrPort, it refuses brackets
// around IPv4.
func parseHostAddr(raw string) (netip.Addr, bool) {
	if len(raw) > 1 && raw[0] == '[' && raw[len(raw)-1] == ']' {
		addr, err := netip.ParseAddr(raw[1 : len(raw)-1])
		return addr, err == nil && addr.Is6()
	}
	addrPort, err := netip.ParseAddrPort(raw)
	return addrPort.Addr(), err == nil
}

var (
	defProvInitOnce sync.Once
	defProvider     Provider
)

// GetDefaultProvider returns the default provider. It is initialized on the
// first call and cached for subsequent calls.
func GetDefaultProvider() (Provider, error) {
	defProvInitOnce.Do(func() {
		whois, err := NewIPWhoIs(IPWhoIsConfig{BaseURL: DefaultIPWhoIsURL, Timeout: DefaultTimeout, UserAgent: DefaultUserAgent})
		if err != nil {
			logger.KV(xlog.ERROR, "reason", "NewIPWhoIs", "err", err.Error())
			return
		}
		locations, err := NewCache(whois, CacheConfig{Size: defaultCacheSize})
		if err != nil {
			logger.KV(xlog.ERROR, "reason", "NewCache", "err", err.Error())
			return
		}

		defProvider = locations
	})
	if defProvider == nil {
		return nil, errors.New("default provider not initialized")
	}
	return defProvider, nil
}

// Location returns the place of addr from the default provider.
func Location(ctx context.Context, addr netip.Addr) (*Place, error) {
	provider, err := GetDefaultProvider()
	if err != nil {
		return nil, err
	}
	return provider.Location(ctx, addr)
}
