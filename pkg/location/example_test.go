package location_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"

	"github.com/effective-security/porto/pkg/location"
)

func ExampleNewCache() {
	// a stand-in for https://ipwho.is
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"city":"Mountain View","region":"California","country":"United States","country_code":"US"}`))
	}))
	defer srv.Close()

	// leave BaseURL empty for location.DefaultIPWhoIsURL
	whois, err := location.NewIPWhoIs(location.IPWhoIsConfig{BaseURL: srv.URL})
	if err != nil {
		panic(err)
	}
	locations, err := location.NewCache(whois, location.CacheConfig{Size: 10000})
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	for _, ip := range []string{"8.8.8.8", "8.8.8.4", "10.0.0.1"} {
		// 8.8.8.4 is in the /24 of 8.8.8.8 and is answered from the cache;
		// the private 10.0.0.1 has no location and is not looked up
		place, err := locations.Location(ctx, netip.MustParseAddr(ip))
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s: %q\n", ip, place.String())
	}
	// Output:
	// 8.8.8.8: "Mountain View, California, United States"
	// 8.8.8.4: "Mountain View, California, United States"
	// 10.0.0.1: ""
}
