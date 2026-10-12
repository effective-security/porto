package location_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/effective-security/porto/pkg/location"
	"github.com/stretchr/testify/assert"
)

func TestPlaceString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		place *location.Place
		want  string
	}{
		{
			name: "city region country",
			place: &location.Place{
				City:        "San Jose",
				Region:      "California",
				Country:     "United States",
				CountryCode: "US",
			},
			want: "San Jose, California, United States",
		},
		{
			name: "repeated city-state",
			place: &location.Place{
				City:    "Singapore",
				Region:  "singapore",
				Country: "Singapore",
			},
			want: "Singapore",
		},
		{
			name: "blank region",
			place: &location.Place{
				City:    "Paris",
				Region:  "  ",
				Country: "France",
			},
			want: "Paris, France",
		},
		{
			name: "repeat only next to itself",
			place: &location.Place{
				City:    "Luxembourg",
				Region:  "Canton de Luxembourg",
				Country: "Luxembourg",
			},
			want: "Luxembourg, Canton de Luxembourg, Luxembourg",
		},
		{
			name:  "all blank",
			place: &location.Place{CountryCode: "US"},
			want:  "",
		},
		{
			name: "nil",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.place.String())
		})
	}
}

func TestParsePublicIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want string
	}{
		{raw: "8.8.8.8", want: "8.8.8.8"},
		{raw: "  8.8.8.8  ", want: "8.8.8.8"},
		{raw: "8.8.8.8:443", want: "8.8.8.8"},
		{raw: "::ffff:8.8.8.8", want: "8.8.8.8"},
		{raw: "[::ffff:8.8.8.8]:443", want: "8.8.8.8"},
		{raw: "2001:4860:4860::8888", want: "2001:4860:4860::8888"},
		{raw: "[2001:4860:4860::8888]", want: "2001:4860:4860::8888"},
		{raw: "[2001:4860:4860::8888]:443", want: "2001:4860:4860::8888"},
		{raw: "2001:4860:4860::8888%eth0", want: "2001:4860:4860::8888"},
		{raw: "172.32.0.1", want: "172.32.0.1"},
		{raw: "100.128.0.1", want: "100.128.0.1"},
		{raw: ""},
		{raw: "not-an-ip"},
		{raw: "8.8.8.8:443:1"},
		{raw: "[8.8.8.8"},
		{raw: "8.8.8.8]"},
		{raw: "[2001:4860:4860::8888"},
		{raw: "2001:4860:4860::8888]"},
		{raw: "[[2001:4860:4860::8888]]"},
		{raw: "[]"},
		{raw: "["},
		{raw: "[::ffff:8.8.8.8]", want: "8.8.8.8"},
		{raw: "[2001:4860:4860::8888%eth0]:443", want: "2001:4860:4860::8888"},
		{raw: "[8.8.8.8]"},
		{raw: "[8.8.8.8]:443"},
		{raw: "8.8.8.8:"},
		{raw: "8.8.8.8:abc"},
		{raw: "8.8.8.8:99999"},
		{raw: "8.8.8.8:-1"},
		{raw: "8.8.8.8: 443"},
		{raw: "2001:4860:4860:0:0:0:0:8888:443"},
		{raw: "[fe80::1%eth0]:443"},
		{raw: "127.0.0.1"},
		{raw: "10.1.2.3"},
		{raw: "172.16.5.1"},
		{raw: "192.168.0.1"},
		{raw: "::ffff:192.168.0.1"},
		{raw: "100.64.0.1"},
		{raw: "169.254.1.1"},
		{raw: "0.0.0.0"},
		{raw: "0.1.2.3"},
		{raw: "192.0.0.8"},
		{raw: "192.0.2.1"},
		{raw: "198.18.0.1"},
		{raw: "198.51.100.7"},
		{raw: "203.0.113.9"},
		{raw: "224.0.0.1"},
		{raw: "240.0.0.1"},
		{raw: "255.255.255.255"},
		{raw: "::"},
		{raw: "::1"},
		{raw: "fc00::1"},
		{raw: "fe80::1"},
		{raw: "fe80::1%eth0"},
		{raw: "ff02::1"},
		{raw: "2001:db8::1"},
		{raw: "3fff::1"},
		{raw: "64:ff9b::a00:1"},
		{raw: "::ffff:0:a00:1"},
		{raw: "::8.8.8.8"},
		{raw: "2002:a00:1::1"},
		{raw: "2001::1"},
		{raw: "2001:2::1"},
		{raw: "2001:10::1"},
		{raw: "fec0::1"},
		{raw: "100::1"},
		{raw: "5f00::1"},
		{raw: "192.88.99.1"},
		{raw: "2a00:1450:4001::1", want: "2a00:1450:4001::1"},
		{raw: "2600::1", want: "2600::1"},
	}
	for _, tt := range tests {
		name := tt.raw
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			addr, ok := location.ParsePublicIP(tt.raw)
			if tt.want == "" {
				assert.False(t, ok)
				assert.False(t, addr.IsValid())
				return
			}
			assert.True(t, ok)
			assert.Equal(t, netip.MustParseAddr(tt.want), addr)
		})
	}
}

func TestIsPublic(t *testing.T) {
	t.Parallel()

	assert.False(t, location.IsPublic(netip.Addr{}))
	assert.True(t, location.IsPublic(netip.MustParseAddr("8.8.8.8")))
	assert.True(t, location.IsPublic(netip.MustParseAddr("::ffff:8.8.8.8")))
	assert.False(t, location.IsPublic(netip.MustParseAddr("::ffff:10.0.0.1")))
	assert.True(t, location.IsPublic(netip.MustParseAddr("2001:4860::1%eth0")))
}

func TestGetDefaultProvider(t *testing.T) {
	t.Parallel()

	provider, err := location.GetDefaultProvider()
	assert.NoError(t, err)
	assert.NotNil(t, provider)

	provider2, err := location.GetDefaultProvider()
	assert.NoError(t, err)
	assert.NotNil(t, provider2)

	assert.Equal(t, provider, provider2)
}

func TestLocationSkipsNonPublic(t *testing.T) {
	t.Parallel()
	place, err := location.Location(context.Background(), netip.MustParseAddr("127.0.0.1"))
	assert.NoError(t, err)
	assert.Nil(t, place)
}
