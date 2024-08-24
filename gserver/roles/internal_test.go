package roles

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func Test_tokenType(t *testing.T) {
	tcases := []struct {
		in    string
		token string
		typ   string
	}{
		{
			in:    "",
			token: "",
			typ:   "",
		},
		{
			in:    "pat.encrypted",
			token: "pat.encrypted",
			typ:   "Bearer",
		},
		{
			in:    "DPoP pat.encrypted",
			token: "pat.encrypted",
			typ:   "DPoP",
		},
		{
			in:    "Bearer pat.encrypted",
			token: "pat.encrypted",
			typ:   "Bearer",
		},
		{
			in:    "xtype pat.encrypted",
			token: "pat.encrypted",
			typ:   "xtype",
		},
	}

	for _, tc := range tcases {
		tk, typ := tokenType(tc.in)
		assert.Equal(t, tc.token, tk, "failed token for: %s", tc.in)
		assert.Equal(t, tc.typ, typ, "failed typye for: %s", tc.in)
	}
}

func Test_dumpDM(t *testing.T) {
	tcases := []struct {
		md  metadata.MD
		exp []any
	}{
		{
			md:  nil,
			exp: nil,
		},
		{
			md:  metadata.MD{},
			exp: nil,
		},
		{
			md:  metadata.New(map[string]string{"k1": "v1"}),
			exp: []any{"k1", "v1"},
		},
	}
	for _, tc := range tcases {
		vals := dumpDM(tc.md)
		assert.Equal(t, tc.exp, vals)
	}
}

func TestParseSTSTokenExpiration(t *testing.T) {
	exp, amzDate, amzExpiry, err := ParseSTSTokenExpiration("https://sts.us-west-2.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAWG7G5M3OC4MROMXA%2F20240824%2Fus-west-2%2Fsts%2Faws4_request&X-Amz-Date=20240824T113458Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=56d8506ba47302a7af22f592960317c8465e6bb4af882ebf607ad7d3fe423126")
	require.NoError(t, err)
	assert.Equal(t, "20240824T113458Z", amzDate)
	assert.Equal(t, "3600", amzExpiry)
	assert.Equal(t, "20240824T123458Z", exp.Format("20060102T150405Z"))
	assert.Equal(t, time.UTC, exp.Location())

	expu := exp.UTC()
	assert.Equal(t, "20240824T123458Z", expu.Format("20060102T150405Z"))
}
