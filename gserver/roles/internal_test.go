package roles

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
			md:  metadata.New(map[string]string{"k1": "v1", "k2": "v2"}),
			exp: []any{"k1", "v1", "k2", "v2"},
		},
	}
	for _, tc := range tcases {
		vals := dumpDM(tc.md)
		assert.Equal(t, tc.exp, vals)
	}
}
