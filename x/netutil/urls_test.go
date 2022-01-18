package netutil

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ParseURL(t *testing.T) {
	tcases := []struct {
		in     string
		scheme string
		host   string
		port   string
		path   string
		err    string
	}{
		{"localhost", "", "", "", "localhost", ""},
		{"localhost.com:8080", "localhost.com", "", "", "", ""},
	}

	for _, tc := range tcases {
		t.Run(tc.in, func(t *testing.T) {
			u, err := url.Parse(tc.in)
			if tc.err == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.scheme, u.Scheme)
				assert.Equal(t, tc.host, u.Host)
				assert.Equal(t, tc.port, u.Port())
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func Test_ParseURLs(t *testing.T) {
	tcases := []struct {
		tname string
		hosts []string
		err   string
	}{
		{"from nil", nil, ""},
		{"from_empty", nil, ""},
		{"valid", []string{"localhost", "123.74.56.18", "ekspand.com", "ekspand.com:80"}, ""},
		{"valid with path", []string{"../dir/"}, ""},
		{"valid1 with page", []string{"foo.html"}, ""},
		{"invalid with ip", []string{"http://192.168.0.%31/"}, "error"},
		{"invalid with code", []string{"http://[fe80::%231]:8080/"}, "error"},
	}

	for _, tc := range tcases {
		t.Run(tc.tname, func(t *testing.T) {
			l, err := ParseURLs(tc.hosts)
			if tc.err == "" {
				require.NoError(t, err)
				assert.Equal(t, len(tc.hosts), len(l))
			} else {
				if !assert.Error(t, err) {
					for _, u := range l {
						t.Logf("parsed url: %s", u.String())
					}
				}
			}
		})
	}
}

func Test_ParseURLsFromString(t *testing.T) {
	tcases := []struct {
		tname string
		hosts string
		exp   int
		err   string
	}{
		{"from_empty", "", 0, ""},
		{"valid", "localhost,123.74.56.18,ekspand.com", 3, ""},
		{"valid with path", "../dir/,../dir2/", 2, ""},
		{"valid1 with page", "foo.html,foo.html", 2, ""},
		{"invalid with ip", "http://192.168.0.%31/", 0, "error"},
		{"invalid with code", "http://[fe80::%231]:8080/", 0, "error"},
	}

	for _, tc := range tcases {
		t.Run(tc.tname, func(t *testing.T) {
			l, err := ParseURLsFromString(tc.hosts)
			if tc.err == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.exp, len(l))
			} else {
				if !assert.Error(t, err) {
					for _, u := range l {
						t.Logf("parsed url: %s", u.String())
					}
				}
			}
		})
	}
}

func Test_JoinURLs(t *testing.T) {
	tcases := []struct {
		in  string
		out string
	}{
		{in: "localhost,123.74.56.18,http://ekspand.com", out: "localhost,123.74.56.18,http://ekspand.com"},
		{in: "https://123.74.56.18,unix://localhost:123456", out: "https://123.74.56.18,unix://localhost:123456"},
	}

	for _, tc := range tcases {
		t.Run(tc.in, func(t *testing.T) {
			l, err := ParseURLsFromString(tc.in)
			require.NoError(t, err)

			str := JoinURLs(l)
			assert.Equal(t, tc.out, str)
		})
	}
}
