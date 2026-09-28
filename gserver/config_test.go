package gserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseListenURLs(t *testing.T) {
	cfg := &Config{
		ListenURLs: []string{"https://trusty:2380"},
	}

	lp, err := cfg.ParseListenURLs()
	require.NoError(t, err)
	assert.Equal(t, 1, len(lp))
}

func TestConfigValidateTrustedProxyCIDRs(t *testing.T) {
	t.Parallel()
	assert.NoError(t, (&Config{TrustedProxyCIDRs: []string{"10.0.0.0/8"}}).Validate())
	err := (&Config{TrustedProxyCIDRs: []string{"invalid"}}).Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, `invalid trusted proxy CIDR "invalid"`)
}

func TestTLSInfo(t *testing.T) {
	empty := &TLSInfo{}
	assert.True(t, empty.Empty())

	i := &TLSInfo{
		CertFile:      "cert.pem",
		KeyFile:       "key.pem",
		TrustedCAFile: "cacerts.pem",
		CRLFile:       "123.crl",
	}
	assert.False(t, i.Empty())
	assert.Equal(t, "cert=cert.pem, key=key.pem, trusted-ca=cacerts.pem, client-cert-auth=false, crl-file=123.crl", i.String())
}

func TestCORSValidate(t *testing.T) {
	t.Parallel()
	enabled := true
	disabled := false
	tests := []struct {
		name    string
		cors    *CORS
		wantErr string
	}{
		{
			name: "absent configuration",
		},
		{
			name: "disabled wildcard with credentials",
			cors: &CORS{
				Enabled:          &disabled,
				AllowedOrigins:   []string{"*"},
				AllowCredentials: &enabled,
			},
		},
		{
			name: "wildcard without credentials",
			cors: &CORS{
				Enabled:        &enabled,
				AllowedOrigins: []string{"*"},
			},
		},
		{
			name: "explicit origin with credentials",
			cors: &CORS{
				Enabled:          &enabled,
				AllowedOrigins:   []string{"https://example.com"},
				AllowCredentials: &enabled,
			},
		},
		{
			name: "origin pattern with credentials",
			cors: &CORS{
				Enabled:          &enabled,
				AllowedOrigins:   []string{"https://*.example.com"},
				AllowCredentials: &enabled,
			},
		},
		{
			name: "wildcard with credentials",
			cors: &CORS{
				Enabled:          &enabled,
				AllowedOrigins:   []string{"*"},
				AllowCredentials: &enabled,
			},
			wantErr: `cors: allowed_origins "*" cannot be combined with allow_credentials; list explicit origins`,
		},
		{
			name: "wildcard among explicit origins with credentials",
			cors: &CORS{
				Enabled:          &enabled,
				AllowedOrigins:   []string{"https://example.com", "*"},
				AllowCredentials: &enabled,
			},
			wantErr: `cors: allowed_origins "*" cannot be combined with allow_credentials; list explicit origins`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cors.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	enabled := true
	disabled := false
	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name: "empty configuration",
			cfg:  &Config{},
		},
		{
			name: "invalid CORS block",
			cfg: &Config{
				CORS: &CORS{
					Enabled:          &enabled,
					AllowedOrigins:   []string{"*"},
					AllowCredentials: &enabled,
				},
			},
			wantErr: `cors: allowed_origins "*" cannot be combined with allow_credentials; list explicit origins`,
		},
		{
			name: "static headers with CORS enabled",
			cfg: &Config{
				CORS: &CORS{
					Enabled:        &enabled,
					AllowedOrigins: []string{"*"},
				},
				HTTPHeaders: map[string]string{
					"Strict-Transport-Security": "max-age=31536000",
					"Vary":                      "Accept",
				},
			},
		},
		{
			name: "CORS headers without CORS block",
			cfg: &Config{
				HTTPHeaders: map[string]string{
					"Access-Control-Allow-Origin":      "https://example.com",
					"Access-Control-Allow-Credentials": "true",
				},
			},
		},
		{
			name: "CORS headers with CORS disabled",
			cfg: &Config{
				CORS: &CORS{
					Enabled: &disabled,
				},
				HTTPHeaders: map[string]string{
					"Access-Control-Allow-Origin": "https://example.com",
				},
			},
		},
		{
			name: "credentials header with CORS enabled",
			cfg: &Config{
				CORS: &CORS{
					Enabled:        &enabled,
					AllowedOrigins: []string{"*"},
				},
				HTTPHeaders: map[string]string{
					"Access-Control-Allow-Credentials": "true",
				},
			},
			wantErr: `http_headers: "Access-Control-Allow-Credentials" cannot be set while cors is enabled; configure it in the cors block`,
		},
		{
			name: "lower-case CORS header with CORS enabled",
			cfg: &Config{
				CORS: &CORS{
					Enabled:        &enabled,
					AllowedOrigins: []string{"https://example.com"},
				},
				HTTPHeaders: map[string]string{
					"X-Frame-Options":             "DENY",
					"access-control-allow-origin": "*",
				},
			},
			wantErr: `http_headers: "access-control-allow-origin" cannot be set while cors is enabled; configure it in the cors block`,
		},
		{
			name: "first CORS header in name order is reported",
			cfg: &Config{
				CORS: &CORS{
					Enabled: &enabled,
				},
				HTTPHeaders: map[string]string{
					"Access-Control-Max-Age":        "600",
					"Access-Control-Expose-Headers": "X-Custom",
				},
			},
			wantErr: `http_headers: "Access-Control-Expose-Headers" cannot be set while cors is enabled; configure it in the cors block`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
