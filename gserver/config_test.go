package gserver

import (
	"testing"
	"time"

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

func TestRateLimitValidate(t *testing.T) {
	t.Parallel()
	enabled := true
	disabled := false
	tests := []struct {
		name    string
		rl      *RateLimit
		wantErr string
	}{
		{
			name: "absent configuration",
		},
		{
			name: "disabled without rate",
			rl:   &RateLimit{Enabled: &disabled},
		},
		{
			name: "enabled with rate",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
			},
		},
		{
			name: "enabled with known lookups and methods",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 10,
				ExpirationTTL:     time.Minute,
				HeadersIPLookups:  []string{"X-Forwarded-For", "X-Real-IP", "RemoteAddr"},
				Metods:            []string{"GET", "POST", "PROPFIND", "M-SEARCH"},
			},
		},
		{
			name: "shortest accepted TTL",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				ExpirationTTL:     time.Second,
			},
		},
		{
			name:    "enabled without rate",
			rl:      &RateLimit{Enabled: &enabled},
			wantErr: "rate_limit: requests_per_second must be positive when enabled, got 0",
		},
		{
			name: "enabled with negative rate",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: -5,
			},
			wantErr: "rate_limit: requests_per_second must be positive when enabled, got -5",
		},
		{
			name: "enabled with negative TTL",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				ExpirationTTL:     -time.Second,
			},
			wantErr: "rate_limit: expiration_ttl must not be negative, got -1s",
		},
		{
			name: "enabled with sub-second TTL",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				ExpirationTTL:     time.Millisecond,
			},
			wantErr: "rate_limit: expiration_ttl must be at least 1s, got 1ms",
		},
		{
			name: "canonical X-Real-Ip is not a tollbooth lookup",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				HeadersIPLookups:  []string{"RemoteAddr", "X-Real-Ip"},
			},
			wantErr: `rate_limit: unsupported headers_ip_lookups entry "X-Real-Ip"; use one of RemoteAddr, X-Forwarded-For, X-Real-IP`,
		},
		{
			name: "unknown lookup",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				HeadersIPLookups:  []string{"CF-Connecting-IP"},
			},
			wantErr: `rate_limit: unsupported headers_ip_lookups entry "CF-Connecting-IP"; use one of RemoteAddr, X-Forwarded-For, X-Real-IP`,
		},
		{
			name: "lower-case method never matches",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				Metods:            []string{"GET", "post"},
			},
			wantErr: `rate_limit: metods entry "post" must be an upper-case HTTP method token`,
		},
		{
			name: "empty method",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				Metods:            []string{""},
			},
			wantErr: `rate_limit: metods entry "" must be an upper-case HTTP method token`,
		},
		{
			name: "method with trailing space",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				Metods:            []string{"GET "},
			},
			wantErr: `rate_limit: metods entry "GET " must be an upper-case HTTP method token`,
		},
		{
			name: "comma-joined methods",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				Metods:            []string{"GET,POST"},
			},
			wantErr: `rate_limit: metods entry "GET,POST" must be an upper-case HTTP method token`,
		},
		{
			name: "slash-joined methods",
			rl: &RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				Metods:            []string{"GET/POST"},
			},
			wantErr: `rate_limit: metods entry "GET/POST" must be an upper-case HTTP method token`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.rl.Validate()
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
			name: "rate limit enabled without rate",
			cfg: &Config{
				RateLimit: &RateLimit{Enabled: &enabled},
			},
			wantErr: "rate_limit: requests_per_second must be positive when enabled, got 0",
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
