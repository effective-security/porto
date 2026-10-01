package roles

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/cockroachdb/errors"
	tcredentials "github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

const testSTSHost = "https://sts.us-west-2.amazonaws.com"

// stsURL returns a presigned GetCallerIdentity URL on host signed at date
// for expires seconds.
func stsURL(host string, date time.Time, expires string) string {
	return host + "/?Action=GetCallerIdentity&Version=2011-06-15" +
		"&X-Amz-Date=" + tcredentials.TimeISO8601(date.UTC()) +
		"&X-Amz-Expires=" + expires + "&X-Amz-Signature=sig"
}

func encodeAWSToken(presignedURL string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(presignedURL))
}

// TestAWSIdentityRejects checks the AWS4 tokens and STS responses that
// awsIdentity rejects, and how many STS calls each one makes.
func TestAWSIdentityRejects(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tests := []struct {
		name    string
		token   string
		respond func(*http.Request) (*http.Response, error)
		allowed []string
		wantErr string
		// wantCalls is the number of STS calls made by two lookups
		wantCalls int32
	}{
		{
			name:    "not base64",
			token:   "not base64!",
			wantErr: "invalid AWS4 token: illegal base64 data",
		},
		{
			name:    "no expiry",
			token:   encodeAWSToken(testSTSHost + "/?Action=GetCallerIdentity&X-Amz-Date=20240824T113458Z"),
			wantErr: "failed to parse AWS4 token: invalid presigned URL: missing X-Amz-Date or X-Amz-Expires",
		},
		{
			name:    "not an STS host",
			token:   encodeAWSToken(stsURL("https://sts.example.com", now, "900")),
			wantErr: `invalid AWS4 token: presigned URL host "sts.example.com" is not an AWS STS endpoint`,
		},
		{
			name:      "expired",
			token:     encodeAWSToken(stsURL(testSTSHost, now.Add(-time.Hour), "60")),
			respond:   stsResponse(http.StatusOK, testAWSBody),
			wantErr:   "AWS4 token has expired on",
			wantCalls: 1,
		},
		{
			name:      "account not allowed",
			token:     encodeAWSToken(stsURL(testSTSHost, now, "900")),
			respond:   stsResponse(http.StatusOK, testAWSBody),
			allowed:   []string{"999999999999"},
			wantErr:   `AWS account "123456789012" is not allowed`,
			wantCalls: 1,
		},
		{
			name:  "invalid ARN",
			token: encodeAWSToken(stsURL(testSTSHost, now, "900")),
			respond: stsResponse(http.StatusOK,
				`{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Account":"123456789012","Arn":"not-an-arn"}}}`),
			wantErr:   "failed to parse AWS ARN",
			wantCalls: 1,
		},
		{
			// a body read error is a transport failure: it is not cached
			name:  "unreadable body",
			token: encodeAWSToken(stsURL(testSTSHost, now, "900")),
			respond: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header:     http.Header{},
					Body:       io.NopCloser(iotest.ErrReader(errors.New("connection reset"))),
					Request:    r,
				}, nil
			},
			wantErr:   "failed to decode AWS response: connection reset",
			wantCalls: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sts := &stsTransport{respond: tt.respond}
			p := newAWSProvider(t, sts)
			p.config.AWS.AllowedAccounts = tt.allowed

			for range 2 {
				id, err := p.awsIdentity(context.Background(), tt.token, awsTokenType)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, id)
			}
			assert.Equal(t, tt.wantCalls, sts.calls.Load())
		})
	}
}

// TestAWSIdentityStrict checks that an AWS4 token STS rejects fails the
// request in Strict mode and falls back to the guest identity otherwise,
// on HTTP and gRPC, and that gRPC accepts a valid token from the
// authorization metadata.
func TestAWSIdentityStrict(t *testing.T) {
	t.Parallel()
	good := encodeAWSToken(stsURL(testSTSHost, time.Now(), "900"))
	bad := encodeAWSToken(stsURL(testSTSHost, time.Now(), "901"))
	sts := &stsTransport{respond: func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.RawQuery, "X-Amz-Expires=901") {
			return stsResponse(http.StatusForbidden, `{"Error":{"Code":"SignatureDoesNotMatch"}}`)(r)
		}
		return stsResponse(http.StatusOK, testAWSBody)(r)
	}}
	const wantErr = "failed to get Caller Identity from AWS: 403 Forbidden"

	for _, strict := range []bool{false, true} {
		p := newAWSProvider(t, sts)
		p.config.Strict = strict
		p.config.DebugLogs = true

		r, err := http.NewRequest(http.MethodGet, "/", nil)
		require.NoError(t, err)
		r.Header.Set(header.Authorization, awsTokenType+" "+bad)
		id, err := p.IdentityFromRequest(r)
		grpcCtx := metadata.NewIncomingContext(context.Background(),
			metadata.Pairs(tcredentials.TokenFieldNameGRPC, awsTokenType+" "+bad))
		grpcID, grpcErr := p.IdentityFromContext(grpcCtx, "/test")
		if strict {
			assert.ErrorContains(t, err, wantErr)
			assert.Nil(t, id)
			assert.ErrorContains(t, grpcErr, wantErr)
			assert.Nil(t, grpcID)
		} else {
			require.NoError(t, err)
			assert.Equal(t, GuestRoleName, id.Role())
			require.NoError(t, grpcErr)
			assert.Equal(t, GuestRoleName, grpcID.Role())
		}

		grpcCtx = metadata.NewIncomingContext(context.Background(),
			metadata.Pairs(tcredentials.TokenFieldNameGRPC, awsTokenType+" "+good))
		grpcID, err = p.IdentityFromContext(grpcCtx, "/test")
		require.NoError(t, err)
		assert.Equal(t, "deployer", grpcID.Role())
		assert.Equal(t, testAWSSubject, grpcID.Subject())
		assert.Equal(t, identity.MethodAWS, grpcID.AuthMethod())
	}
}
