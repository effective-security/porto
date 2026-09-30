package credentials_test

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOauthAccess(t *testing.T) {
	perRPS := credentials.NewOauthAccess("1234")
	assert.True(t, perRPS.RequireTransportSecurity())

	md, err := perRPS.GetRequestMetadata(context.Background(), "url1")
	require.Error(t, err)
	assert.Equal(t, "unable to transfer oauthAccess PerRPCCredentials: AuthInfo is nil", err.Error())
	assert.Empty(t, md)
}

func TestBundle(t *testing.T) {
	b := credentials.NewBundle(credentials.Config{})
	b.UpdateAuthToken(credentials.Token{TokenType: "Bearer", AccessToken: "1234"})

	prpc := b.PerRPCCredentials()
	md, err := prpc.GetRequestMetadata(context.Background(), "notused")
	require.NoError(t, err)
	assert.Equal(t, "Bearer 1234", md[credentials.TokenFieldNameGRPC])

	tc := b.TransportCredentials()
	assert.NotNil(t, tc.Info())
	assert.NotNil(t, tc.Clone())
	err = tc.OverrideServerName("localhost")
	assert.NoError(t, err)
}

func TestBundleNewWithMode(t *testing.T) {
	t.Parallel()

	b := credentials.NewBundle(credentials.Config{})
	nb, err := b.NewWithMode("balancer")
	require.EqualError(t, err, `credentials bundle mode "balancer" is not supported`)
	assert.Nil(t, nb)
}

// metadataResult is the outcome of one GetRequestMetadata call.
type metadataResult struct {
	md  map[string]string
	err error
}

// gatedProvider returns "token-<n>" on its n-th call once release is closed,
// or the context error if ctx ends first. ttl sets the token expiry; zero
// leaves Expires nil.
type gatedProvider struct {
	calls   atomic.Int32
	release chan struct{}
	ttl     time.Duration
}

func (p *gatedProvider) GetCallerIdentity(ctx context.Context) (*credentials.Token, error) {
	n := p.calls.Add(1)
	select {
	case <-p.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	token := &credentials.Token{
		TokenType:   "Bearer",
		AccessToken: fmt.Sprintf("token-%d", n),
	}
	if p.ttl > 0 {
		expires := time.Now().Add(p.ttl)
		token.Expires = &expires
	}
	return token, nil
}

func TestPerRPCRefreshSharedCall(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		ttl  time.Duration
	}{
		{name: "no_expiry"},
		// a token that expires within a minute is Expired as soon as it is
		// stored; the waiters still take it from the shared call
		{name: "short_lived", ttl: 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				provider := &gatedProvider{release: make(chan struct{}), ttl: tc.ttl}
				b := credentials.NewBundle(credentials.Config{})
				b.WithCallerIdentity(provider)
				rc := b.PerRPCCredentials()

				const callers = 8
				results := make(chan metadataResult, callers)
				for range callers {
					go func() {
						md, err := rc.GetRequestMetadata(context.Background())
						results <- metadataResult{md: md, err: err}
					}()
				}
				synctest.Wait()
				assert.Equal(t, int32(1), provider.calls.Load())

				close(provider.release)
				for range callers {
					res := <-results
					require.NoError(t, res.err)
					assert.Equal(t, map[string]string{credentials.TokenFieldNameGRPC: "Bearer token-1"}, res.md)
				}
				assert.Equal(t, int32(1), provider.calls.Load())
			})
		})
	}
}

func TestPerRPCRefreshReusesToken(t *testing.T) {
	t.Parallel()

	provider := &gatedProvider{release: make(chan struct{})}
	close(provider.release)
	b := credentials.NewBundle(credentials.Config{})
	b.WithCallerIdentity(provider)
	rc := b.PerRPCCredentials()

	for range 3 {
		md, err := rc.GetRequestMetadata(context.Background())
		require.NoError(t, err)
		assert.Equal(t, map[string]string{credentials.TokenFieldNameGRPC: "Bearer token-1"}, md)
	}
	// a token without Expires is cached for CacheTTL
	assert.Equal(t, int32(1), provider.calls.Load())
}

// cancelFirstProvider blocks its first call until ctx ends and returns the
// context error; later calls return "token-<n>".
type cancelFirstProvider struct {
	calls atomic.Int32
}

func (p *cancelFirstProvider) GetCallerIdentity(ctx context.Context) (*credentials.Token, error) {
	n := p.calls.Add(1)
	if n == 1 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &credentials.Token{
		TokenType:   "Bearer",
		AccessToken: fmt.Sprintf("token-%d", n),
	}, nil
}

func TestPerRPCRefreshAfterCallerCanceled(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		provider := &cancelFirstProvider{}
		b := credentials.NewBundle(credentials.Config{})
		b.WithCallerIdentity(provider)
		rc := b.PerRPCCredentials()

		firstCtx, cancelFirst := context.WithCancel(context.Background())
		defer cancelFirst()
		first := make(chan error, 1)
		go func() {
			_, err := rc.GetRequestMetadata(firstCtx)
			first <- err
		}()
		synctest.Wait()

		second := make(chan metadataResult, 1)
		go func() {
			md, err := rc.GetRequestMetadata(context.Background())
			second <- metadataResult{md: md, err: err}
		}()
		synctest.Wait()
		assert.Equal(t, int32(1), provider.calls.Load())

		cancelFirst()
		err := <-first
		require.ErrorIs(t, err, context.Canceled)
		assert.EqualError(t, err, "unable to get caller identity: context canceled")

		res := <-second
		require.NoError(t, res.err)
		assert.Equal(t, map[string]string{credentials.TokenFieldNameGRPC: "Bearer token-2"}, res.md)
		assert.Equal(t, int32(2), provider.calls.Load())
	})
}

func TestPerRPCRefreshWaiterDeadline(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		provider := &gatedProvider{release: make(chan struct{})}
		b := credentials.NewBundle(credentials.Config{})
		b.WithCallerIdentity(provider)
		rc := b.PerRPCCredentials()

		first := make(chan metadataResult, 1)
		go func() {
			md, err := rc.GetRequestMetadata(context.Background())
			first <- metadataResult{md: md, err: err}
		}()
		synctest.Wait()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		md, err := rc.GetRequestMetadata(ctx)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, md)

		close(provider.release)
		res := <-first
		require.NoError(t, res.err)
		assert.Equal(t, map[string]string{credentials.TokenFieldNameGRPC: "Bearer token-1"}, res.md)
		assert.Equal(t, int32(1), provider.calls.Load())
	})
}

// scriptedProvider blocks each call until release is closed and then
// returns its result; calls counts the calls.
type scriptedProvider struct {
	calls   atomic.Int32
	release chan struct{}
	token   string
	err     error
	panics  atomic.Bool
}

func (p *scriptedProvider) GetCallerIdentity(context.Context) (*credentials.Token, error) {
	p.calls.Add(1)
	<-p.release
	if p.panics.Load() {
		panic("provider failure")
	}
	if p.err != nil {
		return nil, p.err
	}
	return &credentials.Token{
		TokenType:   "Bearer",
		AccessToken: p.token,
	}, nil
}

func TestPerRPCRefreshSharedError(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		errBoom := errors.New("boom")
		provider := &scriptedProvider{release: make(chan struct{}), err: errBoom}
		b := credentials.NewBundle(credentials.Config{})
		b.WithCallerIdentity(provider)
		rc := b.PerRPCCredentials()

		const callers = 4
		results := make(chan metadataResult, callers)
		for range callers {
			go func() {
				md, err := rc.GetRequestMetadata(context.Background())
				results <- metadataResult{md: md, err: err}
			}()
		}
		synctest.Wait()
		close(provider.release)
		for range callers {
			res := <-results
			require.EqualError(t, res.err, "unable to get caller identity: boom")
			assert.ErrorIs(t, res.err, errBoom)
			assert.Nil(t, res.md)
		}
		assert.Equal(t, int32(1), provider.calls.Load())
	})
}

func TestPerRPCRefreshProviderPanic(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		provider := &scriptedProvider{release: make(chan struct{}), token: "next"}
		provider.panics.Store(true)
		b := credentials.NewBundle(credentials.Config{})
		b.WithCallerIdentity(provider)
		rc := b.PerRPCCredentials()

		leader := make(chan any, 1)
		go func() {
			defer func() { leader <- recover() }()
			_, _ = rc.GetRequestMetadata(context.Background())
		}()
		synctest.Wait()
		waiter := make(chan metadataResult, 1)
		go func() {
			md, err := rc.GetRequestMetadata(context.Background())
			waiter <- metadataResult{md: md, err: err}
		}()
		synctest.Wait()

		close(provider.release)
		// the panic reaches the RPC that made the call
		assert.Equal(t, "provider failure", <-leader)
		res := <-waiter
		require.EqualError(t, res.err, "caller identity provider panicked")
		assert.Nil(t, res.md)

		// the next RPC calls the provider again instead of waiting forever
		provider.panics.Store(false)
		md, err := rc.GetRequestMetadata(context.Background())
		require.NoError(t, err)
		assert.Equal(t, map[string]string{credentials.TokenFieldNameGRPC: "Bearer next"}, md)
		assert.Equal(t, int32(2), provider.calls.Load())
	})
}

func TestPerRPCRefreshProviderReplaced(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		oldProvider := &scriptedProvider{release: make(chan struct{}), token: "old"}
		b := credentials.NewBundle(credentials.Config{})
		b.WithCallerIdentity(oldProvider)
		rc := b.PerRPCCredentials()

		const callers = 3
		results := make(chan metadataResult, callers)
		for range callers {
			go func() {
				md, err := rc.GetRequestMetadata(context.Background())
				results <- metadataResult{md: md, err: err}
			}()
		}
		synctest.Wait()
		assert.Equal(t, int32(1), oldProvider.calls.Load())

		newProvider := &scriptedProvider{release: make(chan struct{}), token: "new"}
		close(newProvider.release)
		b.WithCallerIdentity(newProvider)
		md, err := rc.GetRequestMetadata(context.Background())
		require.NoError(t, err)
		assert.Equal(t, map[string]string{credentials.TokenFieldNameGRPC: "Bearer new"}, md)

		// the old call's result is discarded, including for the RPC that made it
		close(oldProvider.release)
		for range callers {
			res := <-results
			require.NoError(t, res.err)
			assert.Equal(t, map[string]string{credentials.TokenFieldNameGRPC: "Bearer new"}, res.md)
		}
		md, err = rc.GetRequestMetadata(context.Background())
		require.NoError(t, err)
		assert.Equal(t, map[string]string{credentials.TokenFieldNameGRPC: "Bearer new"}, md)
		assert.Equal(t, int32(1), oldProvider.calls.Load())
		assert.Equal(t, int32(1), newProvider.calls.Load())
	})
}

func TestUpdateAuthTokenCopiesExpiry(t *testing.T) {
	t.Parallel()

	provider := &staticProvider{token: &credentials.Token{TokenType: "Bearer", AccessToken: "refreshed"}}
	expires := time.Now().Add(time.Hour)
	b := credentials.NewBundle(credentials.Config{})
	b.WithCallerIdentity(provider)
	b.UpdateAuthToken(credentials.Token{
		TokenType:   "Bearer",
		AccessToken: "set",
		Expires:     &expires,
	})
	// changing the caller's time afterwards does not expire the stored token
	expires = time.Now().Add(-time.Hour)

	md, err := b.PerRPCCredentials().GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]string{credentials.TokenFieldNameGRPC: "Bearer set"}, md)
	assert.Equal(t, int32(0), provider.calls.Load())
}

// staticProvider returns token and err from every call.
type staticProvider struct {
	calls atomic.Int32
	token *credentials.Token
	err   error
}

func (p *staticProvider) GetCallerIdentity(context.Context) (*credentials.Token, error) {
	p.calls.Add(1)
	return p.token, p.err
}

func TestPerRPCRefreshErrors(t *testing.T) {
	t.Parallel()

	errBoom := errors.New("boom")
	for _, tc := range []struct {
		name     string
		provider *staticProvider
		err      string
	}{
		{
			name:     "provider_error",
			provider: &staticProvider{err: errBoom},
			err:      "unable to get caller identity: boom",
		},
		{
			name:     "nil_token",
			provider: &staticProvider{},
			err:      "caller identity returned no token",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := credentials.NewBundle(credentials.Config{})
			b.WithCallerIdentity(tc.provider)
			rc := b.PerRPCCredentials()

			for range 2 {
				md, err := rc.GetRequestMetadata(context.Background())
				require.EqualError(t, err, tc.err)
				assert.Nil(t, md)
			}
			// a failed call is not cached
			assert.Equal(t, int32(2), tc.provider.calls.Load())
		})
	}

	t.Run("wraps_provider_error", func(t *testing.T) {
		t.Parallel()

		b := credentials.NewBundle(credentials.Config{})
		b.WithCallerIdentity(&staticProvider{err: errBoom})
		_, err := b.PerRPCCredentials().GetRequestMetadata(context.Background())
		assert.ErrorIs(t, err, errBoom)
	})

	t.Run("empty_token", func(t *testing.T) {
		t.Parallel()

		provider := &staticProvider{token: &credentials.Token{TokenType: "Bearer"}}
		b := credentials.NewBundle(credentials.Config{})
		b.WithCallerIdentity(provider)
		md, err := b.PerRPCCredentials().GetRequestMetadata(context.Background())
		require.NoError(t, err)
		assert.Nil(t, md)
	})
}

func TestPerRPCRefreshCopiesExpiry(t *testing.T) {
	t.Parallel()

	expires := time.Now().Add(time.Hour)
	provider := &staticProvider{
		token: &credentials.Token{
			TokenType:   "Bearer",
			AccessToken: "token",
			Expires:     &expires,
		},
	}
	b := credentials.NewBundle(credentials.Config{})
	b.WithCallerIdentity(provider)
	rc := b.PerRPCCredentials()

	_, err := rc.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	// the provider changing its token afterwards does not expire the stored copy
	expires = time.Now().Add(-time.Hour)
	md, err := rc.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]string{credentials.TokenFieldNameGRPC: "Bearer token"}, md)
	assert.Equal(t, int32(1), provider.calls.Load())
}

// testSigner returns "<method> <path>" as the DPoP proof, or err.
type testSigner struct {
	err error
}

func (s testSigner) Sign(_ context.Context, method string, u *url.URL, _ any) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return method + " " + u.Path, nil
}

func (testSigner) JWKThumbprint() string { return "thumbprint" }

func TestPerRPCDPoP(t *testing.T) {
	t.Parallel()

	errSign := errors.New("sign failed")
	for _, tc := range []struct {
		name   string
		token  credentials.Token
		signer testSigner
		md     map[string]string
		err    string
	}{
		{
			name:  "dpop_token",
			token: credentials.Token{TokenType: "DPoP", AccessToken: "token"},
			md: map[string]string{
				credentials.TokenFieldNameGRPC: "DPoP token",
				"dpop":                         "POST ",
			},
		},
		{
			name:  "bearer_token_has_no_proof",
			token: credentials.Token{TokenType: "Bearer", AccessToken: "token"},
			md: map[string]string{
				credentials.TokenFieldNameGRPC: "Bearer token",
			},
		},
		{
			name:   "sign_error",
			token:  credentials.Token{TokenType: "DPoP", AccessToken: "token"},
			signer: testSigner{err: errSign},
			err:    "unable to sign DPoP proof: sign failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := credentials.NewBundle(credentials.Config{})
			b.UpdateAuthToken(tc.token)
			b.WithDPoP(tc.signer)
			md, err := b.PerRPCCredentials().GetRequestMetadata(context.Background())
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				assert.ErrorIs(t, err, errSign)
				assert.Nil(t, md)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.md, md)
		})
	}
}

// keySigner labels its DPoP proofs with the name of its key.
type keySigner struct {
	key string
}

func (s keySigner) Sign(context.Context, string, *url.URL, any) (string, error) {
	return "proof-from-" + s.key, nil
}

func (s keySigner) JWKThumbprint() string { return s.key }

// signerInstallingProvider installs signer with WithDPoP while it obtains a
// DPoP token, as a provider does when the new token is bound to a new key.
// Each call waits for release first.
type signerInstallingProvider struct {
	calls   atomic.Int32
	bundle  credentials.Bundle
	signer  keySigner
	release chan struct{}
}

func (p *signerInstallingProvider) GetCallerIdentity(context.Context) (*credentials.Token, error) {
	p.calls.Add(1)
	<-p.release
	p.bundle.WithDPoP(p.signer)
	return &credentials.Token{
		TokenType:   "DPoP",
		AccessToken: "token-bound-to-" + p.signer.key,
	}, nil
}

func TestPerRPCRefreshUsesSignerInstalledByProvider(t *testing.T) {
	t.Parallel()

	expected := map[string]string{
		credentials.TokenFieldNameGRPC: "DPoP token-bound-to-new-key",
		"dpop":                         "proof-from-new-key",
	}
	for _, tc := range []struct {
		name   string
		signer *keySigner
	}{
		{name: "no_previous_signer"},
		{name: "rotated_signer", signer: &keySigner{key: "old-key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				b := credentials.NewBundle(credentials.Config{})
				if tc.signer != nil {
					b.WithDPoP(*tc.signer)
				}
				provider := &signerInstallingProvider{
					bundle:  b,
					signer:  keySigner{key: "new-key"},
					release: make(chan struct{}),
				}
				b.WithCallerIdentity(provider)
				rc := b.PerRPCCredentials()

				// the RPC that refreshes and the RPCs that share its result
				const callers = 4
				results := make(chan metadataResult, callers)
				for range callers {
					go func() {
						md, err := rc.GetRequestMetadata(context.Background())
						results <- metadataResult{md: md, err: err}
					}()
				}
				synctest.Wait()
				close(provider.release)
				for range callers {
					res := <-results
					require.NoError(t, res.err)
					assert.Equal(t, expected, res.md)
				}

				md, err := rc.GetRequestMetadata(context.Background())
				require.NoError(t, err)
				assert.Equal(t, expected, md)
				assert.Equal(t, int32(1), provider.calls.Load())
			})
		})
	}
}

// TestPerRPCConcurrentSetters runs the setters while RPCs read the token,
// signer and provider; run with -race.
func TestPerRPCConcurrentSetters(t *testing.T) {
	t.Parallel()

	provider := &staticProvider{
		token: &credentials.Token{
			TokenType:   "DPoP",
			AccessToken: "fresh",
		},
	}
	expired := time.Now().Add(-time.Hour)
	b := credentials.NewBundle(credentials.Config{})
	rc := b.PerRPCCredentials()

	const iterations = 200
	var wg sync.WaitGroup
	wg.Go(func() {
		for range iterations {
			b.WithDPoP(testSigner{})
			b.WithCallerIdentity(provider)
			b.UpdateAuthToken(credentials.Token{
				TokenType:   "DPoP",
				AccessToken: "stale",
				Expires:     &expired,
			})
		}
	})
	for range 4 {
		wg.Go(func() {
			for range iterations {
				_, err := rc.GetRequestMetadata(context.Background())
				assert.NoError(t, err)
			}
		})
	}
	wg.Wait()
}
