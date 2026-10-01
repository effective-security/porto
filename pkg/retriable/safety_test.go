package retriable

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDumpRequestOutRedactsCredentials(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "https://example.test/path", strings.NewReader("body"))
	req.Header.Set(header.Authorization, "Bearer authorization-secret")
	req.Header["authorization"] = []string{"Bearer raw-header-secret"}
	req.Header.Set("DPoP", "proof-secret")
	req.Header.Set("Cookie", "session=cookie-secret")
	req.Header.Set("Proxy-Authorization", "Basic proxy-secret")

	for _, withBody := range []bool{false, true} {
		dump, err := DumpRequestOut(req, withBody)
		require.NoError(t, err)
		for _, secret := range []string{"authorization-secret", "raw-header-secret", "proof-secret", "cookie-secret", "proxy-secret"} {
			assert.NotContains(t, string(dump), secret)
		}
		assert.Contains(t, string(dump), "[REDACTED]")
	}

	assert.Equal(t, "Bearer authorization-secret", req.Header.Get(header.Authorization))
	assert.Equal(t, "proof-secret", req.Header.Get("DPoP"))
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, "body", string(body))
}

func TestDumpRequestOutWithoutURL(t *testing.T) {
	t.Parallel()

	_, err := DumpRequestOut(&http.Request{Header: make(http.Header)}, false)
	require.ErrorContains(t, err, "nil Request.URL")
}

func TestStoragePrivateFolder(t *testing.T) {
	t.Parallel()

	folder := filepath.Join(t.TempDir(), "credentials")
	require.NoError(t, os.Mkdir(folder, 0755))
	require.NoError(t, os.Chmod(folder, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(folder, authTokenFileName), []byte("old"), 0644))
	require.NoError(t, os.Chmod(filepath.Join(folder, authTokenFileName), 0644))
	storage := NewStorage(folder)
	file, err := storage.SaveAuthToken("secret")
	require.NoError(t, err)

	dirInfo, err := os.Stat(folder)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), dirInfo.Mode().Perm())
	fileInfo, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fileInfo.Mode().Perm())

	keyFolder := filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.Mkdir(keyFolder, 0755))
	require.NoError(t, os.Chmod(keyFolder, 0755))
	key, err := dpop.GenerateKey("")
	require.NoError(t, err)
	_, err = NewStorage(keyFolder).SaveKey(key)
	require.NoError(t, err)
	keyDirInfo, err := os.Stat(keyFolder)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), keyDirInfo.Mode().Perm())

	newFolder := filepath.Join(t.TempDir(), "new-credentials")
	_, err = NewStorage(newFolder).SaveAuthToken("secret")
	require.NoError(t, err)
	newDirInfo, err := os.Stat(newFolder)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), newDirInfo.Mode().Perm())
}

func TestStorageEmptyFolderUsesWorkingDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	storage := NewStorage("")
	tokenPath, err := storage.SaveAuthToken("secret")
	require.NoError(t, err)
	assert.Equal(t, authTokenFileName, tokenPath)
	token, location, err := storage.LoadAuthToken()
	require.NoError(t, err)
	assert.Equal(t, authTokenFileName, location)
	assert.Equal(t, "secret", token.AccessToken)

	key, err := dpop.GenerateKey("")
	require.NoError(t, err)
	keyPath, err := storage.SaveKey(key)
	require.NoError(t, err)
	assert.Equal(t, key.KeyID+".jwk", keyPath)
	_, _, err = storage.LoadKey(key.KeyID)
	require.NoError(t, err)
}

func TestNewStorageExpandsHome(t *testing.T) {
	// not parallel: t.Setenv
	home := t.TempDir()
	t.Setenv("HOME", home)

	tcases := []struct {
		folder   string
		expected string
	}{
		{folder: "~", expected: home},
		{folder: "~/", expected: home},
		{folder: "~/creds/host", expected: filepath.Join(home, "creds", "host")},
		{folder: "~user/creds", expected: "~user/creds"},
		{folder: "creds/~", expected: "creds/~"},
		{folder: "/var/~/creds", expected: "/var/~/creds"},
		{folder: "$HOME/creds", expected: "$HOME/creds"},
		{folder: "", expected: ""},
	}
	for _, tc := range tcases {
		assert.Equal(t, tc.expected, NewStorage(tc.folder).Folder(), tc.folder)
	}

	// without $HOME the user database provides the home directory
	t.Setenv("HOME", "")
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		assert.Equal(t, filepath.Join(u.HomeDir, "creds"), NewStorage("~/creds").Folder())
	} else {
		// without any home directory the folder is used as is
		assert.Equal(t, "~/creds", NewStorage("~/creds").Folder())
	}
}

func TestStorageReplacesCredentialSymlinks(t *testing.T) {
	t.Parallel()

	folder := filepath.Join(t.TempDir(), "credentials")
	require.NoError(t, os.Mkdir(folder, 0700))
	outside := filepath.Join(t.TempDir(), "public-target")
	require.NoError(t, os.WriteFile(outside, []byte("original"), 0644))
	storage := NewStorage(folder)
	tokenPath := filepath.Join(folder, authTokenFileName)
	require.NoError(t, os.Symlink(outside, tokenPath))
	_, err := storage.SaveAuthToken("secret-token")
	require.NoError(t, err)
	assertPrivateReplacement(t, tokenPath, outside)
	token, err := os.ReadFile(tokenPath)
	require.NoError(t, err)
	assert.Equal(t, "secret-token", string(token))

	key, err := dpop.GenerateKey("")
	require.NoError(t, err)
	thumbprint, err := dpop.Thumbprint(key)
	require.NoError(t, err)
	keyPath := filepath.Join(folder, thumbprint+".jwk")
	require.NoError(t, os.Symlink(outside, keyPath))
	_, err = storage.SaveKey(key)
	require.NoError(t, err)
	assertPrivateReplacement(t, keyPath, outside)
}

func assertPrivateReplacement(t *testing.T, path, outside string) {
	t.Helper()
	content, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, "original", string(content))
	info, err := os.Lstat(path)
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular())
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestSetAuthorizationRejectsPublicDPoPKey(t *testing.T) {
	t.Parallel()

	storage := NewStorage(t.TempDir())
	privateKey, err := dpop.GenerateKey("")
	require.NoError(t, err)
	publicKey := privateKey.Public()
	thumbprint, err := dpop.Thumbprint(&publicKey)
	require.NoError(t, err)
	data, err := json.Marshal(&publicKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(storage.Folder(), thumbprint+".jwk"), data, 0600))
	token := url.Values{
		"access_token": {"test-token"},
		"dpop_jkt":     {thumbprint},
	}
	_, err = storage.SaveAuthToken(token.Encode())
	require.NoError(t, err)
	client, err := New(ClientConfig{Host: "https://example.test"})
	require.NoError(t, err)
	client.WithStorage(storage)
	err = client.SetAuthorization()
	require.ErrorContains(t, err, "DPoP key is not a private signer")
}

func TestDPoPProofChangesOnRetry(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	proofs := make(chan string, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proofs <- r.Header.Get("DPoP")
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()

	storage := NewStorage(t.TempDir())
	key, err := dpop.GenerateKey("")
	require.NoError(t, err)
	_, err = storage.SaveKey(key)
	require.NoError(t, err)
	token := url.Values{
		"access_token": {"test-token"},
		"dpop_jkt":     {key.KeyID},
	}
	_, err = storage.SaveAuthToken(token.Encode())
	require.NoError(t, err)

	client, err := New(ClientConfig{Host: server.URL})
	require.NoError(t, err)
	client.WithTransport(server.Client().Transport).WithStorage(storage)
	require.NoError(t, client.SetAuthorization())
	client.WithPolicy(Policy{
		TotalRetryLimit: 1,
		Retries: map[int]ShouldRetry{
			http.StatusServiceUnavailable: DefaultShouldRetryFactory(1, time.Millisecond, "retry"),
		},
	})
	req := httptest.NewRequest(http.MethodGet, server.URL+"/", nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(2), calls.Load())
	first, second := <-proofs, <-proofs
	assert.NotEmpty(t, first)
	assert.NotEmpty(t, second)
	assert.NotEqual(t, first, second)
}

func TestDPoPRequiresSigner(t *testing.T) {
	t.Parallel()

	client, err := New(ClientConfig{})
	require.NoError(t, err)
	client.AddHeader(header.Authorization, "DPoP token")
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	_, err = client.Do(req)
	require.ErrorContains(t, err, "DPoP signer")
}

type countingIdentity struct {
	calls atomic.Int32
}

func (ci *countingIdentity) GetCallerIdentity(context.Context) (*credentials.Token, error) {
	ci.calls.Add(1)
	time.Sleep(10 * time.Millisecond)
	return &credentials.Token{
		TokenType:   "Bearer",
		AccessToken: "test-token",
	}, nil
}

func TestCallerIdentityRefreshSingleFlight(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get(header.Authorization))
	}))
	defer server.Close()
	identity := &countingIdentity{}
	client, err := New(ClientConfig{}, WithCallerIdentity(identity))
	require.NoError(t, err)

	const concurrentRequests = 24
	var group sync.WaitGroup
	results := make(chan error, concurrentRequests)
	for range concurrentRequests {
		group.Add(1)
		go func() {
			defer group.Done()
			req := httptest.NewRequest(http.MethodGet, server.URL+"/", nil)
			resp, err := client.Do(req)
			if err == nil {
				err = resp.Body.Close()
			}
			results <- err
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), identity.calls.Load())
}

type blockingIdentity struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (ci *blockingIdentity) GetCallerIdentity(context.Context) (*credentials.Token, error) {
	if ci.calls.Add(1) == 1 {
		close(ci.started)
		<-ci.release
	}
	return &credentials.Token{
		TokenType:   "Bearer",
		AccessToken: "test-token",
	}, nil
}

func TestCallerIdentityRefreshWaitHonorsContext(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	identity := &blockingIdentity{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(identity.release) }) }
	defer release()
	client, err := New(ClientConfig{}, WithCallerIdentity(identity))
	require.NoError(t, err)
	send := func(ctx context.Context) error {
		req := httptest.NewRequest(http.MethodGet, server.URL+"/", nil).WithContext(ctx)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	firstResult := make(chan error, 1)
	go func() { firstResult <- send(context.Background()) }()
	<-identity.started
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	secondResult := make(chan error, 1)
	go func() { secondResult <- send(ctx) }()
	select {
	case err := <-secondResult:
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Error("refresh waiter did not return when its context expired")
	}
	release()
	require.NoError(t, <-firstResult)
	assert.Equal(t, int32(1), identity.calls.Load())
}

type canceledFirstIdentity struct {
	started chan struct{}
	calls   atomic.Int32
}

func (ci *canceledFirstIdentity) GetCallerIdentity(ctx context.Context) (*credentials.Token, error) {
	if ci.calls.Add(1) == 1 {
		close(ci.started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &credentials.Token{
		TokenType:   "Bearer",
		AccessToken: "test-token",
	}, nil
}

type doneSignalContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (ctx *doneSignalContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.entered) })
	return ctx.Context.Done()
}

func TestCallerIdentityRefreshAfterFirstCallerCanceled(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	identity := &canceledFirstIdentity{started: make(chan struct{})}
	client, err := New(ClientConfig{}, WithCallerIdentity(identity))
	require.NoError(t, err)
	send := func(ctx context.Context) error {
		req := httptest.NewRequest(http.MethodGet, server.URL+"/", nil).WithContext(ctx)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstResult := make(chan error, 1)
	go func() { firstResult <- send(firstCtx) }()
	<-identity.started

	secondCtx, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	defer cancelSecond()
	secondCtxSignal := &doneSignalContext{Context: secondCtx, entered: make(chan struct{})}
	secondResult := make(chan error, 1)
	go func() { secondResult <- send(secondCtxSignal) }()
	select {
	case <-secondCtxSignal.entered:
	case <-secondCtx.Done():
		t.Fatal("second request did not reach the refresh wait")
	}
	cancelFirst()
	require.ErrorIs(t, <-firstResult, context.Canceled)
	require.NoError(t, <-secondResult)
	assert.Equal(t, int32(2), identity.calls.Load())
}

type panickingIdentity struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (ci *panickingIdentity) GetCallerIdentity(context.Context) (*credentials.Token, error) {
	if ci.calls.Add(1) == 1 {
		close(ci.started)
		<-ci.release
		panic("provider panic")
	}
	return &credentials.Token{
		TokenType:   "Bearer",
		AccessToken: "test-token",
	}, nil
}

// TestCallerIdentityRefreshProviderPanic checks that a panicking provider
// releases the requests waiting for its refresh (formerly P-087).
func TestCallerIdentityRefreshProviderPanic(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get(header.Authorization))
	}))
	defer server.Close()
	identity := &panickingIdentity{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(identity.release) }) }
	defer release()
	client, err := New(ClientConfig{}, WithCallerIdentity(identity))
	require.NoError(t, err)
	send := func(ctx context.Context) error {
		req := httptest.NewRequest(http.MethodGet, server.URL+"/", nil).WithContext(ctx)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	recovered := make(chan any, 1)
	go func() {
		defer func() { recovered <- recover() }()
		_ = send(context.Background())
	}()
	<-identity.started

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	waiterCtx := &doneSignalContext{Context: ctx, entered: make(chan struct{})}
	waiterResult := make(chan error, 1)
	go func() { waiterResult <- send(waiterCtx) }()
	select {
	case <-waiterCtx.entered:
	case <-ctx.Done():
		t.Fatal("waiter did not reach the refresh wait")
	}
	release()

	assert.Equal(t, "provider panic", <-recovered, "the panic must continue on the leading request")
	err = <-waiterResult
	require.Error(t, err)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, "caller identity provider panicked", err.Error())

	// the next request makes a new call instead of waiting for the lost one
	require.NoError(t, send(ctx))
	assert.Equal(t, int32(2), identity.calls.Load())
}

// TestCallerIdentityRefreshSupersededByPanic replaces the provider while
// the old one refreshes, then lets the old one panic: the panic must not
// release or overwrite the refresh of the new provider.
func TestCallerIdentityRefreshSupersededByPanic(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r.Header.Get(header.Authorization))
	}))
	defer server.Close()
	old := &panickingIdentity{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(old.release) }) }
	defer release()
	client, err := New(ClientConfig{}, WithCallerIdentity(old))
	require.NoError(t, err)
	send := func() error {
		req := httptest.NewRequest(http.MethodGet, server.URL+"/", nil)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	recovered := make(chan any, 1)
	go func() {
		defer func() { recovered <- recover() }()
		_ = send()
	}()
	<-old.started

	replacement := &countingIdentity{}
	client.WithCallerIdentity(replacement)
	require.NoError(t, send())
	release()
	assert.Equal(t, "provider panic", <-recovered)

	require.NoError(t, send())
	assert.Equal(t, int32(1), replacement.calls.Load())
	assert.Equal(t, int32(1), old.calls.Load())
	client.lock.RLock()
	assert.Nil(t, client.refresh)
	assert.Equal(t, "test-token", client.token.AccessToken)
	client.lock.RUnlock()
	mu.Lock()
	assert.Equal(t, []string{"Bearer test-token", "Bearer test-token"}, seen)
	mu.Unlock()
}

// tokenIdentity returns its token.
type tokenIdentity struct {
	token string
	calls atomic.Int32
}

func (ci *tokenIdentity) GetCallerIdentity(context.Context) (*credentials.Token, error) {
	ci.calls.Add(1)
	return &credentials.Token{
		TokenType:   "Bearer",
		AccessToken: ci.token,
	}, nil
}

// TestCallerIdentityRefreshSuperseded replaces the provider while the old
// one refreshes: the old provider's token is discarded, also for the request
// that called it, which uses the new provider's token.
func TestCallerIdentityRefreshSuperseded(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r.Header.Get(header.Authorization))
	}))
	defer server.Close()
	old := &blockingIdentity{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(old.release) }) }
	defer release()
	client, err := New(ClientConfig{}, WithCallerIdentity(old))
	require.NoError(t, err)
	send := func() error {
		req := httptest.NewRequest(http.MethodGet, server.URL+"/", nil)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	leaderResult := make(chan error, 1)
	go func() { leaderResult <- send() }()
	<-old.started

	replacement := &tokenIdentity{token: "new-token"}
	client.WithCallerIdentity(replacement)
	require.NoError(t, send())
	release()
	require.NoError(t, <-leaderResult)

	assert.Equal(t, int32(1), old.calls.Load())
	assert.Equal(t, int32(1), replacement.calls.Load())
	client.lock.RLock()
	assert.Nil(t, client.refresh)
	assert.Equal(t, "new-token", client.token.AccessToken)
	client.lock.RUnlock()
	mu.Lock()
	assert.Equal(t, []string{"Bearer new-token", "Bearer new-token"}, seen)
	mu.Unlock()
}

func TestClientConcurrentHeaders(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client, err := New(ClientConfig{})
	require.NoError(t, err)

	const iterations = 40
	var group sync.WaitGroup
	results := make(chan error, iterations)
	group.Add(2)
	go func() {
		defer group.Done()
		for range iterations {
			client.WithHeaders(map[string]string{"X-Test": "value"})
			client.AddHeader("X-Other", "value")
			client.WithName("test-client")
			client.WithPolicy(DefaultPolicy())
		}
	}()
	go func() {
		defer group.Done()
		for range iterations {
			req := httptest.NewRequest(http.MethodGet, server.URL+"/", nil)
			resp, err := client.Do(req)
			if err == nil {
				err = resp.Body.Close()
			}
			results <- err
		}
	}()
	group.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
}
