// Package retriable provides an HTTP client with a configurable retry
// policy, JSON request/response marshalling, header propagation through
// context, bearer/DPoP authorization, replay-nonce handling and
// file-based token storage.
//
// A Client wraps a standard *http.Client. Every request goes through
// Client.Do, which rewinds the body and re-sends it according to
// Policy.ShouldRetry; the higher-level Get/Post/Put/Delete/Request helpers
// additionally encode the request body and decode the response. Responses
// with status >= 300 (except 204) are converted into an error, preferably
// an *httperror.Error when the body is a JSON error document.
//
// Basic usage:
//
//	client, err := retriable.New(retriable.ClientConfig{
//		Host: "https://api.example.com",
//		Request: &retriable.RequestPolicy{RetryLimit: 3, Timeout: 5 * time.Second},
//	}, retriable.WithUserAgent("my-cli"))
//	if err != nil {
//		return err
//	}
//	var res struct{ ID string `json:"id"` }
//	hdr, status, err := client.Get(ctx, "/v1/items/1", &res)
//
// Clients can also be built from a YAML/JSON configuration with LoadClient
// (a single ClientConfig) or LoadFactory (a Config holding a map of
// named ClientConfig entries):
//
//	clients:
//	  prod:
//	    host: https://api.example.com
//	    tls:
//	      cert: ~/.config/demo/client.pem
//	      key: ~/.config/demo/client.key
//	      trusted_ca: /etc/pki/cabundle.pem
//	    request:
//	      retry_limit: 3
//	      timeout: 2s
//	    storage_folder: ~/.config/demo
//
// StorageFolder is the root of a Storage where the access token
// (.auth_token) and DPoP private keys (<thumbprint>.jwk) are kept;
// Client.SetAuthorization loads them and adds the Authorization header.
//
// The retry policy is described by Policy: Retries maps an HTTP status code
// (0 for transport errors) to a ShouldRetry callback, TotalRetryLimit caps
// the number of retries across all codes, and RequestTimeout bounds each
// call made through Request/Get/Post/etc. DefaultPolicy retries connection
// errors, 502 and 503, and 429 after the server's Retry-After
// (see RetryAfterShouldRetryFactory). The wait between attempts ends when
// the request context is done. In a ClientConfig, a zero retry_limit or
// timeout keeps the DefaultPolicy value and a negative retry_limit disables
// retries.
//
// All exported functions return errors rather than panic. WithTLS and
// WithDNSServer install modified copies of an *http.Transport; on any other
// http.RoundTripper they cannot apply their setting, so New and every
// request return an error until WithTransport replaces the transport.
//
// Concurrency: the With*/Add*/Set* methods are synchronized, and a request
// uses the configuration current when it starts. Direct changes to the
// exported Name, Policy and Config fields, or to the *http.Client returned
// by HTTPClient, are not synchronized; make them before sharing the Client
// between goroutines.
package retriable
