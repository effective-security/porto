package location

import (
	"cmp"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "location")

const (
	// DefaultIPWhoIsURL is the free ipwho.is endpoint. It allows a limited
	// number of requests per day per calling IP and answers HTTP 429 above
	// it; wrap the provider in a Cache.
	DefaultIPWhoIsURL = "https://ipwho.is"
	// DefaultTimeout bounds one lookup when IPWhoIsConfig.Timeout is zero.
	DefaultTimeout = 3 * time.Second
	// DefaultUserAgent is the User-Agent sent when IPWhoIsConfig.UserAgent
	// is empty.
	DefaultUserAgent = "porto"

	// ipWhoIsFields keeps the answer to the fields Place reports.
	ipWhoIsFields = "success,message,city,region,country,country_code"
	// ipWhoIsMaxBody caps an answer. The filtered JSON is a few hundred
	// bytes; anything larger is not an answer we can use.
	ipWhoIsMaxBody = 4096
	// defaultQuotaBackoff is how long lookups are skipped after a 429
	// without a usable Retry-After.
	defaultQuotaBackoff = time.Minute
	// maxQuotaBackoff caps Retry-After; ipwho.is restores access within a
	// day.
	maxQuotaBackoff = 24 * time.Hour
	// defaultCacheSize is the number of locations to cache by default.
	defaultCacheSize = 1000
)

// ErrQuotaExceeded is wrapped by the error of an IPWhoIs lookup that the
// service refused with HTTP 429, and of every lookup skipped until its
// Retry-After has passed.
var ErrQuotaExceeded = errors.New("location lookup quota exceeded")

// noLocationMessages are the ipwho.is "success": false messages, compared
// without case, that mean the address has no location; any other failure
// is an error, so that a Cache does not keep it.
var noLocationMessages = []string{
	"invalid ip address",
	"reserved range",
}

// IPWhoIsConfig configures NewIPWhoIs. The zero value uses the free
// ipwho.is endpoint.
type IPWhoIsConfig struct {
	// BaseURL is the http or https URL of the lookup service; the address
	// is appended as a path segment and the fields parameter is added to
	// its query. Other query parameters, such as an API key, are kept and
	// are not included in errors. Default DefaultIPWhoIsURL.
	BaseURL string `json:"base_url,omitempty" yaml:"base_url,omitempty"`
	// Timeout bounds one lookup, including reading the answer. Default
	// DefaultTimeout.
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	// UserAgent is sent with each lookup. Default DefaultUserAgent.
	UserAgent string `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`
}

// IPWhoIs is a Provider backed by the ipwho.is JSON API. It sends one
// request per call; wrap it in a Cache to share answers. After an HTTP 429
// it fails every lookup with ErrQuotaExceeded, without a request, until the
// Retry-After the service sent has passed. It is safe for concurrent use.
type IPWhoIs struct {
	base      *url.URL
	userAgent string
	client    *http.Client

	mu      sync.Mutex
	retryAt time.Time
}

// ipWhoIsAnswer is the filtered ipwho.is answer. A JSON null leaves a
// field empty.
type ipWhoIsAnswer struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	City        string `json:"city"`
	Region      string `json:"region"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
}

// NewIPWhoIs returns an ipwho.is Provider. It returns an error when
// cfg.BaseURL is not an absolute http or https URL, or cfg.Timeout is
// negative.
func NewIPWhoIs(cfg IPWhoIsConfig) (*IPWhoIs, error) {
	if cfg.Timeout < 0 {
		return nil, errors.Errorf("invalid location timeout %s", cfg.Timeout)
	}
	baseURL := cmp.Or(cfg.BaseURL, DefaultIPWhoIsURL)
	base, err := url.Parse(baseURL)
	if err != nil {
		// *url.Error repeats the URL, whose query may hold an API key.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, errors.WithMessage(err, "invalid location base URL")
	}
	if (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, errors.Errorf("invalid location base URL %q: expected an http or https URL", displayURL(base))
	}
	query := base.Query()
	query.Set("fields", ipWhoIsFields)
	base.RawQuery = query.Encode()
	base.Fragment = ""

	return &IPWhoIs{
		base:      base,
		userAgent: cmp.Or(cfg.UserAgent, DefaultUserAgent),
		client: &http.Client{
			Timeout: cmp.Or(cfg.Timeout, DefaultTimeout),
			// A redirect is not an answer; do not follow it to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Location implements Provider. It looks up public addresses only, in
// canonical form (see ParsePublicIP). A non-200 status is an error, one that
// wraps ErrQuotaExceeded for 429; an answer with "success": false for an
// invalid address or a reserved range is no location, any other one an
// error.
func (p *IPWhoIs) Location(ctx context.Context, addr netip.Addr) (*Place, error) {
	if !IsPublic(addr) {
		return nil, nil
	}
	addr = canonical(addr)
	ip := addr.String()
	if until := p.quotaUntil(); !until.IsZero() {
		return nil, errors.Wrapf(ErrQuotaExceeded, "location lookup of %s skipped until %s", ip, until.UTC().Format(time.RFC3339))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base.JoinPath(ip).String(), nil)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create location request")
	}
	req.Header.Set(header.Accept, header.ApplicationJSON)
	req.Header.Set(header.UserAgent, p.userAgent)

	resp, err := p.client.Do(req)
	if err != nil {
		// *url.Error repeats the URL, whose query may hold an API key.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, errors.Wrapf(err, "unable to look up location of %s", ip)
	}
	defer drainBody(resp.Body)

	if resp.StatusCode == http.StatusTooManyRequests {
		wait := retryAfter(resp.Header.Get(header.RetryAfter), time.Now())
		p.backOff(wait)
		return nil, errors.Wrapf(ErrQuotaExceeded, "location lookup of %s returned status 429, retry after %s", ip, wait)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("location lookup of %s returned status %d", ip, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ipWhoIsMaxBody+1))
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read location of %s", ip)
	}
	if len(body) > ipWhoIsMaxBody {
		return nil, errors.Errorf("location of %s exceeds %d bytes", ip, ipWhoIsMaxBody)
	}

	var answer ipWhoIsAnswer
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, errors.Wrapf(err, "unable to decode location of %s", ip)
	}
	if !answer.Success {
		message := strings.TrimSpace(answer.Message)
		if !slices.ContainsFunc(noLocationMessages, func(m string) bool { return strings.EqualFold(m, message) }) {
			return nil, errors.Errorf("location lookup of %s failed: %q", ip, message)
		}
		logger.ContextKV(ctx, xlog.DEBUG,
			"reason", "no_location",
			"ip", ip,
			"message", message,
		)
		return nil, nil
	}
	return &Place{
		City:        strings.TrimSpace(answer.City),
		Region:      strings.TrimSpace(answer.Region),
		Country:     strings.TrimSpace(answer.Country),
		CountryCode: strings.TrimSpace(answer.CountryCode),
	}, nil
}

// FetchIPLocation looks up addr once with an ipwho.is provider at baseURL
// (DefaultIPWhoIsURL when empty) and default settings. It is for callers
// that show a location when one is available and carry on without it:
// errors, including an invalid baseURL, are logged at WARNING and return
// nil, as does an address without a location, which is not looked up. Each
// call builds a new provider, so the 429 backoff of IPWhoIs does not apply;
// services that look up many addresses should keep one Provider wrapped in
// a Cache instead.
func FetchIPLocation(ctx context.Context, baseURL string, addr netip.Addr) *Place {
	if !IsPublic(addr) {
		return nil
	}
	place, err := ipLocation(ctx, baseURL, addr)
	if err != nil {
		logger.ContextKV(ctx, xlog.WARNING,
			"reason", "ip_location",
			"ip", addr.String(),
			"err", err.Error(),
		)
		return nil
	}
	return place
}

func ipLocation(ctx context.Context, baseURL string, addr netip.Addr) (*Place, error) {
	p, err := NewIPWhoIs(IPWhoIsConfig{BaseURL: baseURL})
	if err != nil {
		return nil, err
	}
	return p.Location(ctx, addr)
}

// drainBody reads what is left of an answer, up to ipWhoIsMaxBody, and
// closes it. It is best effort: a short remainder that arrives within the
// client Timeout and ctx is read before Location returns, after a status
// error too, so that its connection is idle for the next lookup. The
// transport drains a body closed early only in the background, and the next
// lookup would often dial a new connection.
func drainBody(body io.ReadCloser) {
	_, _ = io.CopyN(io.Discard, body, ipWhoIsMaxBody)
	_ = body.Close()
}

// quotaUntil returns the time until which lookups are skipped after a 429,
// or the zero time when lookups may run.
func (p *IPWhoIs) quotaUntil() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.retryAt.IsZero() && !time.Now().Before(p.retryAt) {
		p.retryAt = time.Time{}
	}
	return p.retryAt
}

// backOff skips lookups for wait from now, unless they are already skipped
// for longer.
func (p *IPWhoIs) backOff(wait time.Duration) {
	until := time.Now().Add(wait)
	p.mu.Lock()
	defer p.mu.Unlock()
	if until.After(p.retryAt) {
		p.retryAt = until
	}
}

// retryAfter returns the wait a Retry-After value asks for, in seconds or
// as an HTTP date relative to now, capped at maxQuotaBackoff. A missing,
// invalid or non-positive value waits defaultQuotaBackoff.
func retryAfter(value string, now time.Time) time.Duration {
	var wait time.Duration
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		// clamp before multiplying, so that no value overflows into a wait
		wait = time.Duration(min(max(seconds, 0), int64(maxQuotaBackoff/time.Second))) * time.Second
	} else if at, err := http.ParseTime(value); err == nil {
		wait = at.Sub(now)
	}
	if wait <= 0 {
		return defaultQuotaBackoff
	}
	return min(wait, maxQuotaBackoff)
}

// displayURL returns u for an error message without its query and
// fragment, which may hold an API key, and without a password.
func displayURL(u *url.URL) string {
	shown := *u
	shown.RawQuery = ""
	shown.Fragment = ""
	return shown.Redacted()
}
