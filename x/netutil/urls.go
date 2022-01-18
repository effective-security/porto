package netutil

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// ParseURLs creates a list of URLs from lists of hosts
func ParseURLs(list []string) ([]*url.URL, error) {
	urls := make([]*url.URL, len(list))
	for i, host := range list {
		u, err := url.Parse(strings.TrimSpace(host))
		if err != nil {
			return nil, errors.WithStack(err)
		}
		urls[i] = u
	}

	return urls, nil
}

// ParseURLsFromString creates a list of URLs from a coma-separated lists of hosts
func ParseURLsFromString(hosts string) ([]*url.URL, error) {
	hosts = strings.TrimSpace(hosts)
	if len(hosts) == 0 {
		return nil, nil
	}
	list := strings.Split(hosts, ",")
	return ParseURLs(list)
}

// JoinURLs returns coma-separated lists of URLs in string format
func JoinURLs(list []*url.URL) string {
	strs := make([]string, len(list))
	for i, url := range list {
		strs[i] = url.String()
	}
	return strings.Join(strs, ",")
}
