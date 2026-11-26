package cache

// SubscriberBufferSize exposes subscriberBufferSize to black-box tests.
const SubscriberBufferSize = subscriberBufferSize

// DefaultListCount exposes defaultListCount to black-box tests.
const DefaultListCount = defaultListCount

// RedisTLSMinVersion reports the minimum TLS version of the Redis client
// behind p, so tests can check client_tls.min_version without connecting.
// It returns false when p is not a Redis provider or has no TLS config.
func RedisTLSMinVersion(p Provider) (uint16, bool) {
	rp, ok := p.(*redisProv)
	if !ok {
		return 0, false
	}
	tlsCfg := rp.client.Options().TLSConfig
	if tlsCfg == nil {
		return 0, false
	}
	return tlsCfg.MinVersion, true
}
