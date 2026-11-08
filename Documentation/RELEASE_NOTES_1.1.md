# v1.1 RELEASE NOTES

v1.1 follows the xpki v1.1 upgrade, which added ML-DSA (FIPS 204,
post-quantum) keys to certificates. Porto now loads ML-DSA key pairs and
offers TLS 1.3 by default.

## Breaking changes

- **TLS 1.3 is the default minimum version.** `tlsconfig.NewServerTLSFromFiles`
  and `tlsconfig.NewClientTLSFromFiles` set `MinVersion` to
  `tlsconfig.DefaultMinVersion` (TLS 1.3; TLS 1.2 before). Every config built
  from them changes: `transport.TLSInfo` and so every `gserver` TLS
  listener, `retriable` clients configured through `ClientConfig.TLS`, and
  the `redisclient` and `cache` Redis TLS clients. A TLS 1.2-only client is
  refused by a server with `protocol version not supported`; a client built
  here cannot reach a server limited to TLS 1.2.
  - Servers: set `server_tls.min_version: "1.2"` in the `gserver`
    configuration (`TLSInfo.MinVersion`), or `transport.TLSInfo.MinVersion =
    tls.VersionTLS12`, or call `tlsconfig.SetMinVersion(cfg,
    tls.VersionTLS12)` on a config from `NewServerTLSFromFiles`.
  - Clients: call `tlsconfig.SetMinVersion` on the config from
    `NewClientTLSFromFiles` before use, or pass a prepared `*tls.Config` to
    `retriable.WithTLS`. The Redis clients have no setting; a Redis server
    must accept TLS 1.3 (Redis 6+ built against OpenSSL 1.1.1+ does).
  - `server_tls.cipher_suites` (`transport.TLSInfo.CipherSuites`) names TLS
    1.2 suites only. With the default minimum it has no effect and
    `ServerTLSWithReloader` logs WARNING `cipher_suites_ignored`; it applies
    again with `min_version: "1.2"`.
- `gserver.Config.Validate` and `Start` reject an unknown
  `server_tls.min_version` with
  `server_tls: min_version: unsupported TLS version "<value>": use 1.2 or 1.3`.
- `gserver` now imports `pkg/tlsconfig` directly (it already did through
  `pkg/transport`); the dependency table in `AGENTS.md` and
  `Documentation/codemap.md` records it.

## New

- **ML-DSA key pairs.** `tlsconfig.X509KeyPairWithOCSP`, and so
  `LoadX509KeyPairWithOCSP`, `NewServerTLSFromFiles`,
  `NewClientTLSFromFiles`, `KeypairReloader`, `transport.TLSInfo` and the
  `retriable`, `redisclient` and `cache` TLS clients, accept an ML-DSA-44,
  -65 or -87 certificate with its PKCS#8 private key in the seed form that
  `x509.MarshalPKCS8PrivateKey`, xpki and
  `openssl genpkey -provparam ml-dsa.output_formats=seed-only` write. Before
  v1.1 the pair failed with `tls: found unknown private key type in PKCS#8
  wrapping` although Go 1.27's `tls.X509KeyPair` accepted it. A key of
  another parameter set than the certificate's is `tls: private key does not
  match public key`. Chain verification, client certificate verification and
  the handshake signature schemes were already handled by Go; the ML-DSA
  schemes are first in Go's default list.
- `tlsconfig.DefaultMinVersion`, `tlsconfig.SetMinVersion`,
  `tlsconfig.ParseTLSVersion` ("1.2", "1.3", "TLS1.2", "TLS 1.3"; empty is the
  default) and `tlsconfig.IsMLDSACertificate`.
- `transport.TLSInfo.MinVersion` (`uint16`, zero is TLS 1.3) and
  `gserver.TLSInfo.MinVersion` (`server_tls.min_version`, string).

## Constraints

- Go signs with ML-DSA in TLS 1.3 only. `tlsconfig.SetMinVersion`, and so
  `transport.TLSInfo.ServerTLSWithReloader` and `gserver.Start`, reject TLS
  1.2 for a config whose `Certificates` hold an ML-DSA pair with
  `tls: ML-DSA certificates require TLS 1.3 as the minimum version`. A
  reloader that rotates from a classical to an ML-DSA pair at run time on a
  server lowered to TLS 1.2 is not checked: TLS 1.3 clients keep working and
  TLS 1.2 clients then fail with `internal error`. Keep the default minimum
  when a rotation to ML-DSA is planned.
- One certificate pair per server or client: a classical pair for TLS 1.2
  clients beside an ML-DSA pair for TLS 1.3 clients is ROADMAP 13.
- `retriable.NewKeyInfo` (DPoP key storage) still rejects ML-DSA JWKs, as
  xpki's `jwt` package does until RFC 9964 support lands there.
- Only the PKCS#8 seed form of an ML-DSA private key is accepted; OpenSSL's
  default seed-and-expanded form fails to parse, as in Go and xpki.

## Validation

Run with Go 1.27.3 and xpki v1.1.320: `pkg/tlsconfig` (ML-DSA-44/65/87
mutual TLS through the constructors, a TLS 1.2-only client before and after
`SetMinVersion`, key/certificate mismatch across parameter sets),
`pkg/transport` (ML-DSA chain through the reloader callback, `MinVersion`
table including the rejected combinations) and `gserver` (`min_version`
validation and listener configuration), `make lint`, `make testshort` and
`go test -race` on the two TLS packages.
