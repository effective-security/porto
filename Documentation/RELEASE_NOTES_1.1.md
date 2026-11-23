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
- `retriable.NewKeyInfo` (DPoP key storage) rejected ML-DSA JWKs up to
  v1.1.455; see "ML-DSA DPoP keys (xpki v1.1.322)" below.
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

## ML-DSA DPoP keys (xpki v1.1.322)

Changes after v1.1.455. xpki v1.1.322 adds the RFC 9964 JOSE algorithms
`ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87` to `jwt` and `jwt/dpop`: an ML-DSA
signer signs JWTs and DPoP proofs, `dpop.VerifyClaims` accepts them, and
`dpop.SaveKey`/`LoadKey` handle `AKP` JWKs. Its `dpop.Thumbprint` now rejects
a nil or invalid key instead of letting go-jose panic on it.

### New

- `pkg/retriable`: `NewKeyInfo`, and so `Storage.ListKeys`, accepts an ML-DSA
  private JWK and reports `Type` `ML-DSA`, `KeySize` 44, 65 or 87 (the
  parameter set, as xpki's `certutil.KeyInfo` does) and `Algo` `ML-DSA-44`,
  `ML-DSA-65` or `ML-DSA-87`. Before, `ListKeys` skipped such a key although
  `SetAuthorization` and `rpcclient` could already sign with it.

### Behavior changes

- `retriable.NewKeyInfo` computes the thumbprint with `dpop.Thumbprint`, as
  `Storage.SaveKey` and `LoadKey` do, and returns
  `unable to compute key thumbprint: dpop: unable to get thumbprint` for a nil
  JWK, a JWK without a key, an RSA key without its private exponent and
  primes, and an uninitialized ML-DSA key. The first and the last used to
  panic, and the RSA key was accepted. A symmetric key returns that error
  instead of go-jose's `unknown key type`. Keys read from a `.jwk` file are
  not affected: go-jose only parses complete keys.

### No change needed

- `gserver/roles` accepts ML-DSA DPoP proofs and, through the application's
  `jwt.Parser`, ML-DSA access tokens, over HTTP and gRPC; `pkg/retriable`,
  `pkg/rpcclient` and `gserver/credentials` sign proofs with a stored ML-DSA
  key through `dpop.NewSigner`. A DPoP key is still generated by the
  application: `dpop.GenerateKey` generates P-256.

### Constraints

- Header size. An ML-DSA proof carries its public key and signature: about
  5.9 KB (ML-DSA-44), 8.2 KB (ML-DSA-65) or 11.1 KB (ML-DSA-87), and an
  access token signed with the same parameter set adds about as much. The
  porto servers keep the Go limits, 1 MiB of HTTP headers and 16 MiB of
  gRPC metadata, but a proxy in front of them can have a lower one. grpc-go
  plans to lower its default gRPC header list size to 8 KB
  (`GRPC_GO_EXPERIMENTAL_ENABLE_8KB_DEFAULT_HEADER_LIST_SIZE`, off in the
  version porto uses); porto sets no explicit limit, see ROADMAP 14.

### Validation

Run with Go 1.27.4 and xpki v1.1.322: `TestNewKeyInfo` (RSA 2048, 3071,
3072 and 4096 with real keys, P-256/384/521, ML-DSA-44/65/87, invalid and
nil keys), `TestStorageListKeys` (an ML-DSA-65 key saved as an `AKP` JWK and
listed), `TestDPoPProofWithMLDSAKey` (a stored ML-DSA-65 key signs the
proof of `Client.Do`, which `dpop.VerifyClaims` verifies against the
`dpop_jkt`). Reverting the thumbprint check makes `TestNewKeyInfo` panic on
the uninitialized ML-DSA key; removing the ML-DSA case fails both storage
tests. `gserver/roles` was checked with a throwaway test (not committed):
ML-DSA-44/65/87 proofs and access tokens, HTTP and gRPC, strict mode.
