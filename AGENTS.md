# RULES OF CONDUCT

This module (`github.com/effective-security/porto`) is a library of server
and client building blocks for Go services. There is no binary, service, or
generated mock tree. The packages are:

- `restserver` (+ `authz`, `ready`, `telemetry`): an `httprouter`-based
  REST server with CORS, role-based path authorization, readiness, request
  logging and metrics.
- `gserver` (+ `credentials`, `roles`): a combined gRPC, gRPC-Web and REST
  gateway server with identity extraction from JWT, DPoP, AWS STS caller
  identity and TLS/SPIFFE certificates.
- `xhttp/*`: HTTP helpers shared by both servers and by clients:
  `correlation` (request IDs), `header` (constants), `httperror` (structured
  errors mapped to and from gRPC codes), `identity` (caller identity in
  `context.Context`), `marshal` (JSON and gzip response writing).
- `pkg/*`: infrastructure: `retriable` (HTTP client with retries and
  failover), `rpcclient` (gRPC client factory), `redisclient`, `cache`
  (memory and Redis providers), `tasks` (cron-like scheduler), `tlsconfig`
  (TLS config with file reloading), `transport` (TLS and keepalive
  listeners), `appinit` (application bootstrap), `discovery` (in-process
  service registry), `crlcache`, `streamctx`.
- `metricskey`: metric descriptors shared by the servers.
- `tests/*`: helpers used only by tests.

Work in one package at a time unless you are changing a documented internal
dependency.

Dependency direction is one way and is listed per package in
[`Documentation/codemap.md`](Documentation/codemap.md). The rules: `xhttp/*`
and `pkg/*` never import `restserver` or `gserver`; `xhttp/header`,
`pkg/tlsconfig`, `pkg/tasks`, `pkg/discovery`, `pkg/streamctx` and
`metricskey` import nothing else from this module; `restserver` imports only
`restserver/*` and `xhttp/*`; `gserver` may import `restserver/*`,
`xhttp/*`, `pkg/transport`, `pkg/discovery` and `pkg/streamctx`.
`pkg/retriable` and `pkg/rpcclient` import `gserver/credentials` for token
types only. Nothing outside `tests/` imports `tests/`.

## NAVIGATION

Do not start by grepping the tree.

1. Open [`Documentation/codemap.md`](Documentation/codemap.md). Use the
   concept index to find the owning file, then the package section for
   entry points and invariants.
2. Open that file (and its `_test.go`) before searching elsewhere.
3. Grep or glob only if the concept is missing from the map. When you find
   it, add it to the map in the same change.
4. For high-level purpose, config samples and install path, see
   [`README.md`](README.md).

## CODING GUIDELINES

### Style

- Target Go 1.27 (`go.mod`). Use the standard library where it now covers a
  helper: `slices.Contains`, `cmp.Or`, `maps.Copy`, `strings.SplitSeq`,
  `min`/`max`, range-over-int, `math/rand/v2`, `crypto/rand`, and the
  standard `uuid` package (`uuid.NewV7().String()`). Do not add calls to
  functions marked `Deprecated` in the stdlib, in
  `github.com/effective-security/x`, or in third-party modules;
  `golangci-lint run` (staticcheck SA1019) must stay clean.
- Do not use long one-liners for map or struct population; split
  key-value pairs on new lines for readability.
- Do not use many hardcoded strings or integers; define `const` at the
  top of the file or in the package. Header and metadata names live in
  `xhttp/header`; reuse them.
- Memoize into variables; do not call functions with the same parameters
  more than once.
- Use `any`, not `interface{}`.

### Errors

- Use `github.com/cockroachdb/errors` for all error creation and wrapping.
- Wrap external errors (filesystem, YAML/JSON, network, Redis, gRPC, AWS
  SDK) using either:
  - `errors.WithMessage(err, "unable to read file")` for static context.
  - `errors.Wrapf(err, "failed to resolve file %s", path)` when context
    includes dynamic values.
- Errors originated from internal sentinel types must also be wrapped so
  the stack is preserved. For `var ErrNotFound = errors.New("not found")`
  do not simply `return ErrNotFound`.
- Compare errors with `errors.Is` / `errors.As`, never `==` or a type
  assertion. Errors returned to HTTP or gRPC callers go through
  `xhttp/httperror` so status codes and codes stay consistent.
- Never ignore errors from serialization, filesystem, or network calls in
  library paths that already return `error`. Helpers that intentionally
  swallow errors must keep that behavior documented in
  `Documentation/codemap.md`.
- Keep error strings accurate after refactors. Do not leave stale package
  or function names in runtime errors.
- Library code does not panic on bad input or bad configuration; it
  returns an error. The only intentional panics are `Must*` constructors
  and `init()`-time table construction.
- Every outgoing HTTP call takes a `context.Context` and a client with a
  timeout (`http.NewRequestWithContext`; no bare `http.Get`).
- Credentials: bearer tokens, cookies, private keys and PINs are never
  logged in full; token files are written with mode `0600`; random values
  come from `crypto/rand`; use constant-time comparison for secrets.
- Headers that carry caller identity (`X-Forwarded-For`, `X-Real-Ip`,
  `Authorization`, DPoP) are untrusted input. Do not widen what the
  servers accept from them without a `FINDINGS.md` or `ROADMAP.md` entry.

### Tests

- Build tests using `assert` and `require` from
  `github.com/stretchr/testify`; suites use `testify/suite`.
- Assert exact behavior, including key absence versus empty values and
  the real `err` from the call being tested.
- Do not assert on source line numbers or on exact compressed bytes; both
  change with unrelated edits or Go releases. Derive expected line numbers
  from `runtime.Caller` and compare decompressed payloads.
- Prefer table tests for conversion and formatting helpers.
- Use `package foo_test` for black-box tests and `package foo` only when a
  test needs unexported seams.
- External fixtures: `pkg/redisclient` and `pkg/cache` start a Redis
  container through `testcontainers-go`, so Docker must be running;
  `pkg/tlsconfig`, `pkg/transport`, `restserver` and `gserver` use the PEM
  fixtures under their `testdata/` directories and `tests/testutils`.
  Do not hard-code other paths; reuse the constants the packages define.
- Cover shared state with a test that actually races, and run
  `make test RACE=true` before proposing a change to shared state
  (scheduler, TLS reloader, caches, identity maps, token storage).
- This module has no gomock-generated interfaces; do not introduce mocks
  unless the package under test cannot be exercised directly.
- add `t.Parallel()` for tests that can run in parallel.

### Tools

- `make tools` : install golangci-lint, cov-report, govulncheck, gomarkdoc
- `make fmt` : apply go fmt with the project rewrites
- `make test` : test entire project (needs Docker for Redis-backed tests)
- `make testshort` : tests with `-test.short`
- `make lint` : gofmt, go vet, govulncheck, golangci-lint
- `make covtest` : coverage run and console report
- `make covtest coverage` : coverage run and HTML report
- `make docs` : regenerate the gomarkdoc API reference under `Documentation/api/`
- `make all` : clean, tools, generate, covtest

CI (`.github/workflows/unittest.yml`) runs `make lint` and
`make build covtest`, and its coverage status requires more than **90%**
total coverage (`MIN_TESTCOV`). Keep every package with statements above
90% too. CI does not run the race detector; run it locally. Pushes to
`main` that change `.VERSION` create a tag `<.VERSION>.<commit count>`.

### Documentation

- Every package has a `doc.go` with a package comment and, where the
  package has a non-obvious entry point, a short usage example.
- Document all exported types, functions, interfaces, and interface
  methods. Say what a symbol is _for_, not just what it is named.
- Keep samples in `doc.go`, the root `README.md`, `pkg/retriable/README.md`
  and `Documentation/` accurate against the current API. A wrong sample is
  worse than no sample; compile a changed sample before committing it.
- When you add a package, add it to the package table in the root
  `README.md`, add `doc.go`, and add a section plus concept-index rows in
  `Documentation/codemap.md`.
- When you find a defect you are not fixing in the same change, add it to
  `FINDINGS.md` with the next free ID and reference the ID from a code
  comment. Larger API or contract changes go to `ROADMAP.md`.

#### Keep `Documentation/codemap.md` current

Update the codemap in the **same change** when you add functionality or
make a major change, including:

- New, removed, or renamed package, subpackage, or file that owns a
  concept.
- New, moved, or renamed exported entry-point type, func, or interface.
- Changed invariants: panic vs error, process-global state (loggers,
  registries, default clients), locking, config file format, header or
  metadata names, supported auth methods, goroutine/callback rules, or
  internal imports between packages.
- Changed test layout or fixture conventions.

The map must stay the navigation index: concept → file → entry points →
invariants. If you had to grep to find something that belongs there, add
the row.

## REPOSITORY MAP

Start here instead of grepping the tree.

- **[`Documentation/codemap.md`](Documentation/codemap.md)** — concept
  index, per-package files and entry points, invariants, internal
  dependencies, test layout, build and CI.
- **[`README.md`](README.md)** — high-level overview, package table,
  configuration samples and quick-start code.
- **[`FINDINGS.md`](FINDINGS.md)** — known defects, referenced by ID from
  code comments. Read it before "fixing" surprising behavior: it may
  already be recorded, with the compatibility decision still open.
- **[`ROADMAP.md`](ROADMAP.md)** — larger planned work.
- **[`pkg/retriable/README.md`](pkg/retriable/README.md)** — retriable
  HTTP client usage.
- Package `doc.go` in each library package.
