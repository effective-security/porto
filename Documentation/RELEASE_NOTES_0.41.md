# porto v0.41 release notes

## Major fixes

### Security

- Redact credential headers from retriable HTTP client debug dumps. Token and DPoP key writes now use private temporary files and replace existing credential paths atomically; newly created credential folders use mode `0700`.

### Concurrency, deadlocks and panics

- Synchronize retriable client setters and token refresh; missing or public-only DPoP signing keys now return errors.

- Make discovery registration and lookup safe for concurrent use; nil services now return an error, and iteration callbacks may register services.

- Synchronize scheduler and task state, and make repeated `Stop` calls safe. A stopped scheduler can be restarted.

### Correctness and interoperability

- Sign a fresh DPoP proof for each retry attempt.

- Forward a normalized correlation ID from HTTP requests to gRPC metadata, including the `x-request-id` alias when present.

- Honor gzip quality values for JSON responses, skip compression below 1 KiB, and add `Vary: Accept-Encoding`. Compressed JSON and unary gRPC-Web responses now reuse gzip writers.

- `cache.GetOrSet` now stores a successful getter result using the provider's default TTL, reports invalid getter types without panicking, and returns cache write errors.

### Tests and tooling

## New features and behaviour

## Breaking changes: what clients must change

- `Scheduler.List` now returns a copy of its slice, `Task.Schedule` returns a snapshot, and `New(s)` copies its input schedule. Use `Add`/`Clear` and `SetNextRun`/`UpdateSchedule` to change live state; mutating returned values or the original `s` no longer changes the scheduler or task.

- `cache.GetOrSet` now writes on a cache miss. Callers that require a read without a cache write should use `Get` and their getter directly. On a miss, the destination must point to a concrete type; interface destinations return an error because their values cannot round-trip reliably across providers.
