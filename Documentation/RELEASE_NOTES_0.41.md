# porto v0.41 release notes

## Major fixes

### Security

- Redact credential headers from retriable HTTP client debug dumps. Token and DPoP key writes now use private temporary files and replace existing credential paths atomically; newly created credential folders use mode `0700`.

### Concurrency, deadlocks and panics

- Synchronize retriable client setters and token refresh; missing or public-only DPoP signing keys now return errors.

- Make discovery registration and lookup safe for concurrent use; nil services now return an error, and iteration callbacks may register services.

### Correctness and interoperability

- Sign a fresh DPoP proof for each retry attempt.

- Forward a normalized correlation ID from HTTP requests to gRPC metadata, including the `x-request-id` alias when present.

- Honor gzip quality values for JSON responses, skip compression below 1 KiB, and add `Vary: Accept-Encoding`. Compressed JSON and unary gRPC-Web responses now reuse gzip writers.

### Tests and tooling

## New features and behaviour

## Breaking changes: what clients must change
