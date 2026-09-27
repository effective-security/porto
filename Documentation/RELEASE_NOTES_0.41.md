# porto v0.41 release notes

## Major fixes

### Security

- Redact credential headers from retriable HTTP client debug dumps. Token and DPoP key writes now use private temporary files and replace existing credential paths atomically; newly created credential folders use mode `0700`.

### Concurrency, deadlocks and panics

- Synchronize retriable client setters and token refresh; missing or public-only DPoP signing keys now return errors.

### Correctness and interoperability

- Sign a fresh DPoP proof for each retry attempt.

- Forward a normalized correlation ID from HTTP requests to gRPC metadata, including the `x-request-id` alias when present.

### Tests and tooling

## New features and behaviour

## Breaking changes: what clients must change
