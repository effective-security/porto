# Findings remediation plan

This queue groups the open issues in [FINDINGS.md](FINDINGS.md) into
reviewable implementation batches. The batches follow package ownership and
shared behavior; a finding that spans packages is completed only when every
named part is fixed. Completed batches are removed; their public behavior
changes are in [the 1.0 release notes](Documentation/RELEASE_NOTES_1.0.md).

Work from top to bottom within each priority. Independent batches can proceed
separately. A batch with an entry in the **Decision** column needs its
compatibility or configuration choice resolved before changing the affected
behavior. Its reproduction, tests, and design can proceed while that choice
is pending. The related larger designs are recorded in
[ROADMAP.md](ROADMAP.md).

No open remediation batches. B33–B37 are complete; their behavior changes
and migration guidance are recorded in
[the 1.0 release notes](Documentation/RELEASE_NOTES_1.0.md).

## Execution rules

1. Confirm each finding against the current code and add a regression test
   for its observable behavior. Preserve its ID until all portions of a
   multi-package finding are complete.
2. For rows with a **Decision**, record the selected behavior and any migration note
   before implementation. An open compatibility decision must be resolved
   explicitly; this plan does not grant approval.
3. Keep each code change reviewable. A multi-package batch may be delivered
   as linked package-scoped changes, with the same batch ID and a single
   final completion check. Update the codemap when entry points, ownership,
   invariants, configuration, or dependency directions change.
4. Run targeted package tests and affected consumers. For shared-state fixes,
   use a test with overlapping reads and writes and run `make test RACE=true`
   with Docker available for the Redis-backed tests. Benchmark performance
   fixes against the same scenario before and after; run race checks
   separately from timing.
5. Obtain an independent code review and address its comments; record the
   review in `PR_REVIEW.md`. Run `make testshort` and `make lint`; run the full
   `make test` suite with Docker for the final integrated change. Keep the total coverage above the
   90% CI gate (`MIN_TESTCOV`) and every package with statements above 90%.
   Record any unavailable fixture or incomplete check.
6. When a batch is complete, remove its fixed findings from `FINDINGS.md`,
   remove the batch from this queue, and note public behavior changes in the
   next release notes. If only part of a finding is fixed, leave the ID and
   record the remaining portion here. Never reuse an ID.
