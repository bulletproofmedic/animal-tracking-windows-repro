# AT-WAL-008 bounded public diagnostic

## Objective

Determine whether two unvalidated candidate ideas are technically worth transferring to a separately authorized private remediation owner:

1. a derived rate must use the derived-rate inclusion permission rather than the raw-event permission;
2. cancellation checks must occur during material preprocessing and bounded sorting work.

## Candidate provenance

The private reference commits are identified only by immutable commit IDs:

- `9ec3f657fc17e58d24c58045e7754c2b14bc5bee` — candidate implementation ideas;
- `c46c7b81ad5e4d4cff1514278659d849763e4f5a` — candidate regression-test ideas.

This reproducer is a fresh, synthetic implementation. It does not contain private Git history, private repository URLs, application configuration, credentials, maps, coordinates, media, databases, logs, or production data.

## Pass/fail objective

The diagnostic passes only when:

- the negative rate control reproduces the zero-numerator defect;
- the candidate rate logic counts rate-only events and does not promote raw-event-only eligibility;
- the negative preprocessing control demonstrates the missing cancellation boundary;
- the candidate logic cancels during preprocessing and bounded sorting;
- deterministic grouping and ordering remain stable;
- the public payload guard passes on Git history and the working tree.

## Stop condition and use

One successful `windows-2025` pull-request run is the stop condition. The result is diagnostic evidence only. It does not authorize remediation, validate the complete private branch, close any finding, establish merge readiness, or replace exact private-commit validation and independent re-audit.
