# AT-WAL-005 Windows semantic reproducer

This is a fresh, sanitized diagnostic payload for the AT-WAL-005 remediation candidate identified by `3a49922910ca639c2f5c05332933db6e5baef0b5`.

It contains only the pure exposure and season semantics module plus its synthetic unit tests. It contains no private Git history, production data, property coordinates, media, database, configuration, credentials, or private repository reference.

## Diagnostic objective

On GitHub-hosted Windows 2025 with CPython 3.13.14:

1. compile the staged Python files;
2. run Ruff lint and format checks using the candidate's pinned tool version;
3. execute the ten pure semantic tests using the candidate's pinned pytest version.

A successful public result validates only this isolated semantic surface. It does not validate Django integration, database transactions, search/report/export population binding, web pagination, packaging, the complete private test suite, merge readiness, implementation acceptance, owner use, or release.
