# AT-WAL-006 bounded public diagnostic

## Purpose

This branch validates isolated synthetic control semantics corresponding to private remediation head
`7063ef35bd37621aee8af05b8cbb0c351dda9f68`.

The bounded question is whether the following pure control properties execute successfully on
Windows Server 2025 with CPython 3.13.14:

- invalid queries remain distinguishable from valid zero-result searches;
- species and direction predicates must match the same accepted child row;
- nonaccepted child rows are excluded from search projection and export;
- exact, minimum, estimated, and unknown counts remain separately classified;
- event-level child-derived groupings are prohibited because they are not partitions;
- empty and populated CSV files use identical ordered schemas;
- source-state changes fail closed;
- report and export populations have explicit limits;
- pagination materializes one bounded page;
- report hashes and CSV ordering are deterministic;
- site or deployment comparisons require verified exposure denominators.

## Disclosure boundary

The payload contains fresh synthetic code and synthetic identifiers only. It contains no private
Git history, private repository URL, credentials, configuration, locations, media, database,
archives, logs, or production data.

## Authority boundary

This is diagnostic evidence only. A passing public run does not validate Django ORM behavior,
database transactions, private integration, packaging, browser behavior, the complete private
branch, finding closure, merge readiness, owner operational use, or release readiness.
