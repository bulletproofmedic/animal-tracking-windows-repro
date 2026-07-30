# Generation 6 Manifest and CI Control Public Validation

This branch contains a fresh synthetic reproducer for immutable source-to-control-to-manifest Git-chain semantics.

It validates:

- a direct-child control commit;
- an exact four-path control boundary;
- a direct-child manifest-only head;
- source and control tree binding;
- deterministic path inventory and file counts;
- exact-head and merge-ref checkout discrimination;
- fail-closed rejection of stale trees, missing and extra inventory entries, stale versions, unauthorized paths, indirect ancestry, and non-manifest head changes.

The payload contains no private repository URL, private Git history, application source, user or property data, coordinates, media, credentials, configuration, databases, backups, logs, or production artifacts.

The project owner authorized this bounded public execution as sufficient producer validation for the corresponding private Generation 6 control candidate. It does not constitute an independent audit, owner-use authorization, release readiness, or production-release authorization.
