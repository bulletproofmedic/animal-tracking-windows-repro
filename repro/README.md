# AT-WAL-001 bounded public diagnostic

This is a fresh synthetic reproducer for five control questions associated with private remediation candidate `2d5f1b33d0fc973a6dee021dea8a73bc24b2f38a`.

It contains no private Git history, private repository URL, credentials, configuration, coordinates, maps, media, database, logs, backups, or production data.

The diagnostic covers:

1. stable external startup locking, one persisted secret, and losing-process no-mutation behavior;
2. service-layer interval chronology, predecessor identity, retirement, and rollback semantics;
3. review-resolution workflow gating and truthful before-state capture;
4. fail-closed manifest validation against committed Git blob bytes rather than checkout-transformed bytes;
5. deterministic exact commit-tree enumeration with separate worktree status and explicit executable, symlink, submodule, and LFS-pointer classification.

Database-level interval constraints are intentionally excluded because the private migration sequence is separately owned. A passing public result is diagnostic only and does not validate the private branch, close a finding, authorize merge, or replace required exact-private-commit Windows validation and independent revalidation.
