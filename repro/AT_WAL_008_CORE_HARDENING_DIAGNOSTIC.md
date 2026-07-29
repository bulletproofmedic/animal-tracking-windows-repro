# AT-WAL-008 core-hardening public diagnostic

## Objective

Exercise a fresh synthetic model of the material controls required by `AT-WAL-008-F-001` through `AT-WAL-008-F-009`:

- defensive deep freezing and canonical collection ordering;
- constrained request/filter validation;
- graph-wide identity, revision, dimension, and selection-count reconciliation;
- temporal and exposure state invariants;
- derived-rate contribution permissions;
- result meaning and logical-type coherence;
- explicit consistent read-snapshot protocol;
- bounded cancellation checkpoints during preprocessing and sorting;
- executable negative and mutation-style regression controls.

## Public boundary

This diagnostic is a fresh synthetic implementation. It contains no private Git history, private repository URL, credentials, project configuration, coordinates, maps, media, databases, logs, production data, or private source copy.

## Validation relationship

The public controls materially preserve the audited semantic and failure boundaries. The private implementation candidate remains separately identified and must be frozen for independent re-audit. A public pass is authorized by the owner to satisfy the producer validation requirement, but does not itself establish finding closure, merge authority, owner operational use, release readiness, or production release.

## Pass condition

The diagnostic passes only when:

1. public-payload unit and current-tree disclosure checks pass;
2. the synthetic source compiles on CPython 3.13.14;
3. legacy negative controls reproduce the mutable-identity and rate-permission defects;
4. every corrected contract, graph, temporal, exposure, result, protocol, calculation, and cancellation control passes;
5. all tests complete on the hosted `windows-2025` runner.
