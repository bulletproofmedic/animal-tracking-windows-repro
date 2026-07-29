# Security Logging Windows Diagnostic

## Purpose

This is a fresh, sanitized, non-authoritative reproducer for Windows-specific security logging and file-activation controls.

It contains synthetic fixtures only. It does not contain private repository history, application configuration, user data, coordinates, media, production logs, archives, or third-party assets.

## Frozen private source identity

The bounded behavior was derived from the immutable private source target:

```text
source target: 26e26fc8446df2a913bcd9883193b16a1d3c8383
logging source blob: 4a527fca84a5dfe2305b589598e47d47fcfe6236
support source blob: f860864e223b849f9ab4c9ea16ee1ceef266c198
```

These hashes identify the source inspected when this fresh reproducer was prepared. No private commit ancestry or complete private source file was transferred.

## Diagnostic questions

The Windows run determines whether the isolated control pattern:

1. establishes protected ACLs owned by the current user;
2. leaves exactly one explicit FullControl Allow entry for the current user and one for LocalSystem;
3. applies exact file and directory inheritance and propagation flags;
4. reapplies those postconditions to active and rotated files through at least eleven rollovers;
5. blocks or detects same-size raw-byte mutation with restored modification time;
6. blocks or detects rename-and-recreate path replacement while a source handle is open;
7. rejects invalid UTF-8 input;
8. preserves an existing no-clobber destination;
9. verifies successful hard-link activation by identity, hash, size, and ACL; and
10. removes only the owned activated link when post-activation validation fails.

## Claim boundary

A successful public run supports only these isolated Windows diagnostic conclusions. It does not establish that the complete private application passes, that a packaged application has passed cross-user NTFS acceptance, that every audit finding is addressed, or that merge, owner use, release readiness, or release is authorized.

Any source correction discovered here must be independently reviewed and applied to the assigned private branch. Complete private exact-head validation remains required when private runner capacity is available and decision-relevant.
