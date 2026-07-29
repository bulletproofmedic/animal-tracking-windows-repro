# Animal Tracking Windows Reproducer

This public repository is a **non-authoritative, sanitized Windows debugging surface** for the private Animal Tracking project.

## Authority boundary

- This repository is not a product source, release source, migration authority, governing manifest, or audit authority.
- Do not push, mirror, or import private Git history.
- Reproducer files must be copied as fresh files with no private commit ancestry.
- A successful run here does not establish that the complete private application passes.
- Any correction must be independently reviewed, applied to the assigned private branch, and rerun against the exact private commit.

## Prohibited content

Do not commit:

- credentials, tokens, keys, cookies, `.env` files, or private configuration;
- actual property coordinates, property boundaries, access routes, calibration data, or private map imagery;
- trail-camera media, people or vehicle imagery, owner databases, backups, exports, or production logs;
- proprietary third-party assets without redistribution permission;
- private repository archives, bundles, patches containing unrelated files, or copied `.git` data.

Use synthetic fixtures and the smallest code/test surface capable of reproducing the Windows-specific failure.

## Workflow

1. Freeze the exact private source commit and identify the failing test or command.
2. Build a minimal reproducer from fresh sanitized files.
3. Run the public `windows-2025` workflow.
4. Correct and validate the reproducer.
5. Export only the intentional fix diff.
6. Apply and inspect that fix on the assigned private branch.
7. Run the complete relevant private Windows validation before accepting the correction.

## Runner parity

The bootstrap workflow matches the private repository's current Windows baseline:

- GitHub-hosted `windows-2025`;
- CPython `3.13.14`;
- read-only `GITHUB_TOKEN` permissions;
- immutable action commit pins.

No licence is granted by publication of this repository. All rights are reserved unless a file states otherwise.
