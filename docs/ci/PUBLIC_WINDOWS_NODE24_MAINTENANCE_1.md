# Public Windows Node 24 Maintenance

## Exact maintenance identity

- Branch: `chore/public-node24-shallow-checkout`
- Workflow: `.github/workflows/windows-repro.yml`
- Scope: one permanent public diagnostic workflow plus this maintenance record

## Changes

- `actions/checkout` updated from the Node 20 v4.2.2 immutable pin to the Node 24 v6.1.0 immutable pin.
- `actions/setup-python` updated from the Node 20 v5.4.0 immutable pin to the Node 24 v6.3.0 immutable pin.
- Pull-request checkout is bound to the exact PR head SHA.
- Checkout depth is reduced to one commit.
- The checked-out SHA is verified before validation.

## Reason

This removes the GitHub Actions Node.js 20 deprecation warning and prevents unrelated historical Base64 payloads on old diagnostic branches from contaminating current bounded payload checks.

## Shared-file coordination

Open diagnostic PRs #6 and #9 also contain historical changes to `.github/workflows/windows-repro.yml`. They must not overwrite this maintenance version. Any continued work on those PRs must rebase onto the adopted public `main` workflow and retain the Node 24 pins and exact shallow checkout.

## Boundaries

No private source, history, data, credentials, configuration, coordinates, media, database, backup, audit evidence, or private repository workflow is changed.
