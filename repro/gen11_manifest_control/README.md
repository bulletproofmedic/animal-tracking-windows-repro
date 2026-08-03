# Generation 11 manifest-control reproducer

This directory is the mandatory sanitized public fallback for the Generation 11 Animal Tracking manifest controller after the exact private CI run and its single retry failed before executing any step.

The reproducer uses synthetic Git objects only. It validates the successor control model:

- an exact base commit;
- one direct source child and exact source delta;
- a four-path control child;
- a manifest-only child;
- an ordered two-parent retained target with zero delta; and
- an exact two-parent post-main merge whose tree is reconstructed from the prior main tree plus source, control, and manifest overlays.

The test includes one positive topology and eleven fail-closed mutations covering base, source delta, source tree, control parent, retained parents/tree, merge parent/tree, merge method, and controlled-path inventory.

`private_identity_binding.json` records the exact private commits, trees, blob identities, and manifest digest represented by the fallback. No private Git history, application source, configuration, credentials, media, coordinates, databases, logs, backups, or production evidence is copied into this repository.

A pass is supplemental diagnostic evidence only. It does not replace exact-private validation, establish independent audit closure, authorize merge, establish implementation acceptance, authorize owner operational use, establish release readiness, or authorize production release.
