# Generation 11 post-merge candidate fallback

This directory contains a sanitized, standard-library-only Git topology model for the exact private Generation 11 post-merge candidate.

It tests the bounded question that private CI run `30860926077` could not execute because the Windows runner failed before step 1 on the initial job and the single permitted retry.

The model verifies:

- one exact base-to-source edge;
- one exact four-path control child;
- one manifest-only child;
- ordered retained parents with zero retained delta;
- a stable-main delta of exactly five coordination paths;
- an exact two-parent candidate with stable main first and retained target second;
- deterministic candidate tree reconstruction; and
- five fail-closed mutations.

`private_identities.json` binds the public result to the exact private commit and tree identities without copying private repository source or history.

This evidence is supplemental. It does not replace exact-private validation, independent audit, implementation acceptance, owner operational authorization, release readiness, or production release authorization.
