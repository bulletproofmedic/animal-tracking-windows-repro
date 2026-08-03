# Generation 10 owner-cleanup launcher reproducer

This directory is a bounded, sanitized public Windows reproducer for the launcher integration boundary represented by private Animal Tracking diagnostic tree `5027c4696062006d0b48acc1e5c10d493fc8e28c`.

It tests the required combined behavior using synthetic dependencies and data only:

- one bounded security correlation around startup;
- minimum security logging before settings and recovery;
- stable recovery lock before reconciliation and restore activation;
- complete security-logger transition after runtime preparation;
- post-restore finalizers, preflight, readiness, and activation finalization order;
- recovery handling after restore or logger-transition failure; and
- exactly-once security failure events.

The payload does not copy private Git history, private data, configuration, credentials, media, maps, databases, logs, backups, or production evidence. It is an independent semantic model, not the private production launcher source.

A passing public result is supplemental diagnostic evidence only. It does not establish exact-private validation, satisfy the Generation 10 exact-blob manifest policy, authorize merge, establish implementation acceptance, authorize owner operational use, establish release readiness, or authorize production release.
