# PR17 synchronization compatibility diagnostic

This payload is a minimal synthetic model for the analysis snapshot boundary adopted after the AT-WAL-008 pure-core synchronization.

It tests only these demonstrated requirements:

1. one repository snapshot is opened per dataset build;
2. all row and dimension reads use that same session;
3. the source-state identity is stable from the first read through the final read;
4. success, cancellation, stream failure, and post-read validation failure close the snapshot exactly once;
5. typed record identities remain distinct when different record types share one stable identifier;
6. no fallback opens a second session after failure.

The payload contains synthetic identities and rows only. It contains no application source, private history, user data, locations, media, credentials, configuration, database, log, archive, or production artifact.

This is public diagnostic evidence. It does not establish execution of the private implementation target and does not close F-007.