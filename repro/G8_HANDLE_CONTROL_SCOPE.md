# Generation 8 Windows handle-control diagnostic

This branch contains a fresh, sanitized Windows diagnostic for the source-remediation control classes associated with private Generation-8 source commit `eb22804c1027039ba55b1b19e8b1ce8e0aed380e`.

It validates only synthetic local files and these Windows platform behaviors:

1. a normal Python append-mode file descriptor can be reopened for bounded read access through the same file object;
2. owner and protected DACL state can be verified through the exact open handle;
3. replacing a pathname cannot make a different file satisfy exact-object acknowledgement;
4. deletion through an open handle removes the validated object rather than a later pathname replacement;
5. handle-bound no-replace rename preserves an existing destination;
6. concurrent exact-object verification remains within the declared source budget and starts no additional PowerShell process after initial ACL establishment.

The payload contains no private repository history, application source tree, credentials, configuration, coordinates, maps, media, databases, logs, archived evidence, or production data. All files and records are synthetic and created in the hosted runner temporary directory.

A successful run is bounded producer diagnostic evidence only. It does not replace exact-private validation, close findings by itself, authorize merge, authorize owner use, or establish release readiness.
