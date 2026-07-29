# AT-R1-SEC-CF-009 sanitized packaged Windows/NTFS diagnostic

This directory contains a fresh, synthetic reproducer for Windows packaging and
NTFS access-control behavior. It is not copied repository history and does not
contain private data, media, logs, configuration, databases, coordinates,
credentials, or production artifacts.

The diagnostic:

- packages a minimal helper with PyInstaller `onedir`;
- records package and executable identities;
- verifies owner and LocalSystem FullControl;
- performs an actual denied-access probe from a temporary unauthorized account;
- executes eleven log rollovers;
- records active and rotated log ACLs;
- exercises temporary and activated support-bundle files;
- injects interruption at workspace, temporary-archive, and activated-archive phases;
- exercises cleanup, restart, staged upgrade, and interrupted upgrade behavior;
- injects ACL establishment and verification failures and requires fail-closed outcomes.

A successful public run is diagnostic evidence only. It does not replace the
required private-package acceptance against the exact private implementation.
