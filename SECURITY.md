# Security and disclosure boundary

This repository is public. Do not report or attach private Animal Tracking data in issues, pull requests, workflow logs, or artifacts.

## Do not disclose

- credentials, tokens, keys, cookies, or private configuration;
- exact property coordinates, boundaries, access routes, or calibrated imagery;
- trail-camera media, people or vehicle imagery;
- owner databases, backups, exports, logs, or recovery packages;
- private repository history or unrelated proprietary source.

Use synthetic values and the minimum source required to reproduce a Windows-specific defect.

If sensitive content is committed:

1. stop further use of the affected branch;
2. revoke any exposed credential immediately;
3. remove the content from the current tree;
4. treat the content as already disclosed despite later deletion;
5. create a new sanitized reproducer from a verified clean source.

Do not use public issues for private incident details.
