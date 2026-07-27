# Reproducer staging area

Place only the minimum sanitized files needed to reproduce one Windows-specific defect in this directory.

Recommended structure:

```text
repro/
├── run.ps1
├── src/
├── tests/
└── requirements.lock
```

`run.ps1` is the workflow entry point. It must:

- stop on the first error;
- install only explicitly pinned dependencies;
- use synthetic fixtures;
- run the smallest deterministic command that reproduces the defect;
- return a nonzero exit code while the defect is present;
- return zero only after the correction passes.

Do not copy a private branch, `.git` directory, repository bundle, database, media corpus, backup, export, or unrelated project code into this directory.
