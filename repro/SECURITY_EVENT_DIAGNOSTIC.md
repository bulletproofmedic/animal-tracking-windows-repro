# Release 1 Security-Event Lifecycle Diagnostic

## Purpose

This branch is a bounded, sanitized Windows/Python diagnostic for the application-security event lifecycle associated with `AT-R1-SEC-CF-003`.

It answers one question:

> On Windows with Python 3.13.14, does the sanitized lifecycle preserve a bounded minimum journal before settings and recovery, transition to a complete logger without replay, emit only fixed privacy-safe rejection and failure events, and enforce the support-event boundary?

## Sanitized payload

The payload contains only fresh synthetic source and tests:

- `repro/security_event_lifecycle.py`
- `repro/tests/test_security_event_lifecycle.py`
- `repro/run.ps1`
- this document

It contains no private repository history, application data, coordinates, media, databases, backups, credentials, secrets, private configuration, production logs, or user identifiers.

## Covered behaviors

The tests cover:

1. minimum logger initialization before settings and recovery callbacks;
2. complete logger transition after recovery activity;
3. retained bootstrap events without replay or duplication;
4. Host, Origin, and CSRF rejection events that discard raw request-controlled values;
5. unavailable-control recording when complete logger transition fails;
6. support-candidate creation requiring the complete logger;
7. bounded creation, disclosure, degradation, rejection, and success events;
8. permission and startup failure events without exception text or path disclosure;
9. bounded numeric fields and a closed event schema;
10. bounded bootstrap journal rotation.

## Excluded behaviors

This diagnostic does not validate:

- private source identity or private Git ancestry;
- exact private dependency integration;
- production ACL implementation;
- production support-bundle archive construction;
- Django middleware integration;
- production recovery implementation;
- packaging or installer behavior;
- the complete private test suite;
- security acceptance, merge readiness, owner use, or release readiness.

## Commands

```powershell
python -m compileall -q repro
python -m unittest discover -s repro/tests -p 'test_security_event_lifecycle.py' -v
```

## Decision rule

A passing public run establishes only bounded diagnostic confidence in the represented lifecycle semantics. It does not replace exact private-commit validation or independent re-audit.

A failing test is actionable only when the failure is attributable to the sanitized lifecycle rather than workflow startup or runner allocation.
