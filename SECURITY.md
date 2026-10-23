# Security Policy

This tool is used to decide whether software artifacts can be trusted, so bugs that make it accept something it should reject are treated as security vulnerabilities.

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` branch (latest) | Yes |
| Older commits and forks | No |

Fixes are only made on `main`. Please update to the latest commit before reporting.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately using GitHub's [private vulnerability reporting](https://github.com/mgnyu/python-rekor-monitor-template/security/advisories/new) (Security tab → "Report a vulnerability"), or email the maintainer at mg8207@nyu.edu.

Please include:

- a description of the issue and its impact (e.g. a forged artifact or tampered proof that passes verification)
- steps or a minimal input to reproduce it
- the commit you tested against

## What to expect

| Step | Target time |
|------|-------------|
| Acknowledge your report | within 3 business days |
| Confirm the issue and assess severity | within 7 days |
| Release a fix for confirmed issues | within 30 days, sooner for critical issues |

We'll keep you updated, credit you in the advisory unless you prefer otherwise, and ask that you keep the details private until a fix is released.

## How security updates are handled

- Fixes are developed in a private fork or advisory, reviewed, and merged to `main` through a pull request.
- A GitHub Security Advisory is published describing the affected commits and the fix.
- Dependencies are pinned in `poetry.lock`. Dependency vulnerabilities are fixed by updating the lock file.

## In scope

- Signature or certificate checks that accept invalid input
- Inclusion or consistency proofs that verify when they shouldn't
- Secrets committed to the repository

Out of scope: vulnerabilities in Rekor/Sigstore themselves (report those to [Sigstore](https://github.com/sigstore/rekor/security)).
