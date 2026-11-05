# Project Governance

## Current project status

Tencent Game Audit is maintained as an independent community security tool. It is not affiliated with, endorsed by, or an official product of Tencent or any game publisher. Corporate ownership, publishing, operation, and investment relationships are recorded separately and are not evidence of compromise.

## Roles and decisions

- The repository owner currently acts as project maintainer and release manager.
- The maintainer reviews code, detection logic, documentation, dependencies, and release changes.
- Contributors may propose changes through pull requests. A pull request is not accepted until reviewed and merged by the maintainer.
- Security-sensitive changes, new high-severity IOCs, and changes that expand collection or system-modification behavior require explicit maintainer review.

## Issue and contribution workflow

- Public issues are categorized through repository issue forms: bug report, detection review, feature request, game compatibility, and threat-intelligence submission.
- Public issue reports must be sanitized. Vulnerabilities, live payloads, credentials, private samples, and unredacted host reports belong in private channels, never public issues.
- Maintainers apply labels for triage, affected subsystem, confidence, and release milestone. A report is not a confirmed incident merely because it is submitted.
- Pull requests should link the issue they address and include regression tests for detection or scanner behavior changes.

## Releases

- Releases use version tags in the form `vMAJOR.MINOR.PATCH`.
- Each release must pass automated tests, static analysis, and a Windows x64 build.
- Changes to `rust-core/` must also pass stable-toolchain formatting, tests, and Clippy checks. The experimental crate is not bundled into the production release until parity, performance, and packaging reviews are complete.
- Release assets should include a SHA-256 checksum file. Users should obtain binaries only from this repository's Releases page and verify checksums before execution.
- Every release should include a concise change summary, known limitations, supported platforms, and a verified checksum. Dependency and workflow changes receive the same review as application code.
- Detection changes should document provenance, confidence, affected scope, false-positive considerations, and known limitations.

## Project principles

1. Read-only by default; no silent remediation or destructive actions.
2. Evidence-led detection; no unsupported attribution or infection claims.
3. Privacy by default; no automatic report or sample upload.
4. Reproducible builds and transparent release notes.
5. Stable machine-readable output and backward-conscious changes.

This document describes the current maintainer-led project. It may evolve as the contributor community grows.
