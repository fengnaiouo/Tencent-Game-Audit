# Project Governance

## Current project status

Tencent Game Audit is maintained as an independent community security tool. It is not affiliated with, endorsed by, or an official product of Tencent or any game publisher. Corporate ownership, publishing, operation, and investment relationships are recorded separately and are not evidence of compromise.

## Roles and decisions

- The repository owner currently acts as project maintainer and release manager.
- The maintainer reviews code, detection logic, documentation, dependencies, and release changes.
- Contributors may propose changes through pull requests. A pull request is not accepted until reviewed and merged by the maintainer.
- Security-sensitive changes, new high-severity IOCs, and changes that expand collection or system-modification behavior require explicit maintainer review.

## Releases

- Releases use version tags in the form `vMAJOR.MINOR.PATCH`.
- Each release must pass automated tests, static analysis, and a Windows x64 build.
- Release assets should include a SHA-256 checksum file. Users should obtain binaries only from this repository's Releases page and verify checksums before execution.
- Detection changes should document provenance, confidence, affected scope, false-positive considerations, and known limitations.

## Project principles

1. Read-only by default; no silent remediation or destructive actions.
2. Evidence-led detection; no unsupported attribution or infection claims.
3. Privacy by default; no automatic report or sample upload.
4. Reproducible builds and transparent release notes.
5. Stable machine-readable output and backward-conscious changes.

This document describes the current maintainer-led project. It may evolve as the contributor community grows.
