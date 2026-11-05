# Open Project Decisions

This file records decisions that require maintainer input or additional evidence. A public repository is not automatically an open-source-licensed project.

## License selection — maintainer decision required

The repository currently has no declared license. Until the owner selects and adds a license, all rights are reserved; public visibility does not grant permission to reuse, redistribute, or relicense the source or IOC data. Do not add a license automatically as part of routine engineering work.

Common choices to evaluate with the repository owner:

- **Apache-2.0:** permissive reuse, explicit patent grant, and notice requirements.
- **MIT:** short permissive license with minimal conditions; no express patent grant comparable to Apache-2.0.
- **GPL-3.0-only:** strong copyleft for distributed derivative works.
- **Dual licensing:** possible, but requires clarity on ownership and contributor rights.

The license for source code and the redistribution terms for third-party IOC data may differ. Each IOC source must retain its own provenance and license notes. A license decision should be reviewed before describing the project as fully open source or accepting broad external contributions.

## Release readiness decisions

- Decide whether to enable GitHub Discussions after community support volume justifies another public channel.
- Decide whether to require signed commits or release attestations after evaluating maintainer key management and CI support.
- Decide whether to enable GitHub private vulnerability reporting if it is not already available in repository settings.
- Keep Rust core experimental until detection parity, memory benchmarks, and the Windows packaging/integration design are approved.
