## Summary

<!-- What changed and why? -->

## Change type

- [ ] Bug fix
- [ ] Detection / IOC update
- [ ] Feature
- [ ] Documentation / maintenance
- [ ] Breaking change

## Security and privacy review

- [ ] Scanner remains read-only; no unapproved remediation or system changes.
- [ ] No secrets, credentials, personal data, raw reports, or private samples are included.
- [ ] Detection claims are evidence-based and do not infer compromise from publisher affiliation.
- [ ] IOC provenance, confidence, scope, dates, false-positive notes, and redistribution terms are documented where applicable.

## Validation

- [ ] `go test -count=1 ./...`
- [ ] `go vet ./...`
- [ ] Windows amd64 build
- [ ] If Rust core changed: `cargo fmt --all -- --check`, `cargo test --locked`, and `cargo clippy --locked --all-targets -- -D warnings` from `rust-core/`
- [ ] Documentation and changelog updated where appropriate

## Additional context

<!-- Link relevant issues, sources, and sanitized evidence. -->
