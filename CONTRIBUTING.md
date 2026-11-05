# Contributing

Thanks for helping improve Tencent Game Audit.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Use the repository's issue forms for bugs, detection reviews, feature requests, game compatibility, and sourced threat-intelligence proposals. Vulnerabilities must be reported privately as described in [SECURITY.md](SECURITY.md).

## Before submitting

- Keep the scanner read-only. Do not add automatic deletion, quarantine, process termination, or security-setting changes without a separately reviewed design.
- Treat Tencent ownership, publishing, operation, and investment as distinct relationships. Never infer compromise from corporate affiliation alone.
- Keep IOC provenance, confidence, affected product/region, date context, and licensing information with every new indicator.
- Prefer locale-neutral APIs and environment variables over hard-coded drive letters, usernames, country assumptions, date formats, or localized command output.
- Keep JSON field names stable and machine-readable. Add tests for locale aliases, non-ASCII paths, and regional game naming where relevant.
- Avoid logging secrets or uploading raw audit reports. Reports may contain sensitive host information.

## Validation

From `tencent-game-audit/` run:

```powershell
go test -count=1 ./...
go vet ./...
$env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'; go build -trimpath -o Tencent-Game-Audit.exe .
```

If you change the experimental Rust core, run the following from `rust-core/`:

```powershell
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

The Rust core currently provides bounded-memory streaming primitives and is tested independently. It is not yet linked into or required by the released Go executable. Do not introduce an FFI or subprocess dependency into the production scanner without a reviewed compatibility, packaging, and failure-reporting design.

Do not commit generated executables, ZIPs, scan reports, local caches, or private samples. Publish binaries as assets on a versioned GitHub Release.
