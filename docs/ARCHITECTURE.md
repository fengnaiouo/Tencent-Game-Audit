# Architecture and Rust Core Roadmap

## Current production architecture

The released Windows application is a Go executable. Go owns command-line parsing, Windows discovery, filesystem traversal, detection orchestration, report generation, localization, and the portable release. The production executable is CGO-free and has no Rust runtime dependency.

## Experimental Rust core

`rust-core/` is an independently tested Rust library, not yet invoked by the Go application. Its first responsibility is to establish bounded-memory primitives that can be compared against the current Go implementation before any production migration.

Current capabilities:

- Fixed-size streaming reads; default 4 MiB, configurable from 256 KiB through 16 MiB.
- Streaming SHA-256 without loading the full file into memory.
- Multi-pattern byte IOC matching, including matches spanning read-buffer boundaries.
- Per-pattern occurrence aggregation and first-match offsets, avoiding an unbounded list of every match.
- A memory-budget-derived worker limit. The estimate includes each worker's read buffer, pattern overlap, and a fixed overhead allowance.
- Per-file errors are returned as incomplete outcomes; callers must not silently count failed reads as clean scans.
- Unsafe Rust is forbidden in the crate.

The memory budget is an admission-control estimate for scanner-owned working buffers, not a hard process RSS limit. Each worker uses one allocation sized for the read buffer plus pattern overlap. Allocator metadata, the compiled IOC automaton, per-pattern result records, caller-owned traversal queues, Go runtime memory, OS cache, and other application components are outside that estimate. The caller must use the returned worker limit and avoid creating additional unbounded buffers.

## Integration stages

1. **Prototype (current):** independent crate, unit tests, CI formatting/test/lint checks.
2. **Parity:** feed identical synthetic and sanitized real-world fixtures to Go and Rust; compare hashes, IOC identities, offsets, error accounting, and coverage flags.
3. **Benchmarks:** measure peak working set, throughput, CPU, allocation behavior, and concurrency under constrained memory on supported Windows systems.
4. **Integration decision:** choose a stable boundary only after parity. Options include a separately packaged helper process or a carefully reviewed native library boundary. The existing CGO-free portability requirement is a constraint; no FFI or subprocess integration is assumed.
5. **Gradual migration:** move one well-defined workload at a time, preserve Go fallback where appropriate, and keep report schemas backward-compatible.

## Resource policy

The initial defaults are engineering starting points, not universal performance claims:

| Setting | Default | Supported range / behavior |
|---|---:|---|
| Read buffer | 4 MiB | 256 KiB–16 MiB |
| Worker memory budget | 256 MiB | Configurable; must fit at least one worker |
| Maximum workers | 8 | Further reduced by the memory budget |
| Match retention | One aggregate per IOC pattern | Count saturates at `u64::MAX`; first offset retained |

The buffer size is not a file-size limit. Large files are streamed until EOF or a reported read error. Memory pressure should reduce concurrency or pause work, never silently discard files.

## Non-goals for the first prototype

- Replacing the Go executable wholesale.
- Automatically unpacking, decrypting, or executing scanned content.
- Following symbolic links/reparse points beyond the existing Go scan-scope policy.
- Claiming a complete content analysis merely because filesystem traversal completed.
- Publishing the Rust core as production-ready before parity and Windows integration tests.
