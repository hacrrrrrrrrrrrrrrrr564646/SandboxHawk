# SandboxHawk 🦅

**Local JavaScript mutation fuzzer for authorized V8 sandbox research.** Built in Go; designed for Linux and usable from Termux where Go and a compatible local `d8` binary are available.

## MVP

- Recursively discovers JavaScript seeds from V8/Fuzzilli-style corpus folders.
- Applies lightweight source mutations and runs a local `d8` subprocess with a timeout.
- Caps captured output, retains behaviorally novel testcases, and deduplicates candidate crashes.
- Writes `findings.json`, `REPORT.md`, and testcase artifacts.
- Includes a line-based delta-debugging minimizer that preserves the observed failure class.
- Uses only Go's standard library.

## Quick start

Install Go, build or obtain a local V8 `d8` binary that you are authorized to test, then:

```sh
go test ./...
go build -o sandboxhawk .
./sandboxhawk scan -d8 /absolute/path/to/d8 -corpus ./testdata/seeds -out ./artifacts -runs 1000 -timeout 2s
```

Minimize a saved candidate by repeatedly removing line chunks while checking that the failure class and normalized output remain stable:

```sh
./sandboxhawk minimize -d8 ./v8/out/x64.release/d8 -input ./artifacts/crashes/sanitizer-abc.js -out ./artifacts/minimized.js
```

If `d8` is on your PATH, `-d8 d8` works. Import additional seed files by placing them in a corpus directory:

```sh
./sandboxhawk scan -d8 ./v8/out/x64.release/d8 -corpus ./my-js-corpus -out ./artifacts -runs 5000
```

## Output

- `artifacts/interesting/`: first testcase for each distinct behavior signature.
- `artifacts/crashes/`: one testcase per deduplicated crash/timeout/sanitizer signature.
- `artifacts/findings.json`: machine-readable candidate findings.
- `artifacts/REPORT.md`: human-readable summary.

A normal JavaScript exception is **not** automatically treated as a native crash. Sanitizer messages are separately tagged. Each finding is only a candidate until it can be reproduced and investigated.

## Honest coverage status

This MVP uses **behavioral-signature feedback**, not native V8 edge coverage. It does not claim to be a full coverage-guided fuzzer yet. True native coverage-guided fuzzing needs an instrumented V8 build or a native harness exposing coverage feedback. The next milestone is a pluggable coverage adapter and corpus scheduler; AST-aware dependency loading and semantics-preserving minimization are also planned.

## Safety and isolation

Only run this against a local V8 build or another target you are explicitly authorized to test. Run in a disposable VM/container with no secrets and restricted networking when testing untrusted seeds. The subprocess timeout is not a complete OS sandbox and does not prevent all resource exhaustion. SandboxHawk does not exploit crashes or automatically submit reports.

## Reference material

The V8 corpus/source-loader code you shared is used as a design reference for seed discovery and source handling. SandboxHawk's initial Go implementation is independently written and does not bundle the V8 JavaScript source loader or its Babel dependencies. Respect the upstream V8 license when copying or modifying upstream code.

## Roadmap

- [x] Go CLI and local `d8` runner
- [x] Seed discovery and basic JS mutations
- [x] Timeout, sanitizer-output and crash candidate triage
- [x] JSON and Markdown reports
- [ ] Native edge-coverage feedback adapter
- [ ] Persistent SQLite corpus and scheduling
- [x] Basic line-based reproduction-preserving testcase minimization
- [ ] Optional AST parser/dependency loader
- [ ] CI smoke tests and reproducible release builds
