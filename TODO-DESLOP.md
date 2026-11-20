Prefix: DSLP
Next: 15

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier E). One agent works this file with the `deslop` skill: take the lowest-numbered open ticket whose area does not start with `Needs owner ·`. After DSLP-5, work the open P1 and P2 findings, then fill in `## Report` below.

## Report

Scorecard (admission 76765cf to this pass): Rust production lines 35,471 → 35,494; Rust test lines 15,335 → 15,387, plus one Python test. Escape-hatch occurrences in `src`, `cli/src` and `examples` stayed at 197. No dead code or dependencies were removed. Warm local `make test` was 102.25s at Ground and 111.35s at DSLP-14; host load makes a performance comparison inconclusive. Line and branch coverage, and automated caught/missed/timeout/unviable mutant counts, need environment: cargo-llvm-cov and cargo-mutants are unavailable and not mirrored. Six hand-injected boundary faults were caught. Findings filed: two P2, both fixed; six P3 remain open. One selector regression introduced during this pass was caught and fixed before handoff; escaped regressions after handoff are unknown.

Ground: OrbStack Linux 7.2.12 aarch64's no-fail-fast suite reports 237 passed and the same 16 failures as admission revision 76765cf (102.25s warm). Failures include lost responses (DSLP-6), unavailable nft dup/fwd operations (DSLP-7), and a monitor mismatch (DSLP-8). A retry added an owned-table teardown failure (DSLP-9); ten isolated admission runs passed. Parent disposition: these 16 failures are host-kernel limitations; hosted CI is authoritative and the parent will check the PR's kernel job. Linux `make lint` passed in 5.27s.

Diagnose: qualification evidence recorded a failed Git lookup as its revision and still reported qualified (DSLP-10). Corrected the README's stale qualification statement. Local suite: 103.08s, the same 16 failures as admission; lint: 1.41s. Hosted CI minutes: not run locally.

Types: no strict candidate adopted without a defect witness and an acceptable false-positive rate. On all-feature library and binary targets, wildcard enum match reported 139 diagnostics, single-variant wildcard 5, truncating casts 108, sign loss 10, unwrap 49, expect 0, redundant clone 5, and needless pass-by-value 8; forbidding unsafe failed on existing FFI and async registration. These are discovery counts, not proven defects. Production Rust escape-hatch occurrences: 164 before and after. Local suite: 120.44s, same 16 failures as admission; lint: 0.24s. CI minutes: not run locally.

Tests: fault injections dropping lost-response handling, sentinel failure, rejection handling, and all but the first CLI mutation each failed the corresponding existing boundary test; sources were restored. The qualification false pass is DSLP-10. Needs environment: `cargo-llvm-cov` and `cargo-mutants` are unavailable and not mirrored; line/branch coverage and automated mutant counts are unmeasured, and no unqualified CI lane was added. These four injected faults are bounded witnesses, not a complete mutation sweep. Local suite: 113.07s, same 16 failures as admission; lint: 1.46s. No tests or production behavior were changed, so the suite budget is unaffected apart from host noise. CI minutes: not run locally.

Dead code: rustc `dead_code` on the all-feature library and `dead_code`/`unreachable_pub` on the binary produced no diagnostics. The fork's qualification harness, test utilities and typeof encoding have live test or compiler/decompiler callers; no behavior-preserving cut was established. Removed: 0 lines and 0 dependencies. Needs environment: cargo-machete and cargo-udeps are unavailable. Local suite: 97.34s, same 16 failures as admission; lint: 0.19s. Cargo interleaved one target header with the preceding test output, so its test path was checked against the panic location before comparison. CI minutes: not run locally.

Bench: the existing Full workload compares loading and listing large sets and rules and single transactions, but lacks packet throughput, tail latency, memory and CPU attribution (DSLP-13). A separate Change workload commits and verifies 1,000 rules; Edit checks selection. Both were exercised, including a deliberately missing binary, and Full was not run. Host readiness was not established, so no performance verdict is claimed. The container cannot resolve this worktree's Git revision and recorded it unavailable. Local suite: 134.49s, same 16 failures as admission; lint: 1.61s. Needs environment: a quiet host or paired busy-host evidence for performance comparisons. `mdtool` misclassified quoted Make variable values as targets in the benchmark guide. CI minutes: not run locally.

DSLP-10: failed Git revision lookup now prevents qualification; the existing explicit override remains supported. A regression failed before the fix and passed after it. Local suite: 124.61s, 238 passed and the same 16 failures as admission; lint: 1.87s. The container run supplied the worktree's pre-commit revision because its Git metadata is inaccessible. CI minutes: not run locally.

DSLP-14: explicitly requested benchmark workloads now fail selection if tier, area or skip excludes them. The regression failed before the fix and passes through `make test`. Local suite: 111.35s, 238 Rust tests passed and the same 16 failures as admission, plus one Python test passed; lint: 0.39s. CI minutes: not run locally.

Review: the cumulative pass was checked against e2762c2. The selector false pass became DSLP-14, Python test discovery now avoids writing bytecode into the worktree, and the benchmark propagates errors without new escape hatches. No other demonstrated finding remains open at P1 or P2.

Method feedback: a selection test must include explicitly requested workloads above the tier ceiling, not just unknown names and empty results. `mdtool` treated quoted Make variable values as target names. The dead-code scan established no safe removal.

Shared-file gaps: the deslop tools reference assumes cargo-llvm-cov, cargo-mutants and dead-code tools can be provisioned; this lane's owner ruling defers the unavailable tools and prohibits installing the first two. No shared file was changed. Needs environment: the parent must confirm the PR's hosted kernel integration job and the performance evidence described above.

## Tickets

### DSLP-6 · P3 · Investigate huge batch response loss on OrbStack kernel

- **Area:** deslop · verification
- **Where:** tests/errors.rs:270, src/batch.rs:574
- **Problem:** On privileged OrbStack Linux 7.2.12 aarch64, every_error_of_a_huge_batch_is_reported and known_issues::many_responses fail because responses_lost is true. Both also fail in the full suite at admission revision 76765cf; the former fails in isolation. The parent reports the upstream full suite passed on the hosted Linux kernel. The receive buffer estimate is unchanged from upstream; no passing isolated local rerun has been established.
- **Recommendation:** Reproduce on a supported Linux host and identify the response loss before changing the upstream implementation or accepting the test as flaky.
- **Fix with:** root-cause
- **Effort:** M

### DSLP-7 · P3 · Document verification on kernels without nft forward and duplicate

- **Area:** deslop · verification
- **Where:** tests/fuzz.rs, tests/lang_compile.rs, tests/lang_json.rs, tests/lang_list.rs, tests/roundtrip.rs, cli/tests/compat.rs
- **Problem:** On OrbStack 7.2.12 aarch64 without a module tree, nft rejects dup and fwd operations with No such file or directory. The admission revision 76765cf fails these same suite cases. Hosted Linux kernel verification is needed; no passing isolated rerun has been established locally.
- **Recommendation:** Run the affected integration cases on a Linux kernel with nft forward and duplicate support and document the required kernel features.
- **Fix with:** root-cause
- **Effort:** S

### DSLP-8 · P3 · Investigate monitor comparison on OrbStack kernel

- **Area:** deslop · verification
- **Where:** cli/tests/compat.rs:2004
- **Problem:** monitor_cli fails on OrbStack Linux 7.2.12 aarch64 at admission revision 76765cf and the candidate: the reference and candidate monitor output differ in delete events. Cause and passing isolated rerun are unverified.
- **Recommendation:** Reproduce in isolation and on the hosted kernel, then determine whether timing or kernel behavior explains the difference.
- **Fix with:** root-cause
- **Effort:** S

### DSLP-9 · P3 · Investigate intermittent owned table teardown failure

- **Area:** deslop · verification
- **Where:** tests/manage.rs:249
- **Problem:** On OrbStack Linux 7.2.12, owner_table_disappears_with_socket failed in 2 of 10 full-suite runs because the table remained after its socket closed. The admission full run and ten isolated admission runs passed. Pre-existence and cause remain unproven; the parent treats a single occurrence in a run as a host flake.
- **Recommendation:** Reproduce the failure under load and distinguish delayed kernel teardown from a product defect before changing the test or socket behavior.
- **Fix with:** root-cause
- **Effort:** M

### DSLP-11 · P3 · Investigate qualification watchdog pid reuse race

- **Area:** Qualification process lifecycle
- **Where:** tests/common/qualify.rs:556
- **Problem:** The watchdog signals a numeric child PID after a timeout, while wait_with_output reaps the child before the done sender is dropped. If the timeout falls between those events and the PID is reused, the signal can target a different process. This ordering risk has not been reproduced.
- **Recommendation:** Prove or exclude the race and use child-owned timeout and cleanup that cannot signal a reused PID.
- **Fix with:** lifecycle-concurrency
- **Effort:** M

### DSLP-13 · P3 · Measure packet workload and resource costs

- **Area:** deslop · bench
- **Where:** examples/bench.rs, examples/bench_change.rs
- **Problem:** The benchmarks cover rule and set loading, listing, and transaction latency, but do not measure packet throughput or tail latency, CPU per packet, memory, or attribution for realistic traffic. The upstream benchmark reports three-run medians without interleaved baseline comparison or a performance gate.
- **Recommendation:** Add a representative packet workload with correctness and completed-work checks, paired baseline measurements, and CPU and memory attribution before using it to make performance claims.
- **Fix with:** bench-pyramid
- **Effort:** M

