Prefix: DSLP
Next: 12

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier E). One agent works this file with the `deslop` skill: take the lowest-numbered open ticket whose area does not start with `Needs owner ·`. After DSLP-5, work the open P1 and P2 findings, then fill in `## Report` below.

## Report

Ground: OrbStack Linux 7.2.12 aarch64's no-fail-fast suite reports 237 passed and the same 16 failures as admission revision 76765cf (102.25s warm). Failures include lost responses (DSLP-6), unavailable nft dup/fwd operations (DSLP-7), and a monitor mismatch (DSLP-8). A retry added an owned-table teardown failure (DSLP-9); ten isolated admission runs passed. Parent disposition: these 16 failures are host-kernel limitations; hosted CI is authoritative and the parent will check the PR's kernel job. Linux `make lint` passed in 5.27s.

Diagnose: qualification evidence recorded a failed Git lookup as its revision and still reported qualified (DSLP-10). Corrected the README's stale qualification statement. Local suite: 103.08s, the same 16 failures as admission; lint: 1.41s. Hosted CI minutes: not run locally.

Types: no strict candidate adopted without a defect witness and an acceptable false-positive rate. On all-feature library and binary targets, wildcard enum match reported 139 diagnostics, single-variant wildcard 5, truncating casts 108, sign loss 10, unwrap 49, expect 0, redundant clone 5, and needless pass-by-value 8; forbidding unsafe failed on existing FFI and async registration. These are discovery counts, not proven defects. Production Rust escape-hatch occurrences: 164 before and after. Local suite: 120.44s, same 16 failures as admission; lint: 0.24s. CI minutes: not run locally.

Tests: fault injections dropping lost-response handling, sentinel failure, rejection handling, and all but the first CLI mutation each failed the corresponding existing boundary test; sources were restored. The qualification false pass is DSLP-10. Needs environment: `cargo-llvm-cov` and `cargo-mutants` are unavailable and not mirrored; line/branch coverage and automated mutant counts are unmeasured, and no unqualified CI lane was added. These four injected faults are bounded witnesses, not a complete mutation sweep. Local suite: 113.07s, same 16 failures as admission; lint: 1.46s. No tests or production behavior were changed, so the suite budget is unaffected apart from host noise. CI minutes: not run locally.

Dead code: rustc `dead_code` on the all-feature library and `dead_code`/`unreachable_pub` on the binary produced no diagnostics. The fork's qualification harness, test utilities and typeof encoding have live test or compiler/decompiler callers; no behavior-preserving cut was established. Removed: 0 lines and 0 dependencies. Needs environment: cargo-machete and cargo-udeps are unavailable. Local suite: 97.34s, same 16 failures as admission; lint: 0.19s. Cargo interleaved one target header with the preceding test output, so its test path was checked against the panic location before comparison. CI minutes: not run locally.

## Tickets

### DSLP-10 · P2 · Reject missing qualification revision instead of recording git errors

- **Area:** Qualification evidence
- **Where:** tests/common/qualify.rs:2271, tests/common/qualify.rs:2233, cli/tests/qualify.rs:2589
- **Problem:** A completed run in a container with an inaccessible Git worktree recorded crabtables_revision as 'fatal: not a git repository: ...' while summary.qualified was true. The revision command returns error text without checking its exit status, so an unidentifiable build can be reported as qualified despite the qualification contract requiring a revision.
- **Recommendation:** Require a valid revision or an explicit valid QUALIFY_REVISION override, fail qualification when it is unavailable, and add a regression proving a failed git lookup cannot produce qualified evidence.
- **Fix with:** error-model
- **Effort:** M

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
- **Problem:** The second OrbStack Linux 7.2.12 full-suite run failed owner_table_disappears_with_socket because the table remained after its socket closed. The first candidate and admission full runs passed; ten isolated admission runs passed. Pre-existence and cause remain unproven.
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

