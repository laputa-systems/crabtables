Prefix: DSLP
Next: 10

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier E). One agent works this file with the `deslop` skill: take the lowest-numbered open ticket whose area does not start with `Needs owner ·`. After DSLP-5, work the open P1 and P2 findings, then fill in `## Report` below.

## Report

Ground: OrbStack Linux 7.2.12 aarch64's no-fail-fast suite reports 237 passed and the same 16 failures as admission revision 76765cf (102.25s warm). Failures include lost responses (DSLP-6), unavailable nft dup/fwd operations (DSLP-7), and a monitor mismatch (DSLP-8). A retry added an owned-table teardown failure (DSLP-9); ten isolated admission runs passed. Parent disposition: these 16 failures are host-kernel limitations; hosted CI is authoritative and the parent will check the PR's kernel job. Linux `make lint` passed in 5.27s. Diagnose, Types, Tests, Dead code, Bench, findings, and the final review have not been run.

## Tickets

### DSLP-2 · P2 · Diagnose: ultrareview into this backlog

- **Area:** deslop · diagnose
- **Where:** whole repository (our changes against upstream)
- **Problem:** No review has ranked this repository's risks for the deslop pass.
- **Recommendation:** Run the deslop Diagnose step. Accept: the diff touches only docs, comments, and this file, and every finding names its Fix with.
- **Fix with:** deslop
- **Effort:** M

### DSLP-3 · P2 · Types: strict profile and typing findings

- **Area:** deslop · types
- **Where:** type checker and lint configuration; Rust/Python sources
- **Problem:** The strict-profile candidates in the deslop skill's tools reference have not been measured here.
- **Recommendation:** Run the deslop Types step. Accept: clean at the adopted profile, escape hatches not increased, witnesses recorded.
- **Fix with:** deslop
- **Effort:** M

### DSLP-4 · P2 · Tests: coverage, boundary gaps, mutation

- **Area:** deslop · tests
- **Where:** test suites and CI
- **Problem:** Coverage and mutation results are unmeasured; no deslop mutation lane exists.
- **Recommendation:** Run the deslop Tests step. Accept: no undispositioned survivor in critical code, the test cost budget holds, and the lane is green where the tools are mirrored.
- **Fix with:** deslop
- **Effort:** L

### DSLP-5 · P2 · Dead code: tools and debloat

- **Area:** deslop · dead code
- **Where:** whole repository (our changes)
- **Problem:** No dead-code scan has run.
- **Recommendation:** Run the deslop Dead code step. Accept: tools clean or allowlisted with reasons; walk-backs filed as Needs owner tickets.
- **Fix with:** deslop
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

