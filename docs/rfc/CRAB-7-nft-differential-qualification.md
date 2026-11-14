# CRAB-7: Qualify firewall behavior against nft

Status: draft

## Summary

Qualify each supported deployment profile by running equivalent policies and traffic through `nft`, `nfcrt`, and the typed crabtables API. Compare observable packet decisions, NAT mappings, conntrack state, and failed updates. Primary-firewall qualification requires executed evidence for the selected profile and resolution of unexplained differences.

This RFC specifies work to implement. It does not certify the current code or claim that the proposed tests have run.

## Motivation

The existing tests provide useful, distinct kinds of evidence:

| Existing boundary | Evidence already asserted | Remaining question |
| --- | --- | --- |
| [Language compiler](../../tests/lang_compile.rs) | nft and crabtables installations produce matching bytecode, listings, and set data | Do equivalent packets and state transitions behave alike? |
| [CLI compatibility](../../cli/tests/compat.rs) and [JSON](../../tests/lang_json.rs) | Exit status, diagnostics, listing formats, and round trips | Does a complete input preserve the same transaction boundary and packet policy? |
| [Conntrack](../../tests/conntrack.rs), [forwarding](../../tests/forward.rs), and [traffic](../../tests/traffic.rs) | Real traffic exercises the typed API, including NAT and conntrack | Does an nft-installed control produce the same behavior for the same scenario? |
| [Batch errors](../../tests/errors.rs) | Kernel rejection leaves the ruleset unchanged, including a split element update | What happens across CLI queries, concurrent writers, response loss, and packets arriving during replacement? |

Keep these tests. Extend their reusable topology and comparison helpers instead of replacing behavioral evidence with a larger collection of snapshots.

The review in [TODO.md](../../TODO.md) identifies specific counterexamples for the new suite. They are source-traced candidates with runtime reproduction still outstanding. A conformance suite must catch those cases before its passing result is used to justify deployment.

## Design

### Declare the profile

Record the crabtables revision and build features, architecture and byte order, kernel release and relevant configuration/modules, nft version, and binary identities. Record capabilities, namespace support, address families, hooks, routing topology, and features the deployment actually uses. Treat unsupported required features as a failed qualification, with a reason. A skipped test is not a passing matrix row.

Qualify each selected kernel/nft pair separately. Historical benchmark versions are context, not an implicit support promise. Offload and bridge behavior need their own profile when used.

### Build two independent worlds

For each scenario, build equivalent disposable client/router/server network namespaces, routes, interfaces, and initial connection state. Install the reference policy with `nft`. Install the candidate separately through `nfcrt` text, JSON where supported, or the typed API. Run the same stimulus sequence on both sides. Compare each candidate frontend to the reference rather than treating agreement between candidate frontends as proof.

Namespace creation and isolation checks must succeed before any firewall command runs. Keep all mutations inside those namespaces. Own child processes and sockets through cleanup on success and failure. Use readiness signals and bounded deadlines rather than sleeps or retries that can hide an initial mismatch.

Fixtures own policy intent, literal boundary values, traffic, and expected observations. The generator must not compute expected verdicts with the compiler under test. Retain existing bytecode comparisons as a complementary way to localize a behavioral difference.

### Required behavioral matrix

Run every applicable row for IPv4 and IPv6, through the families and hooks named in the profile. Each matching packet needs a nearby nonmatching control, and each deny case needs a positive control proving the topology works.

| Area | Scenarios | Required observations |
| --- | --- | --- |
| NAT | DNAT, SNAT, masquerade, local redirect; address/port ranges and maps; TCP and UDP; forward and reply directions | Delivery and replies, receiver-observed addresses/ports, original and reply conntrack tuples, NAT status, and relevant counter deltas |
| Stateful replacement | Establish a connection, replace or reject its NAT/filter policy, then send on the old connection and create a new one | Existing and new flows follow the reference behavior; compare old mapping retention and the new mapping separately |
| Conntrack | NEW/ESTABLISHED, RELATED and INVALID stimuli; original/reply selectors; marks and zones; NOTRACK where supported | Packet decisions and observable states/tuples agree; zone separation and mark propagation have positive and negative controls |
| Expressions | Nested bit operations in concatenations, interval and verdict maps, named and anonymous sets, prefixes including /0 and full width, ordered host-order values crossing byte boundaries, jump/goto/return and rule ordering | Literal boundary packets hit the intended rule or miss it; counters and verdicts expose a changed key, byte order, dependency, or control flow |
| Successful updates | Mixed table/chain/rule/set changes and large element lists, including replacement while traffic continues | Final state matches the reference; tagged probes observe outcomes allowed by a complete old or new policy, without a transient policy gap |
| Rejected updates | Valid operations followed by a kernel-invalid operation at the beginning, middle, and end; a failure after element-message splitting | Nonzero result, unchanged structural ruleset, unchanged effective packet policy, and preservation of preexisting state except normal traffic/time effects |
| CLI boundaries | A single file, stdin, includes, and supported JSON containing mutations and intervening list/get/describe commands; check mode | The mutation unit and failure behavior match the reference; a failed replacement cannot leave its flush committed; a dry run does not install its proposed rules |

Use the source-traced mixed-file failure as an initial regression candidate in a namespace with a restrictive policy:

```nft
flush ruleset
list ruleset
add table ip probe
add chain ip probe bad { type nat hook forward priority 0; }
```

The compiler currently accepts that chain declaration, but the [Linux NAT hook mask](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nft_chain_nat.c#L41) excludes forward. Verify that both frontends fail without losing the original policy. Also exercise a valid replacement and an early parser failure so the oracle distinguishes compilation, kernel rejection, and commit.

Do not require a ruleset rollback to rewind connection tracking, packet counters, or time. Establish the expected behavior with the reference and compare configuration separately from stateful traffic effects. For atomic replacement, include a canary flow denied by both complete policies; any delivery exposes a permissive intermediate state.

### Transaction outcomes and faults

Treat configuration atomicity and knowledge of the outcome as separate contracts:

| Observation | Allowed conclusion |
| --- | --- |
| Failure before submission | No change from this operation |
| Confirmed kernel rejection | This transaction did not apply |
| Confirmed commit | This transaction applied; report any missing echoes separately |
| Replies lost, truncated, undecodable, or unavailable after submission | Outcome remains unknown unless transaction-specific evidence resolves it |

Use the public sans-IO boundary to replay actual response streams with selected errors, echoes, or the sentinel removed. Pair fault cases with observed kernel state. Exercise the blocking and async socket error paths as well as the collector. Include another writer committing between the generation observations while the candidate transaction fails. A namespace-wide generation change alone cannot identify which transaction committed.

The caller must distinguish unknown outcomes from safe-to-retry rejection. A timeout or cancellation after submission does not imply rollback. Validate diagnosis and recovery against a fresh ruleset observation without automatically replaying a possibly committed, non-idempotent update.

### Oracles, generation, and evidence

Compare install status, raw diagnostics, canonical structural rulesets, correlated packet delivery/replies, counter deltas, and conntrack tuples/state. Keep raw observations alongside normalized ones. Normalize only a documented source of nondeterminism, such as handles, timestamps, or independently allocated NAT ports. For allocation, compare the permitted range, endpoint identity, stable mapping, and reply translation rather than erasing the mapping.

Use deterministic scenarios for state transitions and seeded generation for expression combinations, interval boundaries, and mutation sequences. Record the generated-case budget before running it. Bias cases toward different numeric byte orders, nested protocol dependencies, overlapping intervals, empty and maximum values, and errors after earlier valid operations. Shrink a divergence to its policy, initial state, and stimulus sequence, then retain it as a regression fixture.

A qualification result records the profile, commands, case inventory, seeds, execution/skips/failures, raw and normalized rulesets, packet observations, conntrack snapshots, and minimized divergences. Do not turn a passing retry into a passing case. Demonstrate that the harness detects plausible faults such as a dropped NAT statement, an overwritten concatenation register, and a split transaction before trusting it as a gate.

The existing baseline commands remain `python3 scripts/check-constants.py` and, on a capable isolated Linux test host, `sudo cargo test --workspace --all-features`. They do not execute the proposed qualification matrix until that work is implemented. The review environment checked 716 UAPI constants successfully, but lacked Rust and nft and denied network namespace creation.

Qualification passes only when all required rows execute, the declared generated-case budget has no unexplained divergence, failures leave the expected policy intact, and every reported outcome is justified. Keep a deployment profile unqualified while any of those conditions is unmet.

## Alternatives considered

- **Bytecode/listing comparison alone:** retain it for precision and diagnosis. It does not independently observe packet decisions or connection lifetimes.
- **Only separate typed-API traffic tests:** retain them as regressions. Add a paired reference to test frontend equivalence under the same state transitions.
- **Immediately test every kernel and feature:** start with the deployment profile and a declared compatibility floor. Expand profiles as support is claimed, keeping unsupported combinations explicit.

## Open questions

Both questions are decided in the Decision section.

1. **Which kernel/nft pairs and architectures must be supported?** Options are the exact production stack or a broader supported range. Recommend the production stack plus the oldest pair the project intends to support, recording exact versions and byte order. The earlier 6.12/1.1.3 measurements are not a substitute for that choice.
2. **Which deployment features belong in the first qualification?** Recommend local and routed IPv4/IPv6 NAT and filtering through ip/ip6/inet. Add bridge, netdev, offload, NFQUEUE, or other extensions when they are part of the intended deployment; otherwise leave them outside the initial qualification claim.

## Decision

Owner decisions on the open questions:

1. **First profile:** the kernel of the host running the pinned test image (`crabtables-test:local`) with the nft 1.1.x that Debian trixie packages in that image. The suite records the exact kernel release, nft and conntrack versions, binary hashes, architecture, byte order, and loaded netfilter modules at run time in its evidence file; no other kernel/nft pair is claimed.
2. **First scope:** local and routed IPv4 and IPv6 filtering and NAT through the `ip`, `ip6`, and `inet` families (prerouting, input, forward, output, postrouting). Bridge, netdev, flowtable offload, and NFQUEUE are outside this profile. The conntrack row (RELATED and INVALID stimuli, zones, marks, NOTRACK) is inside it.

Acceptance of this design does not establish primary-firewall readiness.

### Implemented

`cli/tests/qualify.rs` (fixtures) and `tests/common/qualify.rs` (harness) implement the paired suite. It lives in the `nfcrt` package so it can run the `nfcrt` binary. Each scenario builds one disposable client/router/server world per frontend (`nft`, `nfcrt`, and the typed API where the scenario has a typed policy), verifies that the namespaces are distinct from each other and from the host and start with an empty ruleset, installs the policy through that frontend, and drives the same stimuli. It compares delivery and replies, receiver-observed addresses and ports, rule counter deltas, conntrack tuples and state, and the structural `nft list ruleset` listing against the `nft` world. The `nft` world must also meet the expectations written in the fixture, so a broken topology or fixture fails instead of passing by agreement. Probes use explicit source ports, readiness is established before any stimulus, and every wait has a bound; absence of delivery is shown with a short deadline or with a fence datagram that is sent after the data and reported only after every other socket is empty.

Rows executed for IPv4 and IPv6, each with positive and negative controls:

| Row | Cases |
| --- | --- |
| Expressions | nested-bitop concatenation vmap keys (TCP and masked UDP address and port), interval and verdict maps with jump, goto and return counters, `/0` and full-width prefixes and an interval set, host-order mark ranges crossing byte boundaries plus a seeded generated set |
| NAT | DNAT, SNAT, SNAT port range, masquerade, local redirect, over TCP and UDP, reply direction, original and reply conntrack tuples, rule counter deltas; DNAT and masquerade also through the typed API |
| Stateful replacement | an established NATed flow across an atomic `flush ruleset` replacement, a new flow, direct flows the policies decide differently, and a canary flow denied by both policies |
| Rejected updates | a kernel-invalid operation first, in the middle, last, and after a 20000-element split, through `nft -f`, `nfcrt -f`, and the typed API, with the held flow and probes before and after |
| CLI boundaries | file, stdin, `include`, JSON (with and without an intervening `list`), parse error, valid replacement, and `-c` check mode that must install nothing; `-j get element` (interval member, point, miss, missing set, map) and `-j describe` output; JSON input containing `get` or `describe`, which both frontends must reject without changing the policy; `get` inside a replacement file, which must fail and apply nothing |
| Conntrack | `ct.states_related_invalid`: NEW and ESTABLISHED UDP and ICMP echo, RELATED (the ICMP port-unreachable of a tracked UDP flow, accepted by one policy and dropped by the next) and INVALID (an unsolicited echo reply), with `ct direction` and per-state counters; `ct.selectors`: `ct original daddr`/`proto-dst` and `ct reply saddr`/`proto-src` on a DNATed flow, over TCP and UDP, with a direct flow and a different original port as negative controls; `ct.mark_propagation_forward`: `meta mark` to `ct mark` to `meta mark` on forwarded flows, `ct mark` set from a constant and from a masked expression, masked match, and near-miss controls; `ct.mark_propagation_local`: `SO_MARK` to `ct mark` and back through the input hook, over TCP and UDP, with other and absent marks as controls; `ct.zones`: `ct zone set` and `ct zone` match, two flows with the same tuple in zones 1 and 2, and a reply assigned to a different zone than its request; `ct.notrack`: `notrack` for both directions, for the request only, and no rule, with a tracked control (also through the typed API). Conntrack tuples (including `zone=` and `mark=`) and the absence of untracked entries are compared against `nft` |
| Successful updates | `update.mixed_replace`: `flush ruleset` plus a map with 4000 verdict elements and a new table with a 3000-element set, replacing a policy with a 2000-element set and a second table; `update.mixed_inplace`: `flush set`/`add element` with 4000 elements, `flush chain` and new rules, `delete table`, and a new table with a 3000-element set, in one file without `flush ruleset`. Tagged probes (see below) flow throughout |

The generated-case budget, recorded in the evidence under `seeds` and `generated_budget`, is 40 seeded mark ranges (seed `0xc4ab70`) in addition to four fixed byte-boundary ranges, 40 seeded prefix rules plus a seeded interval set (seed `0xc4ab71`; lengths biased to 8-, 16-, 32- and 64-bit boundaries and the bit just inside the prefix flipped to produce near misses), and 14 seeded concatenation vmap rules with random address prefix masks and random port masks (seed `0xc4ab72`), each probed from four sources at the key, one bit off inside the mask, one bit off outside it, and the neighbouring ports. Expected verdicts come from plain integer arithmetic in the fixture, never from the compiler under test. Bursts send in chunks of 16 datagrams with a pause between them: unpaced bursts of several hundred datagrams were occasionally lost between the namespaces, and the loss was indistinguishable from a policy difference.

For the update row the sender thread in the client namespace sends one datagram per class every 150 microseconds, each tagged with its class and round number: a class allowed by both policies, by the old policy only, by the new policy only, and by neither. After the update the receiver classifies every round. A round is consistent when its deliveries equal the complete old policy's outcome or the complete new policy's outcome for every class; the run passes when at most 32 rounds match neither or revert to the old outcome after the new one was seen (the same budget as the canary oracle: one round can straddle the switch, and the reference leaks a few packets as it swaps base chains), and at least 100 rounds of each outcome were observed. Controls sent before and after the update through bursts check the final policy, and the listings are compared. A transient gap (for example `flush ruleset` committed before the new tables) makes hundreds of rounds inconsistent.

Run it with `cargo test -p nfcrt --all-features --test qualify` as root (the pinned image runs it with `--privileged`). It writes `.work/qualify-evidence.json` (override with `QUALIFY_EVIDENCE`): profile, seeds, generated-case budget, case inventory, executed/passed/failed/known-divergence/intentional/skipped counts, unmet required rows, the intentional differences with their justifications, the known divergences, and per case the raw reference observations and any divergence. `QUALIFY_FAULT=drop-nat|unmask-concat|split-replace|drop-ct` applies a fault to the candidate policy for a manual run (`drop-ct` removes `ct mark set`, `ct zone set` and `notrack` statements), and the `harness_detects_faults` test asserts that each is detected, including a non-atomic replacement of the mixed update.

Every case ends in exactly one status, and the rule for each is part of the contract:

| Status | Meaning | Effect on `qualified` |
| --- | --- | --- |
| `passed` | every frontend matches the reference and the fixture's expectations | counts toward the row |
| `intentional` | the case marks a difference as a deliberate design decision (`Marker::Intentional`) and the difference reproduces | does not block; reported separately as `intentional_differences` |
| `known_divergence` | the case marks an unresolved difference (`Marker::Known`) and the difference reproduces | blocks |
| `failed` | an unmarked difference, a failed expectation of the reference world, a harness error, a marked case that no longer differs, or an `intentional` marker without a justification | blocks, and fails the test |
| `skipped` | excluded by `QUALIFY_FILTER` | blocks, and fails the test unless a filter was given |

An intentional difference must carry a written justification (at least 60 characters) saying why reproducing the reference would be wrong and what still agrees (status, transaction outcome, packet policy). A case with an empty or short justification fails. A marker that no longer reproduces fails in both cases, so a resolved difference cannot hide behind its marker. Only the owner of the design may classify a difference as intentional; a difference nobody has decided on is a known divergence. `qualified` is true only for a complete run (no filter, no fault) in which every case of every required row is `passed` or `intentional`. `QUALIFY_STRICT=1` makes the test fail when the profile is not qualified.

Transaction-outcome faults (replies lost, truncated or undecodable; another writer; blocking and asynchronous socket errors) remain covered at the library level by the CRAB-4 tests in `src/batch.rs`, `src/socket.rs`, and `src/asynchronous.rs`; the suite does not duplicate them.

### Findings

Reference behavior the suite had to accommodate, recorded in the evidence:

- `nft -j -f` of a JSON file containing a `list` command terminates with signal 11 in nft 1.1.3. `cli.reject_json_with_list` therefore judges `nfcrt` against the fixture (non-zero status, unchanged ruleset and packet policy) and records the crash as a note.
- Replacing a base-chain ruleset with `nft -f` (`flush ruleset` plus new tables) lets a few packets (0 to 3 of several thousand) of a flow both policies deny through while the hooks are swapped, on this kernel. The canary oracle therefore allows a budget of 32 packets; the injected non-atomic replacement leaks thousands.
- Rejection diagnostics differ in text when the kernel refuses an operation (for example a `nat` chain on the forward hook) and nft words the error itself while `nfcrt` reports the kernel error. The suite compares the exit status and the presence of an `Error:` diagnostic, and keeps both texts raw.

The suite found these differences. D3 is intentional. D5 to D9 were real differences between `nfcrt` and `nft` that no design decision covered; each was kept as a minimized, marked fixture (the case ran, had to still diverge, and was reported `known_divergence`) until it was fixed, and each fixture is now an ordinary case that must match `nft`.

| Id | Case | Status | Difference |
| --- | --- | --- | --- |
| CRAB-7-D3 | `cli.list_stdout_in_replacement.{v4,v6}` | intentional | a `list ruleset` that precedes later definitions in a replacement file prints a different listing |
| CRAB-7-D5 | `cli.json_get_map_element.{v4,v6}` | resolved | `get element` on a map: `nft` prints the map with the element and its data; `nfcrt` failed with `map elements need data`. The query names the key only; the kernel returns the data, and a map prints one element per line |
| CRAB-7-D6 | `cli.json_describe_unknown_symbol.{v4,v6}` | resolved | `describe nosuchthing`: `nft` exits 0 and prints `symbol expression, datatype invalid (invalid)`; `nfcrt` reported a syntax error. A word that is no keyword is a symbol; a number or address followed by `-` or `/` is still a syntax error, as in `nft` |
| CRAB-7-D7 | `cli.get_inside_replacement.{v4,v6}` | resolved | `add element` then `get element` of that element in one file: `nft` fails the `get` against the kernel's ruleset before the input and sends nothing; `nfcrt` queried after the commit and installed the file. `get element` and `reset element` now run before the transaction, against the ruleset as it is (so an element the input deletes is still found, and one it adds or a set it creates is not); a failed query stops the input unapplied, and their output is kept and printed in command order |
| CRAB-7-D8 | `cli.reject_keyword_chain_name.{v4,v6}` | resolved | `add chain ip kw fwd`: `nft` rejects the keyword `fwd` as a bare chain name; `nfcrt` accepted it and created the chain. Every name of a table, chain, set, map, object or flowtable (and the target of `jump` and `goto`) rejects the keywords, numbers and quoted strings that `nft` 1.1.3 does |
| CRAB-7-D9 | `expr.concat_full_width_mask.{v4,v6}` | resolved | `saddr and <all-ones> . udp dport and 0xfff0 vmap {...}`: packet decisions agreed, but `nft` drops the no-op address mask from its listing where `nfcrt` listed `saddr & <full mask>`; the bytecode was already the same. A mask that keeps every bit is no longer listed |

D3 justification: `nft` runs `list` after it has evaluated the whole file and before it sends the batch. It prints its local cache, which holds the kernel state at the start of the run with some commands already applied: `flush ruleset` and `delete table` remove entries, and `add table`, `add chain` and `add set` (with the elements written in the definition) of objects that do not yet exist add them. Rules, `add element` into an existing set, `flush chain`, and attribute changes to an existing chain (a new policy) are not applied. The fixture therefore shows the new table and chain without their rules. `nfcrt` runs queries after the commit, so that a query between mutations reports the state those mutations produced; it prints the rules of the new table. Matching `nft` would mean reproducing its cache model for every command, a state that exists in neither the old nor the new kernel ruleset, so the difference is intentional. Status, transaction outcome, and packet policy agree. Element queries are not covered by that decision because they change whether the file is applied: `get element` and `reset element` follow `nft` (D7).

Reference behavior for the new rows: `nft -j get element` and `nft -j describe` print the plain-text output in nft 1.1.3, so the JSON-mode rows compare that text; `get` and `describe` are not JSON input commands (both frontends reject the file with an `Error:` diagnostic and leave the policy unchanged).

The four divergences first recorded here are otherwise resolved: D1 (`dnat to ip daddr . tcp dport map { ... : addr . port }` is now compiled to nft's bytecode, with the port taken from the map data), D2 (a range with equal bounds is evaluated to its value, as `nft` does, which also changes the bytecode from `range eq lo lo` to `cmp eq lo`), and the earlier D4 (IPv6 NAT addresses followed by a port are listed in brackets, per bound of a range, and `tproxy` brackets every IPv6 address).

### Not yet covered

Execution on the production kernel/nft pair, if it differs from the image's, is not covered; the evidence names the pair it ran on and no other is claimed. Bridge, netdev, flowtable offload and NFQUEUE remain outside the profile. Transaction-outcome faults stay at the library level (see above). With D5 to D9 resolved the image profile reports `qualified: true` (102 cases: 100 passed, 2 intentional); the production kernel/nft pair, if it differs, is the only run left. Keep this RFC until the accepted design is implemented, then move the enduring qualification contract to its owning documentation and delete the completed RFC.
