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

1. **Which kernel/nft pairs and architectures must be supported?** Options are the exact production stack or a broader supported range. Recommend the production stack plus the oldest pair the project intends to support, recording exact versions and byte order. The earlier 6.12/1.1.3 measurements are not a substitute for that choice.
2. **Which deployment features belong in the first qualification?** Recommend local and routed IPv4/IPv6 NAT and filtering through ip/ip6/inet. Add bridge, netdev, offload, NFQUEUE, or other extensions when they are part of the intended deployment; otherwise leave them outside the initial qualification claim.

## Decision

Pending profile selection and implementation. Rigorous differential testing is already requested; the open decisions define its supported deployment scope. Acceptance of this design does not establish primary-firewall readiness. Keep this RFC until the accepted design is implemented, then move the enduring qualification contract to its owning documentation and delete the completed RFC.
