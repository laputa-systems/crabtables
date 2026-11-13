Prefix: CRAB
Next: 9
### CRAB-1 · P1 · Query commands split one input file into independently committed updates

- **Area:** CLI atomicity
- **Where:** `cli/src/main.rs:583`, `cli/src/main.rs:628`, `src/lang/compile.rs:883`, `tests/errors.rs:17`
- **Problem:** The CLI commits pending mutations before each query and starts a fresh batch afterward. In a namespace with an installed firewall, a file containing `flush ruleset; list ruleset; add table ip probe; add chain ip probe bad { type nat hook forward priority 0; }` passes the compiler's hook/type checks, commits the flush, then fails the final batch because NAT does not support the forward hook. The old firewall remains removed. Source trace reaches the kernel's hook-mask rejection in [Linux v6.12](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_tables_api.c#L2345); runtime reproduction is unproven in this review environment.
- **Recommendation:** Keep all mutations from one input in one kernel transaction. Define query output against the evaluated ruleset, or reject a mixed input before any mutation if its query cannot be supported atomically. Add an nft/nfcrt differential case with a restrictive initial ruleset and a kernel-invalid final command separated by list, asserting failure preserves the original ruleset and packet policy. Cover stdin, file includes, JSON, and successful mixed inputs through the same boundary.
- **Fix with:** error-model
- **Effort:** M


### CRAB-8 · P2 · Some concatenation components compile to different element data than nft

- **Area:** Language compiler
- **Where:** `src/lang/compile.rs` (`RuleC::load`, `Expr::Concat`), `tests/lang_compile.rs`
- **Problem:** Probing CRAB-2 against `nft --debug=netlink` found concat components whose bytecode or set element data differ from nft: `udp dport << 1` gets no byteorder conversion and the element value 160 where nft stores 0xa000; integer-typed extension-header components (`ip option ra value`, `tcp option maxseg size`) get wrong element data; `jhash` as a component gets a different register layout. A set or map keyed this way can miss entries nft would match. These are compiler observations; packet behavior was not checked.
- **Recommendation:** Add each shape to the nft bytecode differential in `tests/lang_compile.rs`, fix the encoding to match nft, and add a packet case for the shift and exthdr keys with a drop entry and accepting fallback.
- **Fix with:** reference-parity
- **Effort:** M


### CRAB-4 · P2 · Commit recovery confuses lost responses with a known transaction outcome

- **Area:** Transaction outcome reporting
- **Where:** `src/batch.rs:685`, `src/batch.rs:770`, `src/batch.rs:912`, `src/socket.rs:267`, `src/socket.rs:290`, `src/asynchronous.rs:134`, `src/error.rs:135`
- **Problem:** With lost responses and no retained error, BatchResponse treats any generation change as proof that this batch committed. GETGEN reports the namespace-wide generation, so a different writer can advance it while this batch is rejected and its error is lost. The existing lost_responses test asserts success for that indistinguishable sequence. Post-send receive, decode, and sentinel errors also escape as ordinary errors even though changes may already be applied. The kernel generation scope and source paths were checked; transport-fault reproduction is unproven here.
- **Recommendation:** Return an explicit unknown outcome whenever the available responses cannot establish this batch's result, preserving the transport cause. Do not infer authorship from a generation delta or promise rollback after a post-send failure. Extend collector and sync/async boundary tests with a rejected batch plus another writer's commit, lost errors/echoes, truncated replies, and a failed sentinel; prove callers cannot mistake unknown for confirmed success or safe-to-retry rejection.
- **Fix with:** error-model
- **Effort:** M


### CRAB-7 · P2 · Qualify packet behavior and failed updates against nft before primary firewall use

- **Area:** Firewall compatibility
- **Where:** `tests/lang_compile.rs:18`, `cli/tests/compat.rs:27`, `tests/conntrack.rs:427`, `tests/forward.rs:172`, `tests/errors.rs:17`, `tests/errors.rs:145`
- **Problem:** Existing differential tests compare bytecode, listings, JSON, exit status, and diagnostics. Separate typed-API tests exercise real NAT/conntrack traffic and rejection rollback, but do not run the same stateful packet scenarios through nft and crabtables. They therefore do not establish equivalent NAT mappings, reply behavior, compound-expression verdicts, existing-flow behavior across replacement, or complete CLI rollback under the owner's primary-firewall requirement. This is a verified coverage gap, not a claim that all existing behavior tests are missing.
- **Recommendation:** Implement the linked qualification design with paired isolated topologies, a declared kernel/nft deployment matrix, independent packet and conntrack observations, generated boundary cases, and explicit success/rejection/unknown transaction outcomes. Retain the current bytecode and rollback tests. Require every applicable matrix row to execute and produce reviewable evidence before qualifying a deployment profile.
- **Fix with:** test-audit
- **Effort:** L
- **Design:** [Draft RFC](docs/rfc/CRAB-7-nft-differential-qualification.md)


### CRAB-6 · P3 · Replacing a concatenated set key leaves its concatenation flag set

- **Area:** Set metadata
- **Where:** `src/builder.rs:1154`, `src/objects.rs:748`, `src/objects.rs:755`, `tests/builder.rs:303`
- **Problem:** Calling Set::keyed with two fields and then with_key with one field updates the key type/length and clears field_lens, but leaves NFT_SET_CONCAT set. Encoding sends the flag without a concatenation descriptor. [Linux v6.12 validation](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_tables_api.c#L5203) rejects that combination. This breaks a valid public builder sequence and rejects its containing batch; no current caller or runtime reproduction was established.
- **Recommendation:** Recompute the concatenation flag when replacing a key while preserving unrelated flags. Check multi-field to single-field and single-field to multi-field transitions through set creation, including a non-concat flag that must survive.
- **Fix with:** make-invalid-states-unrepresentable
- **Effort:** S

