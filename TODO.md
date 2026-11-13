Prefix: CRAB
Next: 8
### CRAB-2 · P1 · Nested protocol expressions overwrite earlier concatenated key components

- **Area:** Language compiler
- **Where:** `src/lang/compile.rs:1494`, `src/lang/compile.rs:2777`, `src/lang/compile.rs:2825`, `src/lang/compile.rs:3030`, `src/lang/compile.rs:3441`, `src/lang/parse.rs:2871`
- **Problem:** The concatenation dependency prepass visits only direct Payload children. For `ip saddr . tcp dport and 255 vmap { 1.2.3.4 . 80 : drop }` in an IPv4 chain, the address is loaded into R1 before the nested Binop loads tcp dport. That load emits its l4proto dependency into R1, overwriting the address before the lookup. The drop entry is missed, so an accepting fallback can allow traffic the rule intended to block. The parser accepts this operand shape and merge_payload_cmps does not repair the overwrite. This is a source trace; compilation and packet reproduction remain unproven here.
- **Recommendation:** Collect dependencies recursively before loading any concatenation component, or allocate dependency scratch registers outside live key registers. Add a compiler differential and a paired packet case for this exact key with a drop entry and accepting fallback, plus positive and negative address/port controls. Cover nested bit operations and other supported nested expressions while retaining the direct-payload prepass behavior.
- **Fix with:** make-invalid-states-unrepresentable
- **Effort:** M


### CRAB-3 · P1 · Host-order range matches compare the wrong numeric interval

- **Area:** Typed rule builder
- **Where:** `src/builder.rs:223`, `src/builder.rs:371`, `src/builder.rs:519`, `src/builder.rs:601`
- **Problem:** match_range encodes host-order fields and bounds in native byte order without the conversion used by match_cmp. On a little-endian host, `.match_range(Field::Mark, 1u32, 256u32)` emits bounds 01 00 00 00 and 00 01 00 00. The kernel's [range evaluator](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nft_range.c#L23) compares byte strings, so this reversed interval cannot match even marks 1 and 256. A range-based drop or allow rule silently changes policy. The source and kernel comparison contract were checked; runtime reproduction is unproven here.
- **Recommendation:** Share ordered-value encoding with match_cmp: convert multibyte host-order registers and both bounds to network order, retaining the existing encoding for network-order fields. Compare the typed API against nft for mark and conntrack host-order ranges crossing byte boundaries, including both endpoints and adjacent misses, and assert actual packet verdicts.
- **Fix with:** single-source-of-truth
- **Effort:** S


### CRAB-4 · P2 · Commit recovery confuses lost responses with a known transaction outcome

- **Area:** Transaction outcome reporting
- **Where:** `src/batch.rs:685`, `src/batch.rs:770`, `src/batch.rs:912`, `src/socket.rs:267`, `src/socket.rs:290`, `src/asynchronous.rs:134`, `src/error.rs:135`
- **Problem:** With lost responses and no retained error, BatchResponse treats any generation change as proof that this batch committed. GETGEN reports the namespace-wide generation, so a different writer can advance it while this batch is rejected and its error is lost. The existing lost_responses test asserts success for that indistinguishable sequence. Post-send receive, decode, and sentinel errors also escape as ordinary errors even though changes may already be applied. The kernel generation scope and source paths were checked; transport-fault reproduction is unproven here.
- **Recommendation:** Return an explicit unknown outcome whenever the available responses cannot establish this batch's result, preserving the transport cause. Do not infer authorship from a generation delta or promise rollback after a post-send failure. Extend collector and sync/async boundary tests with a rejected batch plus another writer's commit, lost errors/echoes, truncated replies, and a failed sentinel; prove callers cannot mistake unknown for confirmed success or safe-to-retry rejection.
- **Fix with:** error-model
- **Effort:** M


### CRAB-5 · P2 · A valid zero-length network prefix produces kernel-invalid expressions

- **Area:** Typed rule builder
- **Where:** `src/builder.rs:615`, `src/builder.rs:625`, `src/builder.rs:633`
- **Problem:** match_prefix with a valid IPv4 or IPv6 /0 enters the byte-aligned path with n=0, emitting a zero-length payload load and empty comparison data. Linux v6.12 rejects zero-length register stores and values in [nf_tables_api.c](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_tables_api.c#L11158). A generated catch-all prefix therefore rejects the whole update instead of matching all addresses of that family. This source trace was checked against kernel validation; runtime reproduction is unproven here.
- **Recommendation:** Handle /0 as an unconditional address match while retaining the field's family or protocol dependency, especially in inet/bridge/netdev chains. Compare typed IPv4 and IPv6 /0 rules against nft with matching and opposite-family traffic, and retain /1 and full-width boundary checks.
- **Fix with:** make-invalid-states-unrepresentable
- **Effort:** S


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

