Prefix: CRAB
Next: 10
### CRAB-8 · P2 · Some concatenation components compile to different element data than nft

- **Area:** Language compiler
- **Where:** `src/lang/compile.rs` (`RuleC::load`, `Expr::Concat`), `tests/lang_compile.rs`
- **Problem:** Probing CRAB-2 against `nft --debug=netlink` found concat components whose bytecode or set element data differ from nft: `udp dport << 1` gets no byteorder conversion and the element value 160 where nft stores 0xa000; integer-typed extension-header components (`ip option ra value`, `tcp option maxseg size`) get wrong element data; `jhash` as a component gets a different register layout. A set or map keyed this way can miss entries nft would match. These are compiler observations; packet behavior was not checked.
- **Recommendation:** Add each shape to the nft bytecode differential in `tests/lang_compile.rs`, fix the encoding to match nft, and add a packet case for the shift and exthdr keys with a drop entry and accepting fallback.
- **Fix with:** reference-parity
- **Effort:** M


### CRAB-7 · P2 · Qualify packet behavior and failed updates against nft before primary firewall use

- **Area:** Firewall compatibility
- **Where:** `tests/lang_compile.rs:18`, `cli/tests/compat.rs:27`, `tests/conntrack.rs:427`, `tests/forward.rs:172`, `tests/errors.rs:17`, `tests/errors.rs:145`
- **Problem:** Existing differential tests compare bytecode, listings, JSON, exit status, and diagnostics. Separate typed-API tests exercise real NAT/conntrack traffic and rejection rollback, but do not run the same stateful packet scenarios through nft and crabtables. They therefore do not establish equivalent NAT mappings, reply behavior, compound-expression verdicts, existing-flow behavior across replacement, or complete CLI rollback under the owner's primary-firewall requirement. This is a verified coverage gap, not a claim that all existing behavior tests are missing.
- **Recommendation:** Implement the linked qualification design with paired isolated topologies, a declared kernel/nft deployment matrix, independent packet and conntrack observations, generated boundary cases, and explicit success/rejection/unknown transaction outcomes. Retain the current bytecode and rollback tests. Require every applicable matrix row to execute and produce reviewable evidence before qualifying a deployment profile.
- **Fix with:** test-audit
- **Effort:** L
- **Design:** [Draft RFC](docs/rfc/CRAB-7-nft-differential-qualification.md)


### CRAB-9 · P3 · monitor_trace fails intermittently on unmatched packet shapes

- **Area:** Test reliability
- **Where:** `cli/tests/compat.rs` (`monitor_trace`)
- **Problem:** The test tolerates extra nfcrt trace lines only when their shape matches a line nft printed. When nfcrt's run catches a packet kind nft's run missed (observed: a TCP RST to a closed port, with its `in`/`out` packet, policy and drop-rule lines), the test fails. It failed 2 of 3 runs at `289be0d`, before the CRAB-1..5 fixes, so the failure is in the test, not the trace decoder.
- **Recommendation:** Make the traffic deterministic for both runs (send the same fixed packet set after both monitors are ready, and wait for the expected count) instead of widening the shape tolerance; keep the nft equality check on every line.
- **Fix with:** root-cause
- **Effort:** S


### CRAB-6 · P3 · Replacing a concatenated set key leaves its concatenation flag set

- **Area:** Set metadata
- **Where:** `src/builder.rs:1154`, `src/objects.rs:748`, `src/objects.rs:755`, `tests/builder.rs:303`
- **Problem:** Calling Set::keyed with two fields and then with_key with one field updates the key type/length and clears field_lens, but leaves NFT_SET_CONCAT set. Encoding sends the flag without a concatenation descriptor. [Linux v6.12 validation](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_tables_api.c#L5203) rejects that combination. This breaks a valid public builder sequence and rejects its containing batch; no current caller or runtime reproduction was established.
- **Recommendation:** Recompute the concatenation flag when replacing a key while preserving unrelated flags. Check multi-field to single-field and single-field to multi-field transitions through set creation, including a non-concat flag that must survive.
- **Fix with:** make-invalid-states-unrepresentable
- **Effort:** S

