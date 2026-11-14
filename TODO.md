Prefix: CRAB
Next: 14
### CRAB-13 · P3 · Remaining diagnostic and accept/reject differences from nft in expression forms

- **Area:** Language parser and compiler
- **Where:** `src/lang/parse.rs`, `src/lang/compile.rs`, `src/lang/datatype.rs`
- **Problem:** Transport protocol conflicts, hyphenated names, `icmpv6` in `ip` tables, protocol number sets, NAT addresses taken from headers, and the `redirect`, `fwd` and `synproxy` diagnostics now follow nft 1.1.3. What was found on the way and is still different: a statement that names a missing object (`counter name x`, `quota`, `limit`, `synproxy`, `ct helper`, `ct timeout`, `ct expectation`, `meta secmark set`) fails in nfcrt at the kernel (`Could not process rule: No such file or directory`) where nft reports `No such file or directory; did you mean chain 'c' in table ip 't'?` at evaluation; an unknown name of a symbolic type (`ip dscp foo`, `ct state new-established`, `tcp flags foo`, `icmp type foo`, `meta nfproto ipv4-ipv6`) reports `Could not parse <type> value` where nft says `Could not parse <description> expression; did you you mean `x`?`; after a syntax error inside a `{ }` block nft reports a second error where its parser recovers (`add set ip t fwd { type ipv4_addr; }`) and nfcrt stops at the first; `dnat to 80-90:5` and `dnat to 80:5` are accepted where nft resolves `80-90` and `80` as host names and fails; `22- 80` and `{tcp -17}` parse in nft; `meta nfproto { 2, 5-10 }` is listed `{ ipv4, 5-ipv6 }`; a concatenated interval anonymous set carries a merge-elements user data entry that nft omits; `describe` of a keyword or of a header protocol without a field words its syntax error differently; `-a get element` prints `# handle` on the table.
- **Recommendation:** Fix each in the `cli/tests/compat.rs` nft differential, the object references first because they change when a bad rule is reported, not whether it is installed.
- **Fix with:** reference-parity
- **Effort:** M


### CRAB-7 · P2 · Qualify packet behavior and failed updates against nft before primary firewall use

- **Area:** Firewall compatibility
- **Where:** `cli/tests/qualify.rs`, `tests/common/qualify.rs`, `tests/lang_compile.rs:18`, `cli/tests/compat.rs:27`, `tests/conntrack.rs:427`, `tests/forward.rs:172`, `tests/errors.rs:17`, `tests/errors.rs:145`
- **Problem:** The paired suite runs the same policies and traffic through nft, nfcrt, and the typed API for local and routed IPv4/IPv6 filtering, NAT, conntrack (NEW/ESTABLISHED, RELATED, INVALID, original/reply selectors, ct mark and meta mark propagation, zones, NOTRACK), stateful and large mixed successful updates under tagged continuing traffic, rejected updates, and CLI boundaries including JSON `get`/`describe` (profile: the pinned image's kernel with its Debian trixie nft 1.1.x), with a seeded budget of 40 mark ranges, 40 prefixes plus an interval set, and 14 concatenation keys, and records an evidence file. It detects an injected dropped NAT statement, dropped ct/zone/notrack statements, an unmasked concatenation key, and non-atomic replacements. Every required row executes and the image profile is qualified: the evidence reports `qualified: true` (102 cases, 100 passed, 2 intentional, none failed, skipped or known). The five divergences recorded earlier are resolved and their fixtures are ordinary cases: D5 `get element` on a map, D6 `describe` of an unknown word, D7 `get` of an element added in the same file (nfcrt now runs element queries against the ruleset before the input, as nft, so the input fails and nothing is applied), D8 a keyword as a chain name, D9 a full-width mask in a concatenation key. CRAB-7-D3 (`list` inside a replacement file shows nft's pre-commit cache) is a deliberate design difference reported as `intentional` with its written justification and does not block. Remaining: execution on the production kernel/nft pair if it differs from the image's. Nft itself crashes on JSON input with `list` and leaks a few packets while swapping base chains, so those rows judge nfcrt against fixture expectations or a packet budget.
- **Recommendation:** Run the suite on the production kernel/nft pair and keep it qualified (`QUALIFY_STRICT=1` fails otherwise). Keep the CRAB-4 library-level transaction-outcome tests as the fault coverage. Delete the RFC once its contract moves to owning documentation.
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


### CRAB-10 · P3 · Remaining nft differences in shifted sets, ip option types and typeof

- **Area:** Language compiler
- **Where:** `src/lang/compile.rs` (`expr_comp`, `exthdr_typeof`, `Expr::Concat` loading)
- **Problem:** Found while fixing CRAB-8: a single-key shifted set (`udp dport << 1 { 160, 162 }`) keeps the shift in the rule where nft folds it into the constants; `ip option <name> type` fields get key type 263 (integer) where nft uses 2503; named sets reject `typeof tcp option maxseg size` ("unsupported typeof expression") which nft accepts; nft aborts on `jhash` in concats of eight or more words where crabtables has no matching limit; `jhash` inputs in concats whose width `static_words` cannot predict (rt, socket, fib components) keep the old `word+4` placement. Verdict impact of the first and last is unverified.
- **Recommendation:** Add each to the nft differential in `tests/lang_compile.rs`, match nft's bytecode and set metadata, and add a packet case for the shifted single-key set and a jhash concat with an unpredictable-width component.
- **Fix with:** reference-parity
- **Effort:** M


### CRAB-6 · P3 · Replacing a concatenated set key leaves its concatenation flag set

- **Area:** Set metadata
- **Where:** `src/builder.rs:1154`, `src/objects.rs:748`, `src/objects.rs:755`, `tests/builder.rs:303`
- **Problem:** Calling Set::keyed with two fields and then with_key with one field updates the key type/length and clears field_lens, but leaves NFT_SET_CONCAT set. Encoding sends the flag without a concatenation descriptor. [Linux v6.12 validation](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_tables_api.c#L5203) rejects that combination. This breaks a valid public builder sequence and rejects its containing batch; no current caller or runtime reproduction was established.
- **Recommendation:** Recompute the concatenation flag when replacing a key while preserving unrelated flags. Check multi-field to single-field and single-field to multi-field transitions through set creation, including a non-concat flag that must survive.
- **Fix with:** make-invalid-states-unrepresentable
- **Effort:** S

