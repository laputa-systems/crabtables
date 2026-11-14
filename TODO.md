Prefix: CRAB
Next: 13
### CRAB-12 · P2 · The parser silently accepts or drops NAT and expression forms nft rejects

- **Area:** Language parser and compiler
- **Where:** `src/lang/parse.rs`, `src/lang/compile.rs`
- **Problem:** Found while fixing CRAB-11, each checked against nft 1.1.3: `redirect to 1.2.3.4:80` silently drops the address (nft: syntax error); `dnat to ip saddr map { ... : 1.2.3.4 . 80 }` is accepted (nft rejects it); in `inet`, `tproxy to :80` after an `ip saddr` or `meta nfproto ipv4` match is accepted where nft reports conflicting protocols; `meta nfproto` in an `ip` table is accepted; the "Statement after terminal statement" check is missing; `tcp option mss`, `tcp dport 1 | 2`, `:tcp dport` as a NAT port and `meta l4proto { tcp - udp }` do not parse; `tproxy ip to [::1]:80` reports a different error. Silently dropping part of a statement installs a different policy than written.
- **Recommendation:** Reject the silently-dropped and over-accepted forms with nft's diagnostics first (they change policy), then add the missing syntax; cover each in the `cli/tests/compat.rs` nft differential.
- **Fix with:** reference-parity
- **Effort:** M


### CRAB-7 · P2 · Qualify packet behavior and failed updates against nft before primary firewall use

- **Area:** Firewall compatibility
- **Where:** `cli/tests/qualify.rs`, `tests/common/qualify.rs`, `tests/lang_compile.rs:18`, `cli/tests/compat.rs:27`, `tests/conntrack.rs:427`, `tests/forward.rs:172`, `tests/errors.rs:17`, `tests/errors.rs:145`
- **Problem:** The paired suite now runs the same policies and traffic through nft, nfcrt, and the typed API for local and routed IPv4/IPv6 filtering and NAT (profile: the pinned image's kernel with its Debian trixie nft 1.1.x) and records an evidence file. It covers expressions, NAT, stateful replacement, rejected updates, and CLI boundaries, and it detects an injected dropped NAT statement, an unmasked concatenation key, and a non-atomic replacement. The profile is not qualified. Remaining: (1) one known divergence kept as a marked fixture, CRAB-7-D3 (`list ruleset` before later definitions in a replacement file prints nft's evaluation cache, which nfcrt's after-commit queries intentionally do not reproduce); (2) rows not yet implemented: conntrack RELATED/INVALID stimuli, zones, mark propagation and NOTRACK, successful large mixed updates under continuing traffic, JSON `get`/`describe`; (3) a larger seeded expression budget; (4) execution on the production kernel/nft pair if it differs from the image's. Nft itself crashes on JSON input with `list` and leaks a few packets while swapping base chains, so those two rows judge nfcrt against fixture expectations or a packet budget.
- **Recommendation:** Resolve or document each divergence, implement the remaining rows, and re-run until the evidence reports `qualified: true` (`QUALIFY_STRICT=1` fails otherwise). Keep the CRAB-4 library-level transaction-outcome tests as the fault coverage. Delete the RFC once its contract moves to owning documentation.
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

