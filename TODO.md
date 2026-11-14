Prefix: CRAB
Next: 12
### CRAB-11 · P2 · NAT statements accept or encode forms nft treats differently

- **Area:** Language compiler
- **Where:** `src/lang/compile.rs` (`nat()`, tproxy)
- **Problem:** Found while fixing the CRAB-7 divergences: `dnat to 1.2.3.4:80` without a preceding transport protocol match compiles in nfcrt, while nft rejects it (a port translation without a protocol dependency); `tproxy to :80` in an `inet` table is sent with family `inet` where nft sends an unspecified family, so bytecode differs and the listing reads `tproxy ip to :80`. Packet impact is unverified.
- **Recommendation:** Reject port NAT without a transport dependency with nft's diagnostic, encode the unspecified tproxy family as nft does, and add both to the nft differential and the qualification NAT row.
- **Fix with:** reference-parity
- **Effort:** S


### CRAB-7 · P2 · Qualify packet behavior and failed updates against nft before primary firewall use

- **Area:** Firewall compatibility
- **Where:** `cli/tests/qualify.rs`, `tests/common/qualify.rs`, `tests/lang_compile.rs:18`, `cli/tests/compat.rs:27`, `tests/conntrack.rs:427`, `tests/forward.rs:172`, `tests/errors.rs:17`, `tests/errors.rs:145`
- **Problem:** The paired suite runs the same policies and traffic through nft, nfcrt, and the typed API for local and routed IPv4/IPv6 filtering, NAT, conntrack (NEW/ESTABLISHED, RELATED, INVALID, original/reply selectors, ct mark and meta mark propagation, zones, NOTRACK), stateful and large mixed successful updates under tagged continuing traffic, rejected updates, and CLI boundaries including JSON `get`/`describe` (profile: the pinned image's kernel with its Debian trixie nft 1.1.x), with a seeded budget of 40 mark ranges, 40 prefixes plus an interval set, and 14 concatenation keys, and records an evidence file. It detects an injected dropped NAT statement, dropped ct/zone/notrack statements, an unmasked concatenation key, and non-atomic replacements. Every required row executes, and the image profile is not yet qualified: the evidence reports `qualified: false` because of five unresolved divergences kept as marked fixtures (`known_divergence`, which block): D5 `get element` on a map fails in nfcrt; D6 `describe` of an unknown word errors where nft exits 0 (probably benign); D7 `get` of an element added earlier in the same file fails in nft but succeeds in nfcrt, which changes whether the file is applied; D8 nfcrt accepts the keyword `fwd` as a bare chain name; D9 nfcrt keeps an all-ones address mask in a concatenation key that nft drops (packets agree, listings differ). CRAB-7-D3 (`list` inside a replacement file shows nft's pre-commit cache) is a deliberate design difference reported as `intentional` with its written justification and does not block. Remaining: (1) resolve D5 to D9 or have the owner classify them as intentional, then re-run until the evidence reports `qualified: true` (`QUALIFY_STRICT=1` fails otherwise); (2) execution on the production kernel/nft pair if it differs from the image's. Nft itself crashes on JSON input with `list` and leaks a few packets while swapping base chains, so those rows judge nfcrt against fixture expectations or a packet budget.
- **Recommendation:** Resolve or document each divergence and re-run until the evidence reports `qualified: true` (`QUALIFY_STRICT=1` fails otherwise). Keep the CRAB-4 library-level transaction-outcome tests as the fault coverage. Delete the RFC once its contract moves to owning documentation.
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

