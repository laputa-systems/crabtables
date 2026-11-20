# Verification

- Linux with root, network namespaces, nftables, conntrack and iproute2: `make test` runs the workspace with all features; `make lint` runs clippy on workspace targets.
- On OrbStack Linux 7.2.12 aarch64, `errors::every_error_of_a_huge_batch_is_reported` and `known_issues::many_responses` fail with lost responses at admission revision 76765cf; the parent reports a passing upstream hosted kernel job (DSLP-6).
- On that host `fuzz::mutated_kernel_messages`, `lang_compile::{corpus,extra,nat_header_addresses_fwd_and_transport_context}`, `lang_json::{corpus,extra,input_corpus,input_extra}`, `lang_list::{corpus,extra,transport_dependencies_and_full_width_masks}`, `roundtrip::corpus_roundtrip`, and `compat::statements_after_terminal_statements` fail where nft reports unavailable dup/fwd operations, also at admission (DSLP-7).
- `compat::monitor_cli` also fails at admission on that host with a monitor output mismatch (DSLP-8). Passing isolated reruns for these additional failures have not been established.
- Parent disposition: compare the complete local `--no-fail-fast` failure set with `.work/tmp/base-failures.txt`; hosted CI is authoritative for kernel integration. One occurrence of `manage::owner_table_disappears_with_socket` is a known flake (DSLP-9).
- CLI arguments, exit status and text: `cargo test -p nfcrt --test compat`; atomic transactions and packet behavior: `cargo test -p nfcrt --test qualify` and `cargo test --test traffic`.
- Public Rust API and netlink format: `cargo test --workspace --all-features`; language and nft JSON formats: `cargo test --features lang_json --test lang_compile --test lang_list --test lang_json`.
- Performance workload: `examples/bench.rs` compares rule and set loading/listing and transactions; it requires a privileged Linux host, nft and libnftables. Consumer `ctrs` requires separate tests for API changes.
- Admission local full test: 102.25s warm, 237 passed and 16 host failures; lint: 5.27s. No vendored tree was found.
