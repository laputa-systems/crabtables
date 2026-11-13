# 🦀 nfcrt

[![crates.io](https://img.shields.io/crates/v/nfcrt.svg)](https://crates.io/crates/nfcrt)
[![CI](https://github.com/laputa-systems/crabtables/actions/workflows/ci.yml/badge.svg)](https://github.com/laputa-systems/crabtables/actions/workflows/ci.yml)

A pure-Rust nftables command line tool targeting `nft` compatibility. It has no C
dependencies (no libnftables, libnftnl, or libmnl) and is built on
[crabtables](https://crates.io/crates/crabtables).

It accepts nft syntax and supports text and JSON input/output. Examples:

```sh
nfcrt add table inet filter
nfcrt add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
nfcrt add rule inet filter input tcp dport 22 counter accept
nfcrt list ruleset
nfcrt -f /etc/nftables.conf
nfcrt -j list ruleset
nfcrt monitor
```

`-o`/`--optimize` is unsupported. The compatibility tests cover a substantial
corpus, but do not establish equivalence for every expression or transaction.
Read the [qualification status](https://github.com/laputa-systems/crabtables/blob/main/README.md#compatibility-and-qualification)
and [open findings](https://github.com/laputa-systems/crabtables/blob/main/TODO.md)
before using it as a primary firewall frontend.

## Installation

Follow the [installation and capability instructions](https://github.com/laputa-systems/crabtables/blob/main/README.md#nfcrt).
They distinguish the published package from installing this checkout.

## Performance

See the [historical measurements and benchmark harness](https://github.com/laputa-systems/crabtables/blob/main/README.md#performance).

## How it was made

See the [project origin and existing test command](https://github.com/laputa-systems/crabtables/blob/main/README.md#how-it-was-made).

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](https://github.com/finnbear/crabtables/blob/main/LICENSE-APACHE)
   or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](https://github.com/finnbear/crabtables/blob/main/LICENSE-MIT)
   or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
