//! Rulesets compiled by us must equal rulesets loaded by `nft`: same
//! bytecode (`nft --debug=netlink list ruleset`) and same listing.
#[path = "lang_common/mod.rs"]
mod common;
use common::*;
use crabtables::{Family, Socket};

fn setup() {
    netns();
    for d in ["d0", "d1", "eth0", "eth1"] {
        std::process::Command::new("ip")
            .args(["link", "add", d, "type", "dummy"])
            .status()
            .unwrap();
    }
}

/// Bytecode and listing of the ruleset, plus the kernel's set objects.
fn snapshot() -> (String, String, String) {
    // Element order of hash sets depends on a per-set random seed.
    let mut bytecode = String::new();
    let mut elems: Vec<&str> = Vec::new();
    let raw = strip_expires(&nft(&["--debug=netlink", "list", "ruleset"]));
    // Binding chains are numbered by a counter shared by all namespaces.
    let raw = {
        let mut out = String::new();
        let mut rest = raw.as_str();
        while let Some(i) = rest.find("__chain") {
            out.push_str(&rest[..i + 7]);
            rest = rest[i + 7..].trim_start_matches(|c: char| c.is_ascii_digit());
            out.push('N');
        }
        out.push_str(rest);
        out
    };
    for l in raw.lines() {
        if l.starts_with("\telement ") {
            elems.push(l);
            continue;
        }
        elems.sort();
        for e in elems.drain(..) {
            bytecode.push_str(e);
            bytecode.push('\n');
        }
        bytecode.push_str(l);
        bytecode.push('\n');
    }
    elems.sort();
    for e in elems.drain(..) {
        bytecode.push_str(e);
        bytecode.push('\n');
    }
    let listing = strip_expires(&nft(&["list", "ruleset"]));
    let mut s = Socket::new().unwrap();
    let rs = s.list_ruleset(Family::Unspec).unwrap();
    let mut sets = String::new();
    for (set, _) in &rs.sets {
        let mut set = set.clone();
        set.handle = None;
        sets.push_str(&format!("{set:?}\n"));
    }
    (bytecode, listing, sets)
}

fn by_nft(script: &str) -> (String, String, String) {
    let script = script.to_owned();
    std::thread::spawn(move || {
        setup();
        nft_script(&script);
        snapshot()
    })
    .join()
    .unwrap()
}

fn by_us(script: &str) -> (String, String, String) {
    let script = script.to_owned();
    std::thread::spawn(move || {
        setup();
        let cmds = crabtables::lang::parse::parse(&script)
            .unwrap_or_else(|e| panic!("parse: {}", e.render(&script, Some("script"))));
        let mut c = crabtables::lang::compile::Compiler::new();
        c.compile(&cmds)
            .unwrap_or_else(|e| panic!("compile: {}", e.render(&script, Some("script"))));
        let (batch, sources) = c.into_batch();
        let mut s = Socket::new().unwrap();
        if let Err(e) = s.commit(&batch) {
            let mut msg = format!("commit: {e}\n");
            if let Some(b) = e.as_batch() {
                for m in &b.errors {
                    if let Some(src) = m.index.and_then(|i| sources.get(i)) {
                        let span = m
                            .location
                            .as_ref()
                            .and_then(|l| l.expr_index)
                            .and_then(|i| src.expr_spans.get(i))
                            .copied()
                            .unwrap_or(src.span);
                        msg.push_str(
                            &crabtables::lang::Error::at(m.to_string(), span)
                                .render(&script, Some("script")),
                        );
                    }
                }
            }
            panic!("{msg}");
        }
        snapshot()
    })
    .join()
    .unwrap()
}

/// Differences between two bytecode dumps, by rule / set block.
fn block_diff(want: &str, got: &str) -> String {
    fn blocks(s: &str) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for l in s.lines() {
            if !l.starts_with([' ', '\t']) || v.is_empty() {
                v.push(String::new());
            }
            let b = v.last_mut().unwrap();
            b.push_str(l);
            b.push('\n');
        }
        v
    }
    let (w, g) = (blocks(want), blocks(got));
    let mut out = String::new();
    let mut n = 0;
    for i in 0..w.len().max(g.len()) {
        let (a, b) = (
            w.get(i).map_or("", String::as_str),
            g.get(i).map_or("", String::as_str),
        );
        if a != b {
            out.push_str(&format!("--- nft:\n{a}+++ ours:\n{b}\n"));
            n += 1;
            if n >= 6 {
                break;
            }
        }
    }
    out
}

fn check(script: &str) {
    let want = by_nft(script);
    if std::env::var_os("DUMP_NFT").is_some() {
        eprintln!("{}\n{}", want.0, want.2);
    }
    let got = by_us(script);
    if want.0 != got.0 {
        panic!("bytecode differs:\n{}", block_diff(&want.0, &got.0));
    }
    if let Some(d) = diff(&want.1, &got.1) {
        panic!("listing differs:\n{d}");
    }
    if let Some(d) = diff(&want.2, &got.2) {
        panic!("sets differ:\n{d}");
    }
}

#[test]
fn basic() {
    check(
        "table inet t {
  chain c {
    type filter hook input priority filter; policy accept;
    tcp dport 22 accept
    ct state new,established counter
    ct state established
    ct state == established
    ip saddr 10.0.0.0/8 drop
    ip saddr 10.16.0.0/12 drop
    tcp dport { 22, 80 }
    tcp dport { 22 }
    meta mark > 5
    tcp dport 1-1000
    ip ttl set 64
    tcp dport set 80
    ip saddr set 1.2.3.4
  }
}
",
    );
}

#[test]
fn corpus() {
    check(include_str!("data/corpus.nft"));
}

#[test]
fn corpus2() {
    check(include_str!("data/corpus2.nft"));
}

#[test]
fn types() {
    check(include_str!("data/types.nft"));
}

#[test]
fn objects() {
    check(include_str!("data/objects.nft"));
}

#[test]
fn sets_and_statements() {
    check(include_str!("data/sets.nft"));
}

#[test]
fn extra() {
    check(include_str!("data/extra.nft"));
}

#[test]
fn wiki() {
    check(include_str!("data/wiki.nft"));
}

#[test]
fn concat_nested_dependency_keys() {
    for family in ["ip", "inet"] {
        check(&format!(
            "table {family} t {{
  chain c {{
    type filter hook input priority filter; policy accept;
    ip saddr . tcp dport and 255 vmap {{ 1.2.3.4 . 80 : drop }}
  }}
}}
"
        ));
        check(&format!(
            "table {family} t {{
  chain c {{
    type filter hook input priority filter; policy accept;
    ip saddr . tcp dport & 0xff00 | 0x50 vmap {{ 1.2.3.4 . 80 : drop }}
    ip saddr . ip protocol & 0xf vmap {{ 1.2.3.4 . 6 : drop }}
  }}
}}
"
        ));
    }
}

#[test]
fn concat_nested_dependency_keys_ip6() {
    for family in ["ip6", "inet"] {
        check(&format!(
            "table {family} t {{
  chain c {{
    type filter hook input priority filter; policy accept;
    ip6 saddr . tcp dport and 255 vmap {{ ::1 . 80 : drop }}
    ip6 saddr . tcp dport & 0xff00 | 0x50 vmap {{ ::1 . 80 : drop }}
  }}
}}
"
        ));
    }
}

fn check_concat_keys(lines: &[&str]) {
    for family in ["ip", "inet"] {
        for line in lines {
            check(&format!(
                "table {family} t {{
  chain c {{
    type filter hook input priority filter; policy accept;
    {line}
  }}
}}
"
            ));
        }
    }
}

#[test]
fn concat_shifted_components() {
    check_concat_keys(&[
        "ip saddr . udp dport << 1 vmap { 1.2.3.4 . 160 : drop }",
        "ip saddr . tcp dport >> 1 vmap { 1.2.3.4 . 40 : drop }",
        "udp dport << 1 . ip saddr vmap { 160 . 1.2.3.4 : drop }",
        "ip saddr . udp dport << 1 . udp sport >> 1 vmap { 1.2.3.4 . 160 . 40 : drop }",
        "ip saddr . udp dport << 1 { 1.2.3.4 . 160 }",
        "ip saddr . meta mark << 1 vmap { 1.2.3.4 . 10 : drop }",
        "ip saddr . ip ttl << 1 vmap { 1.2.3.4 . 128 : drop }",
        "ip saddr . udp dport << 1 . meta mark vmap { 1.2.3.4 . 160 . 1 : drop }",
        "ip saddr . meta mark . udp dport << 1 . ip daddr vmap { 1.2.3.4 . 1 . 160 . 5.6.7.8 : drop }",
    ]);
}

#[test]
fn concat_integer_exthdr_components() {
    check_concat_keys(&[
        "ip saddr . ip option ra value vmap { 1.2.3.4 . 5 : drop }",
        "ip saddr . tcp option maxseg size vmap { 1.2.3.4 . 1460 : drop }",
        "tcp option maxseg size . ip saddr vmap { 1460 . 1.2.3.4 : drop }",
        "ip saddr . tcp option window count vmap { 1.2.3.4 . 7 : drop }",
        "ip saddr . tcp option maxseg size . ip option ra value vmap { 1.2.3.4 . 1460 . 5 : drop }",
    ]);
}

#[test]
fn concat_jhash_components() {
    check_concat_keys(&[
        "ip saddr . jhash ip daddr mod 4 vmap { 1.2.3.4 . 1 : drop }",
        "ip saddr . jhash ip daddr . tcp dport mod 4 vmap { 1.2.3.4 . 1 : drop }",
        "jhash ip daddr mod 4 . ip saddr vmap { 1 . 1.2.3.4 : drop }",
        "ip saddr . jhash ip daddr mod 4 seed 0x10 offset 2 vmap { 1.2.3.4 . 3 : drop }",
        "ip saddr . jhash ip daddr mod 4 . tcp dport vmap { 1.2.3.4 . 1 . 80 : drop }",
        "ip saddr . symhash mod 4 vmap { 1.2.3.4 . 1 : drop }",
        "jhash ip daddr mod 4 . jhash ip saddr mod 8 vmap { 1 . 2 : drop }",
        "ip saddr . jhash ip daddr mod 4 . tcp dport vmap { 1.2.3.4 . 1 . 80 : drop }",
    ]);
}

#[test]
fn concat_jhash_components_ip6() {
    for family in ["ip6", "inet"] {
        for line in [
            "jhash ip6 daddr mod 4 . ip6 saddr vmap { 1 . ::1 : drop }",
            "ip6 saddr . jhash ip6 daddr mod 4 vmap { ::1 . 1 : drop }",
            "jhash ip6 daddr mod 4 . jhash ip6 saddr mod 8 vmap { 1 . 2 : drop }",
            "jhash ip6 daddr mod 4 . jhash ip6 saddr mod 8 . ip6 saddr vmap { 1 . 2 . ::1 : drop }",
        ] {
            check(&format!(
                "table {family} t {{
  chain c {{
    type filter hook input priority filter; policy accept;
    {line}
  }}
}}
"
            ));
        }
    }
}

#[test]
fn exthdr_and_hash_single_keys() {
    for family in ["ip", "inet"] {
        check(&format!(
            "table {family} t {{
  chain c {{
    type filter hook input priority filter; policy accept;
    tcp option maxseg size {{ 1400, 1460 }}
    tcp option maxseg size vmap {{ 1400 : drop, 1460 : accept }}
    ip option ra value {{ 1, 2 }}
    jhash ip saddr mod 4 {{ 1, 2 }}
    jhash ip saddr mod 4 vmap {{ 1 : drop, 2 : accept }}
  }}
}}
"
        ));
    }
}

#[test]
fn nat_map_with_port_data() {
    check(
        "table ip t {
  map pm {
    type ipv4_addr . inet_service : ipv4_addr . inet_service
    elements = { 10.0.0.1 . 8080 : 10.1.0.2 . 80 }
  }
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    dnat to ip daddr . tcp dport map { 10.0.0.1 . 8080 : 10.1.0.2 . 80, 10.0.0.1 . 8081 : 10.1.0.3 . 81 }
    udp dport 1 dnat to ip daddr . udp dport map { 10.0.0.1 . 53 : 10.1.0.2 . 5353 } persistent
    tcp dport 2 dnat to ip daddr . tcp dport map @pm
    dnat to ip daddr map { 10.0.0.1 : 10.1.0.2 }
  }
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    snat to ip saddr . tcp sport map { 10.0.0.1 . 8080 : 10.1.0.2 . 80 }
  }
}
table ip6 t {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    dnat to ip6 daddr . tcp dport map { fd00::1 . 8080 : fd00:2::2 . 80, fd00::1 . 8081 : fd00:2::3 . 81 }
    dnat to ip6 daddr map { fd00::1 : fd00:2::2 }
  }
}
table inet t {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    dnat ip to ip daddr . tcp dport map { 10.0.0.1 . 8080 : 10.1.0.2 . 80 }
    dnat ip6 to ip6 daddr . tcp dport map { fd00::1 . 8080 : fd00:2::2 . 80 }
  }
}
",
    );
}

#[test]
fn single_value_ranges() {
    check(
        "table ip t {
  chain c {
    type filter hook input priority filter; policy accept;
    meta mark 100-100 counter
    meta mark != 100-100
    meta mark { 5-5, 7-9 }
    tcp dport 80-80
    ip saddr 10.0.0.1-10.0.0.1
  }
}
",
    );
}

#[test]
fn nat_port_with_transport_context() {
    check(
        "table ip t {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    meta l4proto tcp dnat to 1.2.3.4:80
    meta l4proto { tcp, udp } dnat to 1.2.3.4:80
    meta l4proto { 98, 99 } dnat to 1.2.3.4:80
    ip protocol tcp redirect to :80
    ip protocol { tcp, 99 } redirect to :80
    ip protocol 99 tcp dport 1 dnat to 1.2.3.4:80
    ct protocol udp redirect to :80
    icmp type echo-request dnat to 1.2.3.4:80
    tcp dport vmap { 1 : accept } redirect to :80
    tcp dport 1 redirect to 80
    tcp dport 2 redirect to 80-90
    meta l4proto 6 meta l4proto != 17 dnat to 10.80.1.1:80
    dnat to 1.2.3.4
    redirect
  }
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    udp dport 1 masquerade to :80-90
    meta l4proto tcp snat to 1.2.3.4:80
  }
}
",
    );
}

#[test]
fn inet_port_only_nat_and_tproxy_family() {
    check(
        "table inet t {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    tcp dport 1 dnat to :80
    tcp dport 2 redirect to :80
    tcp dport 3 dnat ip to 1.2.3.4:80
  }
  chain mangle {
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto tcp tproxy to :80
    tcp dport 1 tproxy to :80
    udp dport 1 tproxy ip to :80
    udp dport 2 tproxy ip6 to [fd00::5]:80
  }
}
table ip t4 {
  chain mangle {
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto tcp tproxy to :80
    meta l4proto tcp tproxy ip to 1.2.3.4
  }
}
table ip6 t6 {
  chain mangle {
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto tcp tproxy to :80
    meta l4proto tcp tproxy ip6 to [fd00::5]
  }
}
",
    );
}
