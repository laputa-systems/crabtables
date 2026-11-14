//! Our listing of rulesets loaded by `nft` must equal `nft list ruleset`.
#[path = "lang_common/mod.rs"]
mod common;
use common::*;
use crabtables::{Family, Socket};

fn check(script: &str) {
    netns();
    for d in ["d0", "d1", "eth0", "eth1"] {
        std::process::Command::new("ip")
            .args(["link", "add", d, "type", "dummy"])
            .status()
            .unwrap();
    }
    nft_script(script);
    let listing = nft(&["list", "ruleset"]);
    let want = strip_expires(&listing);
    let mut s = Socket::new().unwrap();
    let rs = s.list_ruleset(Family::Unspec).unwrap();
    let got = strip_expires(&crabtables::lang::list_ruleset(&rs, &Default::default()));
    if let Some(d) = diff(&want, &got) {
        panic!("listing differs:\n{d}");
    }
    // Parsing the listing and printing it again gives the same text.
    let cmds = crabtables::lang::parse::parse(&listing)
        .unwrap_or_else(|e| panic!("parse: {}", e.render(&listing, Some("listing"))));
    let tables: Vec<_> = cmds
        .into_iter()
        .map(|c| match c {
            crabtables::lang::ast::Cmd::Table { table, .. } => table,
            c => panic!("unexpected {c:?}"),
        })
        .collect();
    let again = strip_expires(&crabtables::lang::print::tables(
        &tables,
        &Default::default(),
    ));
    if let Some(d) = diff(&want, &again) {
        panic!("reprinted parse differs:\n{d}");
    }
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
fn nat_ip6_brackets() {
    check(
        "table ip6 t {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    tcp dport 1 dnat to [fd00:2::2]:80
    tcp dport 2 dnat to [fd00:2::2]:80-90
    dnat to [fd00:2::2]-[fd00:2::5]
    tcp dport 4 dnat to [fd00:2::2]-[fd00:2::5]:80
    dnat to [fd00:2::2]
    tcp dport 5 redirect to :80
  }
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    tcp dport 1 snat to [fd00:2::2]:80
    tcp dport 2 snat to [fd00:2::2]-[fd00:2::5]:80
    snat to fd00:2::2
    tcp dport 3 masquerade to :80
  }
}
table inet t {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    tcp dport 1 dnat ip6 to [fd00:2::2]:80
    tcp dport 2 dnat ip to 1.2.3.4:80
    dnat ip6 to fd00:2::2
    tcp dport 3 dnat to :80
    tcp dport 4 redirect to :80
  }
  chain mangle {
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto tcp tproxy ip6 to [fd00::5]:80
    meta l4proto tcp tproxy ip6 to [fd00::5]
    meta l4proto tcp tproxy ip to 1.2.3.4:80
    meta l4proto tcp tproxy ip6 to :80
    meta l4proto tcp tproxy to :80
    tcp dport 9 tproxy to :80
  }
}
",
    );
}

#[test]
fn nat_port_fields_and_protocol_ranges() {
    check(
        "table ip t {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    tcp dport 1 dnat to :tcp dport
    tcp dport 2 redirect to :tcp dport
    tcp dport 3 dnat to 1.2.3.4:tcp sport
    dnat to 1.2.3.4:tcp dport random
  }
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    tcp dport 1 masquerade to :tcp dport
    tcp dport 2 snat to 1.2.3.4:tcp sport
  }
  chain mangle {
    type filter hook prerouting priority mangle; policy accept;
    tcp dport 1 tproxy to :tcp dport
  }
  chain c {
    type filter hook input priority filter; policy accept;
    meta l4proto 6-17 accept
    meta l4proto { icmp, 6-17 } accept
    meta l4proto != 6-17 accept
    meta l4proto vmap { 6-17 : accept }
    ip protocol 6-17 accept
    tcp option maxseg exists accept
    tcp option maxseg size 1460 accept
  }
}
",
    );
}
