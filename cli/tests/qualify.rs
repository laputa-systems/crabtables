//! CRAB-7: paired nft-versus-crabtables behavioral qualification. See
//! docs/rfc/CRAB-7-nft-differential-qualification.md.
#[path = "../../tests/common/mod.rs"]
mod common;
#[path = "../../tests/common/qualify.rs"]
mod harness;

use std::net::IpAddr;
use std::sync::Mutex;

use crabtables::sys::{
    NF_CT_STATE_ESTABLISHED_BIT, NF_CT_STATE_NEW_BIT, NF_CT_STATE_RELATED_BIT, NF_CT_STATE_UNTRACKED_BIT,
};
use crabtables::{
    Batch, Chain, ChainType, Family, Field, Hook, Policy, RuleBuilder, Set, SetElem, SetElemList, Table, datatype,
};
use harness::*;

const MARK_SEED: u64 = 0x00c4_ab70;
const MARK_RANDOM_RANGES: usize = 40;

struct B {
    fam: Fam,
    steps: Vec<Step>,
    sinks: Vec<SinkSpec>,
    sport: u16,
}

impl B {
    fn new(fam: Fam) -> B {
        B {
            fam,
            steps: Vec::new(),
            sinks: Vec::new(),
            sport: 41_000,
        }
    }

    fn sink(&mut self, proto: Proto, bind: Bind, port: u16) {
        self.sinks.push(SinkSpec::new(proto, bind, port, true));
    }

    fn sink_quiet(&mut self, proto: Proto, bind: Bind, port: u16) {
        self.sinks.push(SinkSpec::new(proto, bind, port, false));
    }

    fn install(&mut self, label: &'static str, text: String) {
        self.steps.push(Step::Install(Ruleset {
            label,
            text,
            typed: None,
            ok: true,
        }));
    }

    fn probe_full(
        &mut self,
        name: &str,
        from: Origin,
        proto: Proto,
        dst: (Where, u16),
        hold: bool,
        want: Want,
    ) -> u16 {
        self.sport += 1;
        let sport = self.sport;
        self.steps.push(Step::Probe(Probe {
            name: name.to_string(),
            from,
            proto,
            dst,
            sport,
            mark: 0,
            hold,
            want,
        }));
        sport
    }

    fn probe(&mut self, name: &str, from: Origin, proto: Proto, dst: (Where, u16), want: Want) -> u16 {
        self.probe_full(name, from, proto, dst, false, want)
    }

    fn hold(&mut self, name: &str, from: Origin, proto: Proto, dst: (Where, u16), want: Want) -> u16 {
        self.probe_full(name, from, proto, dst, true, want)
    }

    fn probe_spec(
        &mut self,
        name: &str,
        from: Origin,
        proto: Proto,
        dst: (Where, u16),
        (sport, mark): (u16, u32),
        want: Want,
    ) {
        self.steps.push(Step::Probe(Probe {
            name: name.to_string(),
            from,
            proto,
            dst,
            sport,
            mark,
            hold: false,
            want,
        }));
    }

    fn snap(&mut self, label: &'static str, counters: &[(&'static str, u64)], tuples: Vec<Vec<String>>, absent: Vec<Vec<String>>) {
        self.steps.push(Step::Snap(SnapSpec {
            label,
            counters: counters.to_vec(),
            conntrack: true,
            tuples,
            absent,
            ..Default::default()
        }));
    }

    fn finish(self, id: String, row: &'static str) -> Case {
        Case {
            id,
            row,
            fam: self.fam,
            sinks: self.sinks,
            steps: self.steps,
            marker: Marker::None,
            generated: None,
        }
    }
}

fn needles(parts: &[String]) -> Vec<String> {
    parts.to_vec()
}

fn orig(c: IpAddr, sport: u16, d: IpAddr, dport: u16) -> String {
    format!("src={c} dst={d} sport={sport} dport={dport}")
}

fn nat_text(f: Fam, p: &str) -> String {
    let (t, pool) = (f.table(), f.pool());
    let (s0, c1, c2) = (f.server(0), f.client(1), f.client(2));
    let (dnat, range) = (f.hp(s0, 80), f.hp(pool, "5000-5010"));
    format!(
        r#"table {t} q {{
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname "c0" {p} dport 8080 counter dnat to {dnat} comment "dnat"
    iifname "c0" {p} dport 8090 counter redirect to :9090 comment "redirect"
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname "s0" {t} saddr {c1} {p} dport 80 counter snat to {pool} comment "snat"
    oifname "s0" {t} saddr {c2} {p} dport 82 counter snat to {range} comment "snat-range"
    oifname "s0" counter masquerade comment "masq"
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state established,related counter accept comment "~est"
    ct state new {p} dport 80 counter accept comment "new80"
    ct state new {p} dport 82 counter accept comment "new82"
  }}
}}
"#
    )
}

fn nat_case(f: Fam, proto: Proto) -> Case {
    let p = proto.name();
    let mut b = B::new(f);
    let (rc, rs, pool) = (f.router_c(), f.router_s(), f.pool());
    let (c0, c1, c2) = (f.client(0), f.client(1), f.client(2));
    let s0 = f.server(0);
    for port in [80, 81, 82] {
        b.sink(proto, Bind::Srv(0), port);
    }
    b.sink(proto, Bind::Any, 9090);
    b.install("nat", nat_text(f, p));
    let est = if proto == Proto::Tcp { "ESTABLISHED" } else { p };
    let cl = Origin::Client;
    let sp1 = b.probe(
        "dnat",
        cl(0),
        proto,
        (Where::RouterC, 8080),
        Want::at(proto, Bind::Srv(0), 80, rs, PeerPort::Same),
    );
    let sp2 = b.probe(
        "snat",
        cl(1),
        proto,
        (Where::Srv(0), 80),
        Want::at(proto, Bind::Srv(0), 80, pool, PeerPort::Same),
    );
    let sp3 = b.probe(
        "masq",
        cl(0),
        proto,
        (Where::Srv(0), 80),
        Want::at(proto, Bind::Srv(0), 80, rs, PeerPort::Same),
    );
    let sp4 = b.probe(
        "redirect",
        cl(0),
        proto,
        (Where::RouterC, 8090),
        Want::at(proto, Bind::Any, 9090, c0, PeerPort::Same),
    );
    let sp5 = b.probe(
        "snat-range",
        cl(2),
        proto,
        (Where::Srv(0), 82),
        Want::at(proto, Bind::Srv(0), 82, pool, PeerPort::Range(5000, 5010)),
    );
    b.probe("no-nat-refused", cl(0), proto, (Where::RouterC, 8081), Want::Refused);
    b.probe("forward-denied", cl(0), proto, (Where::Srv(0), 81), Want::Blocked);
    let tuples = vec![
        needles(&[
            est.to_string(),
            orig(c0, sp1, rc, 8080),
            format!("src={s0} dst={rs} sport=80 dport={sp1}"),
        ]),
        needles(&[
            est.to_string(),
            orig(c1, sp2, s0, 80),
            format!("src={s0} dst={pool} sport=80 dport={sp2}"),
        ]),
        needles(&[
            est.to_string(),
            orig(c0, sp3, s0, 80),
            format!("src={s0} dst={rs} sport=80 dport={sp3}"),
        ]),
        needles(&[
            est.to_string(),
            orig(c0, sp4, rc, 8090),
            format!("sport=9090 dport={sp4}"),
        ]),
        needles(&[
            est.to_string(),
            orig(c2, sp5, s0, 82),
            format!("src={s0} dst={pool} sport=82 dport="),
        ]),
    ];
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters: vec![
            ("dnat", 1),
            ("redirect", 1),
            ("snat", 1),
            ("snat-range", 1),
            ("masq", 2),
            ("new80", 3),
            ("new82", 1),
        ],
        conntrack: true,
        tuples,
        absent: vec![vec!["dport=81 ".into()]],
        nat_ports: vec![(vec![orig(c2, sp5, s0, 82)], 5000, 5010)],
        ..Default::default()
    }));
    b.finish(format!("nat.{p}.{}", f.tag()), "nat")
}

fn nat_map_text(f: Fam, p: &str) -> String {
    let (t, rc) = (f.table(), f.router_c());
    let (s0, s1) = (f.server(0), f.server(1));
    format!(
        r#"table {t} q {{
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    dnat to {t} daddr . {p} dport map {{ {rc} . 8080 : {s0} . 80, {rc} . 8081 : {s1} . 81 }}
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname "s0" masquerade
  }}
}}
"#
    )
}

fn nat_map_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let rs = f.router_s();
    b.sink(Proto::Tcp, Bind::Srv(0), 80);
    b.sink(Proto::Tcp, Bind::Srv(1), 81);
    b.install("natmap", nat_map_text(f, "tcp"));
    let cl = Origin::Client(0);
    b.probe(
        "map-8080",
        cl,
        Proto::Tcp,
        (Where::RouterC, 8080),
        Want::at(Proto::Tcp, Bind::Srv(0), 80, rs, PeerPort::Same),
    );
    b.probe(
        "map-8081",
        cl,
        Proto::Tcp,
        (Where::RouterC, 8081),
        Want::at(Proto::Tcp, Bind::Srv(1), 81, rs, PeerPort::Same),
    );
    b.probe("map-miss", cl, Proto::Tcp, (Where::RouterC, 8082), Want::Refused);
    b.finish(format!("nat.map.tcp.{}", f.tag()), "nat")
}

fn nat_typed_text(f: Fam) -> String {
    let t = f.table();
    let dnat = f.hp(f.server(0), 80);
    format!(
        r#"table {t} q {{
  chain prerouting {{
    type nat hook prerouting priority -100; policy accept;
    iifname "c0" tcp dport 8080 dnat to {dnat}
  }}
  chain postrouting {{
    type nat hook postrouting priority 100; policy accept;
    oifname "s0" masquerade
  }}
}}
"#
    )
}

fn listing_case(f: Fam) -> Case {
    let mut b = B::new(f);
    b.install("listing", nat_typed_text(f));
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        lister: true,
        ..Default::default()
    }));
    b.finish(format!("nat.listing.{}", f.tag()), "nat")
}

fn nat_typed_batch(f: Fam) -> Batch {
    let fam = if f == Fam::V4 { Family::Ipv4 } else { Family::Ipv6 };
    let mut b = Batch::new();
    b.add_table(&Table::new(fam, "q"));
    b.add_chain(&Chain::new(fam, "q", "prerouting").with_hook(ChainType::Nat, Hook::PREROUTING, -100));
    b.add_chain(&Chain::new(fam, "q", "postrouting").with_hook(ChainType::Nat, Hook::POSTROUTING, 100));
    b.add_rule(
        &RuleBuilder::new(fam, "q", "prerouting")
            .match_eq(Field::IifName, "c0")
            .match_eq(Field::TcpDport, 8080u16)
            .dnat(f.server(0), Some(80))
            .build(),
    );
    b.add_rule(
        &RuleBuilder::new(fam, "q", "postrouting")
            .match_eq(Field::OifName, "s0")
            .masquerade(0)
            .build(),
    );
    b
}

fn nat_typed_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let (rs, s0) = (f.router_s(), f.server(0));
    b.sink(Proto::Tcp, Bind::Srv(0), 80);
    b.steps.push(Step::Install(Ruleset {
        label: "nat-typed",
        text: nat_typed_text(f),
        typed: Some(nat_typed_batch),
        ok: true,
    }));
    let sp = b.probe(
        "dnat",
        Origin::Client(0),
        Proto::Tcp,
        (Where::RouterC, 8080),
        Want::at(Proto::Tcp, Bind::Srv(0), 80, rs, PeerPort::Same),
    );
    b.probe("miss", Origin::Client(0), Proto::Tcp, (Where::RouterC, 8081), Want::Refused);
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters: vec![],
        conntrack: true,
        tuples: vec![needles(&[
            "ESTABLISHED".into(),
            orig(f.client(0), sp, f.router_c(), 8080),
            format!("src={s0} dst={rs} sport=80 dport={sp}"),
        ])],
        absent: vec![],
        ..Default::default()
    }));
    b.finish(format!("nat.typed.tcp.{}", f.tag()), "nat")
}

fn stateful_a(f: Fam) -> String {
    let (t, dnat) = (f.table(), f.hp(f.server(0), 80));
    format!(
        r#"table {t} q {{
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname "c0" tcp dport 8080 counter dnat to {dnat} comment "dnat"
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname "s0" counter masquerade comment "masq"
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    udp dport 9999 accept
    ct state established,related counter accept comment "~est"
    ct state new tcp dport 80 counter accept comment "new80"
  }}
}}
"#
    )
}

fn stateful_b(f: Fam) -> String {
    let (t, dnat, s1) = (f.table(), f.hp(f.server(1), 80), f.server(1));
    format!(
        r#"flush ruleset
table {t} q {{
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname "c0" tcp dport 8080 counter dnat to {dnat} comment "dnat"
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname "s0" counter masquerade comment "~masq"
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    udp dport 9999 accept
    ct state established,related counter accept comment "~est"
    ct state new tcp dport 81 counter accept comment "new81"
    ct state new {t} daddr {s1} tcp dport 80 counter accept comment "new80b"
  }}
}}
"#
    )
}

fn stateful_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let (rc, rs) = (f.router_c(), f.router_s());
    let (c0, s0, s1) = (f.client(0), f.server(0), f.server(1));
    let cl = Origin::Client(0);
    b.sink(Proto::Tcp, Bind::Srv(0), 80);
    b.sink(Proto::Tcp, Bind::Srv(0), 81);
    b.sink(Proto::Tcp, Bind::Srv(1), 80);
    b.sink(Proto::Udp, Bind::Srv(0), 9);
    b.sinks.push(SinkSpec::fence(Bind::Srv(0), 9999));
    b.install("a", stateful_a(f));
    let sp_old = b.hold(
        "old-flow",
        cl,
        Proto::Tcp,
        (Where::RouterC, 8080),
        Want::at(Proto::Tcp, Bind::Srv(0), 80, rs, PeerPort::Same),
    );
    b.probe(
        "a-direct-80",
        cl,
        Proto::Tcp,
        (Where::Srv(0), 80),
        Want::at(Proto::Tcp, Bind::Srv(0), 80, rs, PeerPort::Same),
    );
    b.probe("a-direct-81", cl, Proto::Tcp, (Where::Srv(0), 81), Want::Blocked);
    b.steps.push(Step::Snap(SnapSpec {
        label: "a",
        counters: vec![("dnat", 1), ("masq", 2), ("new80", 2)],
        conntrack: true,
        tuples: vec![needles(&[
            "ESTABLISHED".into(),
            orig(c0, sp_old, rc, 8080),
            format!("src={s0} dst={rs} sport=80 dport={sp_old}"),
        ])],
        absent: vec![],
        ..Default::default()
    }));
    b.steps.push(Step::Replace(Replace {
        policy: Ruleset {
            label: "b",
            text: stateful_b(f),
            typed: None,
            ok: true,
        },
        canary: sink_name(Proto::Udp, Bind::Srv(0), 9),
        canary_port: 9,
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
    b.steps.push(Step::Send {
        name: "old-flow",
        want: true,
    });
    let sp_new = b.probe(
        "b-8080",
        cl,
        Proto::Tcp,
        (Where::RouterC, 8080),
        Want::at(Proto::Tcp, Bind::Srv(1), 80, rs, PeerPort::Same),
    );
    b.probe(
        "b-direct-81",
        cl,
        Proto::Tcp,
        (Where::Srv(0), 81),
        Want::at(Proto::Tcp, Bind::Srv(0), 81, rs, PeerPort::Same),
    );
    b.probe("b-direct-80", cl, Proto::Tcp, (Where::Srv(0), 80), Want::Blocked);
    b.probe("b-canary", cl, Proto::Udp, (Where::Srv(0), 9), Want::Blocked);
    b.steps.push(Step::Snap(SnapSpec {
        label: "b",
        counters: vec![("dnat", 1), ("new81", 1), ("new80b", 1)],
        hide_ct: vec!["dport=9 ".into()],
        conntrack: true,
        tuples: vec![
            needles(&[
                "ESTABLISHED".into(),
                orig(c0, sp_old, rc, 8080),
                format!("src={s0} dst={rs} sport=80 dport={sp_old}"),
            ]),
            needles(&[
                "ESTABLISHED".into(),
                orig(c0, sp_new, rc, 8080),
                format!("src={s1} dst={rs} sport=80 dport={sp_new}"),
            ]),
        ],
        absent: vec![],
        ..Default::default()
    }));
    b.finish(format!("stateful.replace.{}", f.tag()), "stateful")
}

fn concat_text(f: Fam) -> String {
    let (t, c1) = (f.table(), f.client(1));
    format!(
        r#"table {t} q {{
  chain forward {{
    type filter hook forward priority filter; policy accept;
    {t} saddr . tcp dport and 255 vmap {{ {c1} . 80 : drop }}
  }}
}}
"#
    )
}

fn concat_case(f: Fam) -> Case {
    let mut b = B::new(f);
    for port in [80, 81, 336] {
        b.sink(Proto::Tcp, Bind::Srv(0), port);
    }
    b.install("concat", concat_text(f));
    let ok = |port| Want::at(Proto::Tcp, Bind::Srv(0), port, f.client(0), PeerPort::Same);
    let ok1 = |port| Want::at(Proto::Tcp, Bind::Srv(0), port, f.client(1), PeerPort::Same);
    let dst = |port| (Where::Srv(0), port);
    b.probe("listed-key", Origin::Client(1), Proto::Tcp, dst(80), Want::Blocked);
    b.probe("listed-addr-other-port", Origin::Client(1), Proto::Tcp, dst(81), ok1(81));
    b.probe("other-addr-listed-port", Origin::Client(0), Proto::Tcp, dst(80), ok(80));
    b.probe("masked-port-key", Origin::Client(1), Proto::Tcp, dst(336), Want::Blocked);
    b.probe("other-addr-masked-port", Origin::Client(0), Proto::Tcp, dst(336), ok(336));
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        ..Default::default()
    }));
    b.finish(format!("expr.concat_vmap.{}", f.tag()), "expressions")
}

fn concat_udp_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let t = f.table();
    let net_num = addr_num(f.client(2)) & !0x7f;
    let (net, mask): (IpAddr, &str) = match f {
        Fam::V4 => (std::net::Ipv4Addr::from(net_num as u32).into(), "255.255.255.128"),
        Fam::V6 => (std::net::Ipv6Addr::from(net_num).into(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff80"),
    };
    let text = format!(
        r#"table {t} q {{
  chain forward {{
    type filter hook forward priority filter; policy accept;
    udp dport 9999 accept
    {t} saddr and {mask} . udp dport and 0xff00 vmap {{ {net} . 5120 : drop }}
  }}
}}
"#
    );
    b.install("concat-udp", text);
    let ports = [5119u16, 5120, 5375, 5376];
    let mut dgrams = Vec::new();
    for port in ports {
        b.sink_quiet(Proto::Udp, Bind::Srv(0), port);
        for src in 0..4 {
            let key_addr = addr_num(f.client(src)) & !0x7f;
            let dropped = key_addr == net_num && (port & 0xff00) == 5120 & 0xff00;
            dgrams.push(Dgram {
                src,
                sport: 20_000 + dgrams.len() as u16,
                dport: port,
                mark: 0,
                want: !dropped,
            });
        }
    }
    b.sinks.push(SinkSpec::fence(Bind::Srv(0), 9999));
    b.steps.push(Step::Burst(Burst {
        label: "keys",
        from: Origin::Client(0),
        dst: Where::Srv(0),
        dgrams,
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
    b.finish(format!("expr.concat_vmap_udp_masks.{}", f.tag()), "expressions")
}

#[derive(Clone, Copy)]
enum Fate {
    Fall,
    Pass,
    Drop,
}

fn chain_verdict(port: u16) -> (bool, [u32; 5]) {
    let mut c = [0u32; 5];
    let mut fate = Fate::Fall;
    match port {
        6000..=6099 => fate = Fate::Drop,
        6100..=6199 => fate = Fate::Pass,
        _ => {}
    }
    if matches!(fate, Fate::Drop) {
        return (false, c);
    }
    if matches!(fate, Fate::Pass) {
        return (true, c);
    }
    match port {
        5000..=5099 => {
            c[0] += 1;
            if port == 5050 {
                c[3] += 1;
                return (true, c);
            }
            c[1] += 1;
            if port == 5051 {
                return (false, c);
            }
            c[3] += 1;
            (true, c)
        }
        5100..=5199 => {
            c[2] += 1;
            (port != 5151, c)
        }
        5200..=5299 => (false, c),
        _ => {
            c[3] += 1;
            (true, c)
        }
    }
}

fn jump_text(f: Fam) -> String {
    let t = f.table();
    format!(
        r#"table {t} q {{
  map pm {{
    type inet_service : verdict
    flags interval
    elements = {{ 6000-6099 : drop, 6100-6199 : accept }}
  }}
  chain ja {{
    counter comment "ja-in"
    udp dport 5050 return
    counter comment "ja-after"
    udp dport 5051 drop
  }}
  chain gb {{
    counter comment "gb-in"
    udp dport 5150 return
    udp dport 5151 drop
  }}
  chain forward {{
    type filter hook forward priority filter; policy accept;
    udp dport 9999 accept
    udp dport vmap @pm
    udp dport vmap {{ 5000-5099 : jump ja, 5100-5199 : goto gb, 5200-5299 : drop }}
    counter comment "fall"
  }}
}}
"#
    )
}

fn jump_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let ports: [u16; 18] = [
        4999, 5000, 5050, 5051, 5099, 5100, 5150, 5151, 5199, 5200, 5299, 5300, 5999, 6000, 6099, 6100,
        6199, 6200,
    ];
    let mut dgrams = Vec::new();
    let mut want = [0u32; 5];
    for (i, port) in ports.iter().enumerate() {
        b.sink_quiet(Proto::Udp, Bind::Srv(0), *port);
        let (delivered, c) = chain_verdict(*port);
        for k in 0..5 {
            want[k] += c[k];
        }
        dgrams.push(Dgram {
            src: 0,
            sport: 20_000 + i as u16,
            dport: *port,
            mark: 0,
            want: delivered,
        });
    }
    b.sinks.push(SinkSpec::fence(Bind::Srv(0), 9999));
    b.install("jump", jump_text(f));
    b.steps.push(Step::Burst(Burst {
        label: "ports",
        from: Origin::Client(0),
        dst: Where::Srv(0),
        dgrams,
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters: vec![
            ("ja-in", want[0] as u64),
            ("ja-after", want[1] as u64),
            ("gb-in", want[2] as u64),
            ("fall", want[3] as u64),
        ],
        ..Default::default()
    }));
    b.finish(format!("expr.jump_goto_return_maps.{}", f.tag()), "expressions")
}

fn addr_num(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(a) => u32::from(a) as u128,
        IpAddr::V6(a) => u128::from(a),
    }
}

fn in_prefix(a: IpAddr, net: IpAddr, len: u32) -> bool {
    let width = if a.is_ipv4() { 32 } else { 128 };
    if len == 0 {
        return true;
    }
    (addr_num(a) >> (width - len)) == (addr_num(net) >> (width - len))
}

fn prefix_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let t = f.table();
    let v6 = f == Fam::V6;
    let a = |v4: [u8; 4], v6last: u16| -> IpAddr {
        if v6 {
            IpAddr::V6(std::net::Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, v6last))
        } else {
            IpAddr::V4(std::net::Ipv4Addr::from(v4))
        }
    };
    let zero: IpAddr = if v6 { "::".parse().unwrap() } else { "0.0.0.0".parse().unwrap() };
    let high: IpAddr = if v6 { "::".parse().unwrap() } else { "128.0.0.0".parse().unwrap() };
    let (base, hi_half) = if v6 {
        (a([0; 4], 0), a([0; 4], 0x80))
    } else {
        (a([10, 1, 0, 0], 0), a([10, 1, 0, 128], 0))
    };
    let c1 = f.client(1);
    let lens = if v6 { (121, 121, 127, 128) } else { (25, 25, 31, 32) };
    let pair = if v6 { a([0; 4], 2) } else { a([10, 1, 0, 2], 0) };
    let prefixes: Vec<(IpAddr, u32)> = vec![
        (zero, 0),
        (c1, lens.3),
        (base, lens.0),
        (hi_half, lens.1),
        (high, 1),
        (pair, lens.2),
    ];
    let (set_lo, set_hi) = (a([10, 1, 0, 200], 0xc8), a([10, 1, 0, 210], 0xd2));
    let set_one = f.client(0);
    let in_set = |s: IpAddr| s == set_one || (addr_num(set_lo)..=addr_num(set_hi)).contains(&addr_num(s));
    let set_ty = if v6 { "ipv6_addr" } else { "ipv4_addr" };
    let mut rules = String::new();
    let mut ports: Vec<u16> = Vec::new();
    let mut matcher: Vec<Box<dyn Fn(IpAddr) -> bool>> = Vec::new();
    for (i, (net, len)) in prefixes.iter().enumerate() {
        rules.push_str(&format!(
            "    udp dport {} {t} saddr {net}/{len} counter drop comment \"p{i}\"\n",
            6000 + i
        ));
        ports.push(6000 + i as u16);
        let (net, len) = (*net, *len);
        matcher.push(Box::new(move |s| in_prefix(s, net, len)));
    }
    let k = prefixes.len();
    rules.push_str(&format!(
        "    udp dport {} {t} saddr @blk counter drop comment \"p{k}\"\n",
        6000 + k
    ));
    ports.push(6000 + k as u16);
    matcher.push(Box::new(in_set));
    let text = format!(
        r#"table {t} q {{
  set blk {{
    type {set_ty}
    flags interval
    elements = {{ {set_one}, {set_lo}-{set_hi} }}
  }}
  chain forward {{
    type filter hook forward priority filter; policy accept;
    udp dport 9999 accept
{rules}  }}
}}
"#
    );
    b.install("prefix", text);
    let mut dgrams = Vec::new();
    let mut counts = vec![0u64; ports.len()];
    for (pi, port) in ports.iter().enumerate() {
        b.sink_quiet(Proto::Udp, Bind::Srv(0), *port);
        for src in 0..4 {
            let dropped = matcher[pi](f.client(src));
            if dropped {
                counts[pi] += 1;
            }
            dgrams.push(Dgram {
                src,
                sport: 20_000 + dgrams.len() as u16,
                dport: *port,
                mark: 0,
                want: !dropped,
            });
        }
    }
    b.sinks.push(SinkSpec::fence(Bind::Srv(0), 9999));
    b.steps.push(Step::Burst(Burst {
        label: "sources",
        from: Origin::Client(0),
        dst: Where::Srv(0),
        dgrams,
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
    let names: Vec<&'static str> = (0..ports.len())
        .map(|i| &*Box::leak(format!("p{i}").into_boxed_str()))
        .collect();
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters: names.into_iter().zip(counts).collect(),
        ..Default::default()
    }));
    b.finish(format!("expr.prefix_set.{}", f.tag()), "expressions")
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 16
    }
}

fn mark_ranges() -> Vec<(u32, u32)> {
    let mut v = vec![
        (1, 256),
        (0xfffe, 0x1_0001),
        (0xff_ffff, 0x100_0001),
        (0x7fff_fffe, 0x8000_0001),
    ];
    let mut r = Lcg(MARK_SEED);
    let widths = [1u64, 2, 255, 256, 0xffff, 0x1_0000, 0xff_ffff, 0x100_0000];
    for _ in 0..MARK_RANDOM_RANGES {
        let lo = (r.next() & 0xffff_ffff) as u32;
        let w = widths[(r.next() % widths.len() as u64) as usize];
        let hi = (lo as u64 + w).min(u32::MAX as u64) as u32;
        v.push((lo, hi));
    }
    v
}

fn mark_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let t = f.table();
    let ranges = mark_ranges();
    let mut rules = String::new();
    let mut dgrams = Vec::new();
    let mut counts = Vec::new();
    for (i, (lo, hi)) in ranges.iter().enumerate() {
        let port = 5100 + i as u16;
        rules.push_str(&format!(
            "    udp dport {port} meta mark {lo}-{hi} counter drop comment \"r{i}\"\n"
        ));
        b.sink_quiet(Proto::Udp, Bind::Srv(0), port);
        let mut marks: Vec<u32> = vec![0, u32::MAX, *lo, *hi, lo.wrapping_add(1), hi.wrapping_sub(1)];
        if *lo > 0 {
            marks.push(lo - 1);
        }
        if *hi < u32::MAX {
            marks.push(hi + 1);
        }
        marks.sort();
        marks.dedup();
        let mut n = 0;
        for m in marks {
            let inside = (*lo..=*hi).contains(&m);
            if inside {
                n += 1;
            }
            dgrams.push(Dgram {
                src: 0,
                sport: 20_000 + dgrams.len() as u16,
                dport: port,
                mark: m,
                want: !inside,
            });
        }
        counts.push(n);
    }
    b.sinks.push(SinkSpec::fence(Bind::Srv(0), 9999));
    let text = format!(
        r#"table {t} q {{
  chain output {{
    type filter hook output priority filter; policy accept;
    udp dport 9999 accept
{rules}  }}
}}
"#
    );
    b.install("marks", text);
    b.steps.push(Step::Burst(Burst {
        label: "marks",
        from: Origin::Router,
        dst: Where::Srv(0),
        dgrams,
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
    let names: Vec<&'static str> = (0..ranges.len())
        .map(|i| &*Box::leak(format!("r{i}").into_boxed_str()))
        .collect();
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters: names.into_iter().zip(counts).collect(),
        ..Default::default()
    }));
    let mut c = b.finish(format!("expr.mark_ranges.{}", f.tag()), "expressions");
    c.generated = Some((MARK_SEED, MARK_RANDOM_RANGES));
    c
}

const BASE: &str = r#"table inet q {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related counter accept comment "~est"
    udp dport 7000 ct state new counter accept comment "allow"
    tcp dport 7002 ct state new counter accept comment "allow-tcp"
  }
}
"#;

const REPLACED: &str = r#"flush ruleset
list ruleset
describe tcp dport
table inet q {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related counter accept comment "~est"
    udp dport 7001 ct state new counter accept comment "allow"
  }
}
"#;

const FAILING: &str = "flush ruleset
list ruleset
add table ip probe
add chain ip probe bad { type nat hook forward priority 0; }
";

const FAILING_JSON_LIST: &str = r#"{"nftables": [
{"flush": {"ruleset": null}},
{"list": {"ruleset": null}},
{"add": {"table": {"family": "ip", "name": "probe"}}},
{"add": {"chain": {"family": "ip", "table": "probe", "name": "bad", "type": "nat", "hook": "forward", "prio": 0}}}
]}"#;

const FAILING_JSON: &str = r#"{"nftables": [
{"flush": {"ruleset": null}},
{"add": {"table": {"family": "ip", "name": "probe"}}},
{"add": {"chain": {"family": "ip", "table": "probe", "name": "bad", "type": "nat", "hook": "forward", "prio": 0}}}
]}"#;

const REPLACED_JSON: &str = r#"{"nftables": [
{"flush": {"ruleset": null}},
{"add": {"table": {"family": "inet", "name": "q"}}},
{"add": {"chain": {"family": "inet", "table": "q", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}}},
{"add": {"rule": {"family": "inet", "table": "q", "chain": "forward", "expr": [
  {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
  {"counter": null}, {"accept": null}]}}},
{"add": {"rule": {"family": "inet", "table": "q", "chain": "forward", "expr": [
  {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 7001}},
  {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["new"]}},
  {"counter": null}, {"accept": null}]}}}
]}"#;

fn base_typed(_: Fam) -> Batch {
    let f = Family::Inet;
    let mut b = Batch::new();
    b.add_table(&Table::new(f, "q"));
    b.add_chain(
        &Chain::new(f, "q", "forward")
            .with_hook(ChainType::Filter, Hook::FORWARD, 0)
            .with_policy(Policy::Drop),
    );
    let r = || RuleBuilder::new(f, "q", "forward");
    b.add_rule(
        &r().ct_state(NF_CT_STATE_ESTABLISHED_BIT | NF_CT_STATE_RELATED_BIT)
            .counter()
            .comment("~est")
            .accept()
            .build(),
    );
    b.add_rule(
        &r().match_eq(Field::UdpDport, 7000u16)
            .ct_state(NF_CT_STATE_NEW_BIT)
            .counter()
            .comment("allow")
            .accept()
            .build(),
    );
    b.add_rule(
        &r().match_eq(Field::TcpDport, 7002u16)
            .ct_state(NF_CT_STATE_NEW_BIT)
            .counter()
            .comment("allow-tcp")
            .accept()
            .build(),
    );
    b
}

#[derive(Clone, Copy, PartialEq)]
enum Policy2 {
    A,
    B,
}

fn controls(b: &mut B, round: &str, state: Policy2) {
    let cl = Origin::Client(0);
    let c0 = b.fam.client(0);
    let (a_ok, b_ok) = (state == Policy2::A, state == Policy2::B);
    let udp = |port, ok: bool| {
        if ok {
            Want::at(Proto::Udp, Bind::Srv(0), port, c0, PeerPort::Same)
        } else {
            Want::Blocked
        }
    };
    b.probe(&format!("{round}-udp7000"), cl, Proto::Udp, (Where::Srv(0), 7000), udp(7000, a_ok));
    b.probe(&format!("{round}-udp7001"), cl, Proto::Udp, (Where::Srv(0), 7001), udp(7001, b_ok));
    b.probe(
        &format!("{round}-tcp7003"),
        cl,
        Proto::Tcp,
        (Where::Srv(0), 7003),
        Want::Blocked,
    );
}

fn update_case(
    f: Fam,
    id: String,
    row: &'static str,
    update: Vec<Step>,
    after: Policy2,
    typed: bool,
) -> Case {
    update_case_with(f, id, row, "", update, after, typed)
}

fn update_case_with(
    f: Fam,
    id: String,
    row: &'static str,
    extra: &str,
    update: Vec<Step>,
    after: Policy2,
    typed: bool,
) -> Case {
    let mut b = B::new(f);
    b.sink(Proto::Udp, Bind::Srv(0), 7000);
    b.sink(Proto::Udp, Bind::Srv(0), 7001);
    b.sink(Proto::Tcp, Bind::Srv(0), 7002);
    b.sink(Proto::Tcp, Bind::Srv(0), 7003);
    b.steps.push(Step::Install(Ruleset {
        label: "base",
        text: format!("{BASE}{extra}"),
        typed: typed.then_some(base_typed as fn(Fam) -> Batch),
        ok: true,
    }));
    let c0 = f.client(0);
    let sp = b.hold(
        "held",
        Origin::Client(0),
        Proto::Tcp,
        (Where::Srv(0), 7002),
        Want::at(Proto::Tcp, Bind::Srv(0), 7002, c0, PeerPort::Same),
    );
    controls(&mut b, "pre", Policy2::A);
    let held_tuple = vec![needles(&[
        "ESTABLISHED".into(),
        orig(c0, sp, f.server(0), 7002),
    ])];
    b.steps.push(Step::Snap(SnapSpec {
        label: "before",
        counters: vec![("allow", 1), ("allow-tcp", 1)],
        conntrack: true,
        tuples: held_tuple.clone(),
        absent: vec![],
        ..Default::default()
    }));
    b.steps.extend(update);
    b.steps.push(Step::Snap(SnapSpec {
        label: "after",
        conntrack: true,
        tuples: held_tuple.clone(),
        ..Default::default()
    }));
    if after == Policy2::A {
        b.steps.push(Step::Same("before", "after"));
    }
    b.steps.push(Step::Send {
        name: "held",
        want: true,
    });
    controls(&mut b, "post", after);
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        conntrack: true,
        tuples: held_tuple,
        ..Default::default()
    }));
    b.finish(id, row)
}

fn bad_install(label: &'static str, text: String, typed: Option<fn(Fam) -> Batch>) -> Step {
    Step::Install(Ruleset {
        label,
        text,
        typed,
        ok: false,
    })
}

fn rej_begin(_: Fam) -> Batch {
    let mut b = Batch::new();
    b.add_chain(&Chain::new(Family::Inet, "q", "natbad").with_hook(ChainType::Nat, Hook::FORWARD, 0));
    b.add_table(&Table::new(Family::Ipv4, "probe"));
    b.insert_rule(&RuleBuilder::new(Family::Inet, "q", "forward").accept().build());
    b
}

fn rej_middle(_: Fam) -> Batch {
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Ipv4, "probe"));
    b.add_rule(&RuleBuilder::new(Family::Inet, "q", "forward").jump("nowhere").build());
    b.insert_rule(&RuleBuilder::new(Family::Inet, "q", "forward").accept().build());
    b
}

fn rej_end(_: Fam) -> Batch {
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Ipv4, "probe"));
    b.insert_rule(&RuleBuilder::new(Family::Inet, "q", "forward").accept().build());
    b.add_rule(&RuleBuilder::new(Family::Inet, "q", "forward").masquerade(0).build());
    b
}

const SPLIT_ELEMENTS: u32 = 20_000;

fn rej_split(_: Fam) -> Batch {
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Inet, "big"));
    b.insert_rule(&RuleBuilder::new(Family::Inet, "q", "forward").accept().build());
    b.add_set(&Set::new(Family::Inet, "big", "s", datatype::IPADDR, 4));
    let mut l = SetElemList::new(Family::Inet, "big", "s");
    for i in 0..SPLIT_ELEMENTS {
        l = l.with(SetElem::new((0x0a00_0000u32 + i).to_be_bytes().to_vec()));
    }
    b.add_elems(&l);
    b.add_chain(&Chain::new(Family::Inet, "q", "natbad").with_hook(ChainType::Nat, Hook::FORWARD, 0));
    b
}

fn split_text() -> String {
    let mut s = String::from("add table inet big\ninsert rule inet q forward accept\n");
    s.push_str("add set inet big s { type ipv4_addr; }\nadd element inet big s { ");
    for i in 0..SPLIT_ELEMENTS {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&std::net::Ipv4Addr::from(0x0a00_0000u32 + i).to_string());
    }
    s.push_str(" }\nadd chain inet q natbad { type nat hook forward priority 0; }\n");
    s
}

fn rejected_cases(f: Fam) -> Vec<Case> {
    let t = f.tag();
    let mk = |name: &str, text: String, typed: fn(Fam) -> Batch| {
        update_case(
            f,
            format!("rejected.{name}.{t}"),
            "rejected",
            vec![bad_install("bad", text, Some(typed))],
            Policy2::A,
            true,
        )
    };
    vec![
        mk(
            "first_op_invalid",
            "add chain inet q natbad { type nat hook forward priority 0; }\nadd table ip probe\ninsert rule inet q forward accept\n".into(),
            rej_begin,
        ),
        mk(
            "middle_op_invalid",
            "add table ip probe\nadd rule inet q forward jump nowhere\ninsert rule inet q forward accept\n".into(),
            rej_middle,
        ),
        mk(
            "last_op_invalid",
            "add table ip probe\ninsert rule inet q forward accept\nadd rule inet q forward masquerade\n".into(),
            rej_end,
        ),
        mk("after_element_split", split_text(), rej_split),
    ]
}

fn cli_step(label: &'static str, args: &[&'static str], files: Vec<(&'static str, String)>, stdin: Option<&'static str>, ok: bool) -> Vec<Step> {
    vec![Step::Cli(Cli {
        label,
        args: args.to_vec(),
        files,
        stdin,
        ok,
        stdout: false,
        reference_may_crash: false,
    })]
}

fn cli_cases(f: Fam) -> Vec<Case> {
    let t = f.tag();
    let tail = "list ruleset\nadd table ip probe\ninclude \"last.nft\"\n";
    let last = "add chain ip probe bad { type nat hook forward priority 0; }\n";
    let incl_ok = |body: &str| vec![
        ("outer.nft", "flush ruleset\ninclude \"tail.nft\"\n".to_string()),
        ("tail.nft", "list ruleset\ninclude \"b.nft\"\n".to_string()),
        ("b.nft", body.to_string()),
    ];
    let table_b = REPLACED.split_once("describe tcp dport\n").unwrap().1;
    let v: Vec<(String, Vec<Step>, Policy2)> = vec![
    (
        "reject_file".into(),
        cli_step("file", &["-f", "bad.nft"], vec![("bad.nft", FAILING.into())], None, false),
        Policy2::A,
    ),
    (
        "reject_stdin".into(),
        cli_step("stdin", &["-f", "-"], vec![], Some(FAILING), false),
        Policy2::A,
    ),
    (
        "reject_include".into(),
        cli_step(
            "include",
            &["-f", "outer.nft"],
            vec![
                ("outer.nft", "flush ruleset\ninclude \"tail.nft\"\n".into()),
                ("tail.nft", tail.into()),
                ("last.nft", last.into()),
            ],
            None,
            false,
        ),
        Policy2::A,
    ),
    (
        "reject_json".into(),
        cli_step("json", &["-j", "-f", "bad.json"], vec![("bad.json", FAILING_JSON.into())], None, false),
        Policy2::A,
    ),
    (
        "reject_json_with_list".into(),
        vec![Step::Cli(Cli {
            label: "json-list",
            args: vec!["-j", "-f", "bad.json"],
            files: vec![("bad.json", FAILING_JSON_LIST.into())],
            stdin: None,
            ok: false,
            stdout: false,
            reference_may_crash: true,
        })],
        Policy2::A,
    ),
    (
        "reject_json_stdin".into(),
        cli_step("json-stdin", &["-j", "-f", "-"], vec![], Some(FAILING_JSON), false),
        Policy2::A,
    ),
    (
        "reject_parse_error".into(),
        cli_step(
            "parse",
            &["-f", "syntax.nft"],
            vec![("syntax.nft", "flush ruleset\nadd table inet z\nadd rule inet z c this is not nft\n".into())],
            None,
            false,
        ),
        Policy2::A,
    ),
    (
        "replace_file".into(),
        cli_step("file", &["-f", "b.nft"], vec![("b.nft", REPLACED.into())], None, true),
        Policy2::B,
    ),
    (
        "replace_stdin".into(),
        cli_step("stdin", &["-f", "-"], vec![], Some(REPLACED), true),
        Policy2::B,
    ),
    (
        "replace_include".into(),
        cli_step("include", &["-f", "outer.nft"], incl_ok(table_b), None, true),
        Policy2::B,
    ),
    (
        "replace_json".into(),
        cli_step("json", &["-j", "-f", "b.json"], vec![("b.json", REPLACED_JSON.into())], None, true),
        Policy2::B,
    ),
    (
        "check_valid_replacement".into(),
        cli_step("check", &["-c", "-f", "b.nft"], vec![("b.nft", REPLACED.into())], None, true),
        Policy2::A,
    ),
    (
        "check_kernel_invalid".into(),
        cli_step("check-bad", &["-c", "-f", "bad.nft"], vec![("bad.nft", FAILING.into())], None, false),
        Policy2::A,
    ),
    ];
    let mut out: Vec<Case> = v
        .into_iter()
        .map(|(name, steps, after)| update_case(f, format!("cli.{name}.{t}"), "cli", steps, after, false))
        .collect();
    let mut d3 = update_case(
        f,
        format!("cli.list_stdout_in_replacement.{t}"),
        "cli",
        vec![Step::Cli(Cli {
            label: "list-stdout",
            args: vec!["-f", "b.nft"],
            files: vec![("b.nft", REPLACED.into())],
            stdin: None,
            ok: true,
            stdout: true,
            reference_may_crash: false,
        })],
        Policy2::B,
        false,
    );
    d3.marker = Marker::Intentional(
        "CRAB-7-D3: nft runs `list` after evaluating the whole file and before sending the batch, so it prints its local cache (kernel state at the start with only some commands applied), a state that exists in neither the old nor the new ruleset. nfcrt runs queries after the commit so that a query between mutations reports the state those mutations produced. Exit status, transaction outcome and packet policy agree.",
    );
    out.push(d3);
    out
}

fn single_mark_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let t = f.table();
    b.sink_quiet(Proto::Udp, Bind::Srv(0), 5100);
    b.sinks.push(SinkSpec::fence(Bind::Srv(0), 9999));
    b.install(
        "single",
        format!(
            "table {t} q {{\n  chain output {{\n    type filter hook output priority filter; policy accept;\n    udp dport 9999 accept\n    udp dport 5100 meta mark 100-100 counter drop comment \"r0\"\n  }}\n}}\n"
        ),
    );
    let dgrams = [99u32, 100, 101]
        .into_iter()
        .enumerate()
        .map(|(i, m)| Dgram {
            src: 0,
            sport: 20_000 + i as u16,
            dport: 5100,
            mark: m,
            want: m != 100,
        })
        .collect();
    b.steps.push(Step::Burst(Burst {
        label: "marks",
        from: Origin::Router,
        dst: Where::Srv(0),
        dgrams,
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters: vec![("r0", 1)],
        ..Default::default()
    }));
    b.finish(format!("expr.mark_range_single_value.{}", f.tag()), "expressions")
}

fn icmp_echo_match(f: Fam) -> &'static str {
    match f {
        Fam::V4 => "icmp type echo-request",
        Fam::V6 => "icmpv6 type echo-request",
    }
}

fn ct_states_text(f: Fam, related: bool) -> String {
    let (t, echo) = (f.table(), icmp_echo_match(f));
    let rel = if related {
        "    ct state related counter accept comment \"rel\"\n"
    } else {
        ""
    };
    let flush = if related { "" } else { "flush ruleset\n" };
    format!(
        r#"{flush}table {t} q {{
  chain count {{
    type filter hook forward priority -10; policy accept;
    ct direction original counter comment "dir-orig"
    ct direction reply counter comment "dir-reply"
    ct state new counter comment "st-new"
    ct state established counter comment "st-est"
    ct state related counter comment "st-rel"
    ct state invalid counter comment "st-inv"
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state invalid counter drop comment "inv-drop"
    ct state established counter accept comment "est"
{rel}    ct state new udp dport 7100-7109 counter accept comment "new-udp"
    ct state new {echo} counter accept comment "ping"
  }}
}}
"#
    )
}

fn ct_states_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let s0 = f.server(0);
    let (c0, c2, c3) = (f.client(0), f.client(2), f.client(3));
    b.sink(Proto::Udp, Bind::Srv(0), 7100);
    b.install("states-a", ct_states_text(f, true));
    let sp_a = b.probe(
        "udp-new-established",
        Origin::Client(0),
        Proto::Udp,
        (Where::Srv(0), 7100),
        Want::at(Proto::Udp, Bind::Srv(0), 7100, c0, PeerPort::Same),
    );
    b.probe(
        "udp-related-icmp-error",
        Origin::Client(1),
        Proto::Udp,
        (Where::Srv(0), 7101),
        Want::Refused,
    );
    b.steps.push(Step::Ping(Ping {
        name: "ping-new-established",
        from: 2,
        dst: Where::Srv(0),
        kind: IcmpKind::EchoRequest,
        answered: true,
    }));
    b.steps.push(Step::Ping(Ping {
        name: "stray-echo-reply-invalid",
        from: 3,
        dst: Where::Srv(0),
        kind: IcmpKind::EchoReply,
        answered: false,
    }));
    let ty = if f == Fam::V4 { "type=8" } else { "type=128" };
    b.snap(
        "a",
        &[
            ("dir-orig", 3),
            ("dir-reply", 3),
            ("st-new", 3),
            ("st-est", 2),
            ("st-rel", 1),
            ("st-inv", 1),
            ("inv-drop", 1),
            ("est", 2),
            ("rel", 1),
            ("new-udp", 2),
            ("ping", 1),
        ],
        vec![
            needles(&[
                "udp".into(),
                orig(c0, sp_a, s0, 7100),
                format!("src={s0} dst={c0} sport=7100 dport={sp_a}"),
            ]),
            needles(&[format!("src={c2}"), format!("dst={s0}"), ty.into()]),
        ],
        vec![vec![format!("src={c3}")]],
    );
    b.install("states-b", ct_states_text(f, false));
    b.probe("udp-related-dropped", Origin::Client(1), Proto::Udp, (Where::Srv(0), 7102), Want::Blocked);
    b.probe(
        "udp-established-again",
        Origin::Client(0),
        Proto::Udp,
        (Where::Srv(0), 7100),
        Want::at(Proto::Udp, Bind::Srv(0), 7100, c0, PeerPort::Same),
    );
    b.steps.push(Step::Ping(Ping {
        name: "stray-echo-reply-invalid-again",
        from: 3,
        dst: Where::Srv(0),
        kind: IcmpKind::EchoReply,
        answered: false,
    }));
    b.steps.push(Step::Snap(SnapSpec {
        label: "b",
        counters: vec![
            ("dir-orig", 2),
            ("dir-reply", 2),
            ("st-new", 2),
            ("st-est", 1),
            ("st-rel", 1),
            ("st-inv", 1),
            ("inv-drop", 1),
            ("est", 1),
            ("new-udp", 2),
        ],
        conntrack: true,
        absent: vec![vec![format!("src={c3}")]],
        lister: true,
        ..Default::default()
    }));
    b.finish(format!("ct.states_related_invalid.{}", f.tag()), "conntrack")
}

fn ct_selectors_text(f: Fam, p: &str, exact: bool) -> String {
    let (t, rc) = (f.table(), f.router_c());
    let (s0, s1, c1) = (f.server(0), f.server(1), f.client(1));
    let dnat = f.hp(s0, 80);
    let n = |name: &str| if exact { name.to_string() } else { format!("~{name}") };
    let (o, r) = (n("orig-sel"), n("reply-sel"));
    format!(
        r#"table {t} q {{
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname "c0" {p} dport {{ 8080, 8082 }} dnat to {dnat}
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct direction original ct original daddr {s1} counter accept comment "never-orig"
    ct direction reply ct reply daddr {c1} counter accept comment "never-reply"
    ct direction original ct original daddr {rc} ct original proto-dst 8080 counter accept comment "{o}"
    ct direction reply ct reply saddr {s0} ct reply proto-src 80 counter accept comment "{r}"
  }}
}}
"#
    )
}

fn ct_selectors_case(f: Fam, proto: Proto) -> Case {
    let p = proto.name();
    let mut b = B::new(f);
    let (rc, c0, s0) = (f.router_c(), f.client(0), f.server(0));
    b.sink(proto, Bind::Srv(0), 80);
    b.install("selectors", ct_selectors_text(f, p, proto == Proto::Udp));
    let sp = b.probe(
        "dnat-8080",
        Origin::Client(0),
        proto,
        (Where::RouterC, 8080),
        Want::at(proto, Bind::Srv(0), 80, c0, PeerPort::Same),
    );
    b.probe(
        "dnat-8082-other-original-port",
        Origin::Client(0),
        proto,
        (Where::RouterC, 8082),
        Want::Blocked,
    );
    b.probe("direct-not-dnat", Origin::Client(0), proto, (Where::Srv(0), 80), Want::Blocked);
    let est = if proto == Proto::Tcp { "ESTABLISHED" } else { p };
    let counters: Vec<(&'static str, u64)> = if proto == Proto::Udp {
        vec![("never-orig", 0), ("never-reply", 0), ("orig-sel", 1), ("reply-sel", 1)]
    } else {
        vec![("never-orig", 0), ("never-reply", 0)]
    };
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters,
        conntrack: true,
        tuples: vec![needles(&[
            est.to_string(),
            orig(c0, sp, rc, 8080),
            format!("src={s0} dst={c0} sport=80 dport={sp}"),
        ])],
        absent: vec![vec!["dport=8082 ".into()]],
        lister: true,
        ..Default::default()
    }));
    b.finish(format!("ct.selectors.{p}.{}", f.tag()), "conntrack")
}

fn ct_mark_forward_text(f: Fam) -> String {
    let t = f.table();
    format!(
        r#"table {t} q {{
  chain pre {{
    type filter hook prerouting priority mangle; policy accept;
    ct mark != 0 meta mark set ct mark counter comment "restore"
    ct state new udp dport 7200 meta mark set 0x77 counter comment "set-meta"
    ct state new udp dport 7200 ct mark set meta mark counter comment "save"
    ct state new udp dport 7202 ct mark set 0x88 counter comment "set-ct"
    ct state new udp dport 7203 ct mark set ct mark and 0xffff0000 or 0x78 counter comment "set-ct-bits"
    ct state new udp dport 7204 ct mark set ct mark and 0xffff0000 or 0x68 counter comment "set-ct-near"
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    meta mark 0x77 ct mark 0x77 counter accept comment "marked"
    ct mark 0x88 counter accept comment "ct88"
    ct mark and 0xfff0 == 0x70 counter accept comment "mask-match"
  }}
}}
"#
    )
}

fn ct_mark_forward_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let c0 = f.client(0);
    for port in 7200..=7204 {
        b.sink(Proto::Udp, Bind::Srv(0), port);
    }
    b.install("mark-forward", ct_mark_forward_text(f));
    let cl = Origin::Client(0);
    let ok = |port| Want::at(Proto::Udp, Bind::Srv(0), port, c0, PeerPort::Same);
    let sp0 = b.probe("meta-to-ct-and-back", cl, Proto::Udp, (Where::Srv(0), 7200), ok(7200));
    b.probe("unmarked-control", cl, Proto::Udp, (Where::Srv(0), 7201), Want::Blocked);
    let sp2 = b.probe("ct-mark-set", cl, Proto::Udp, (Where::Srv(0), 7202), ok(7202));
    let sp3 = b.probe("ct-mark-bitop-match", cl, Proto::Udp, (Where::Srv(0), 7203), ok(7203));
    b.probe("ct-mark-bitop-near-miss", cl, Proto::Udp, (Where::Srv(0), 7204), Want::Blocked);
    let tup = |port: u16, sp: u16, mark: u32| {
        needles(&[
            "udp".into(),
            orig(c0, sp, f.server(0), port),
            format!("mark={mark}"),
        ])
    };
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters: vec![
            ("restore", 3),
            ("set-meta", 1),
            ("save", 1),
            ("set-ct", 1),
            ("set-ct-bits", 1),
            ("set-ct-near", 1),
            ("marked", 2),
            ("ct88", 2),
            ("mask-match", 2),
        ],
        conntrack: true,
        tuples: vec![tup(7200, sp0, 0x77), tup(7202, sp2, 0x88), tup(7203, sp3, 0x78)],
        absent: vec![vec!["dport=7201 ".into()], vec!["dport=7204 ".into()]],
        lister: true,
        ..Default::default()
    }));
    b.finish(format!("ct.mark_propagation_forward.{}", f.tag()), "conntrack")
}

fn ct_mark_local_text(f: Fam, exact: bool) -> String {
    let t = f.table();
    let nd = if f == Fam::V6 {
        "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept\n"
    } else {
        ""
    };
    let n = |name: &str| if exact { name.to_string() } else { format!("~{name}") };
    let (a, r, m) = (n("sock-to-ct"), n("restore"), n("reply-marked"));
    format!(
        r#"table {t} q {{
  chain out {{
    type filter hook output priority filter; policy accept;
    meta mark 0x33 ct mark set meta mark counter comment "{a}"
  }}
  chain pre {{
    type filter hook prerouting priority mangle; policy accept;
    ct mark != 0 meta mark set ct mark counter comment "{r}"
  }}
  chain in {{
    type filter hook input priority filter; policy drop;
{nd}    ct state established ct mark 0x33 meta mark 0x33 counter accept comment "{m}"
  }}
}}
"#
    )
}

fn ct_mark_local_case(f: Fam, proto: Proto) -> Case {
    let p = proto.name();
    let mut b = B::new(f);
    let rs = f.router_s();
    b.sink(proto, Bind::Srv(0), 7210);
    b.install("mark-local", ct_mark_local_text(f, proto == Proto::Udp));
    let router = Origin::Router;
    let dst = (Where::Srv(0), 7210);
    let sp = 43_001u16;
    b.probe_spec(
        "sock-mark-0x33",
        router,
        proto,
        dst,
        (sp, 0x33),
        Want::at(proto, Bind::Srv(0), 7210, rs, PeerPort::Same),
    );
    for (i, (name, mark)) in [("sock-mark-0x34", 0x34u32), ("sock-mark-none", 0)].into_iter().enumerate() {
        let want = if proto == Proto::Udp {
            Want::unanswered(proto, Bind::Srv(0), 7210, rs)
        } else {
            Want::Blocked
        };
        b.probe_spec(name, router, proto, dst, (43_002 + i as u16, mark), want);
    }
    let counters: Vec<(&'static str, u64)> = if proto == Proto::Udp {
        vec![("sock-to-ct", 1), ("restore", 1), ("reply-marked", 1)]
    } else {
        vec![]
    };
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters,
        conntrack: true,
        tuples: vec![needles(&[
            p.to_string(),
            "dport=7210".to_string(),
            format!("sport={sp}"),
            "mark=51".into(),
        ])],
        lister: true,
        ..Default::default()
    }));
    b.finish(format!("ct.mark_propagation_local.{p}.{}", f.tag()), "conntrack")
}

fn ct_zone_text(f: Fam, zone: u16, asym: bool) -> String {
    let t = f.table();
    let flush = if zone == 1 && !asym { "" } else { "flush ruleset\n" };
    let asym_rules = if asym {
        "    udp dport 7302 ct zone set 1 counter comment \"za-orig\"\n    udp sport 7302 ct zone set 2 counter comment \"za-reply\"\n"
    } else {
        ""
    };
    let asym_fwd = if asym {
        "    ct state new ct zone 1 udp dport 7302 counter accept comment \"new-asym\"\n"
    } else {
        ""
    };
    format!(
        r#"{flush}table {t} q {{
  chain raw {{
    type filter hook prerouting priority raw; policy accept;
    udp dport 7300 ct zone set {zone} counter comment "z-orig"
    udp sport 7300 ct zone set {zone} counter comment "z-reply"
{asym_rules}  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state established counter accept comment "est"
    ct state new ct zone {zone} udp dport 7300 counter accept comment "new-z{zone}"
{asym_fwd}  }}
}}
"#
    )
}

fn ct_zone_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let (c0, s0) = (f.client(0), f.server(0));
    b.sink(Proto::Udp, Bind::Srv(0), 7300);
    b.sink(Proto::Udp, Bind::Srv(0), 7302);
    let cl = Origin::Client(0);
    let ok = Want::at(Proto::Udp, Bind::Srv(0), 7300, c0, PeerPort::Same);
    let sp = 44_100u16;
    b.install("zone-1", ct_zone_text(f, 1, false));
    b.probe_spec("zone1-first", cl, Proto::Udp, (Where::Srv(0), 7300), (sp, 0), ok.clone());
    b.probe_spec("zone1-same-flow", cl, Proto::Udp, (Where::Srv(0), 7300), (sp, 0), ok.clone());
    let zt = |z: u16, port: u16, sp: u16| {
        needles(&[
            "udp".into(),
            orig(c0, sp, s0, port),
            format!("zone={z}"),
        ])
    };
    b.snap(
        "z1",
        &[("z-orig", 2), ("z-reply", 2), ("new-z1", 1), ("est", 3)],
        vec![zt(1, 7300, sp)],
        vec![vec![format!("sport={sp} dport=7300"), "zone=2".into()]],
    );
    b.install("zone-2", ct_zone_text(f, 2, true));
    b.probe_spec("zone2-same-tuple", cl, Proto::Udp, (Where::Srv(0), 7300), (sp, 0), ok);
    let sp2 = 44_200u16;
    b.probe_spec(
        "zone-mismatch-reply",
        cl,
        Proto::Udp,
        (Where::Srv(0), 7302),
        (sp2, 0),
        Want::unanswered(Proto::Udp, Bind::Srv(0), 7302, c0),
    );
    b.steps.push(Step::Snap(SnapSpec {
        label: "z2",
        counters: vec![
            ("z-orig", 1),
            ("z-reply", 1),
            ("new-z2", 1),
            ("est", 1),
            ("za-orig", 1),
            ("za-reply", 1),
            ("new-asym", 1),
        ],
        conntrack: true,
        tuples: vec![zt(1, 7300, sp), zt(2, 7300, sp), zt(1, 7302, sp2)],
        absent: vec![vec![format!("sport={sp2} dport=7302"), "zone=2".into()]],
        lister: true,
        ..Default::default()
    }));
    b.finish(format!("ct.zones.{}", f.tag()), "conntrack")
}

fn ct_notrack_text(f: Fam) -> String {
    let t = f.table();
    format!(
        r#"table {t} q {{
  chain raw {{
    type filter hook prerouting priority raw; policy accept;
    iifname "c0" udp dport 7400 counter notrack comment "nt-orig"
    iifname "s0" udp sport 7400 counter notrack comment "nt-reply"
    iifname "c0" udp dport 7402 counter notrack comment "nt-orig-only"
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state untracked counter accept comment "untracked"
    ct state established counter accept comment "est"
    ct state new udp dport 7401 counter accept comment "new7401"
  }}
}}
"#
    )
}

fn ct_notrack_typed(f: Fam) -> Batch {
    let fam = if f == Fam::V4 { Family::Ipv4 } else { Family::Ipv6 };
    let mut b = Batch::new();
    b.add_table(&Table::new(fam, "q"));
    b.add_chain(&Chain::new(fam, "q", "raw").with_hook(ChainType::Filter, Hook::PREROUTING, -300));
    b.add_chain(
        &Chain::new(fam, "q", "forward")
            .with_hook(ChainType::Filter, Hook::FORWARD, 0)
            .with_policy(Policy::Drop),
    );
    let raw = |iif: &str, field: Field, port: u16, name: &str| {
        RuleBuilder::new(fam, "q", "raw")
            .match_eq(Field::IifName, iif)
            .match_eq(field, port)
            .counter()
            .notrack()
            .comment(name)
            .build()
    };
    b.add_rule(&raw("c0", Field::UdpDport, 7400, "nt-orig"));
    b.add_rule(&raw("s0", Field::UdpSport, 7400, "nt-reply"));
    b.add_rule(&raw("c0", Field::UdpDport, 7402, "nt-orig-only"));
    let r = || RuleBuilder::new(fam, "q", "forward");
    b.add_rule(&r().ct_state(NF_CT_STATE_UNTRACKED_BIT).counter().comment("untracked").accept().build());
    b.add_rule(&r().ct_state(NF_CT_STATE_ESTABLISHED_BIT).counter().comment("est").accept().build());
    b.add_rule(
        &r().ct_state(NF_CT_STATE_NEW_BIT)
            .match_eq(Field::UdpDport, 7401u16)
            .counter()
            .comment("new7401")
            .accept()
            .build(),
    );
    b
}

fn ct_notrack_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let c0 = f.client(0);
    for port in 7400..=7403 {
        b.sink(Proto::Udp, Bind::Srv(0), port);
    }
    b.steps.push(Step::Install(Ruleset {
        label: "notrack",
        text: ct_notrack_text(f),
        typed: Some(ct_notrack_typed),
        ok: true,
    }));
    let cl = Origin::Client(0);
    let ok = |port| Want::at(Proto::Udp, Bind::Srv(0), port, c0, PeerPort::Same);
    b.probe("untracked-both-ways", cl, Proto::Udp, (Where::Srv(0), 7400), ok(7400));
    let sp = b.probe("tracked-control", cl, Proto::Udp, (Where::Srv(0), 7401), ok(7401));
    b.probe(
        "untracked-request-tracked-reply",
        cl,
        Proto::Udp,
        (Where::Srv(0), 7402),
        Want::unanswered(Proto::Udp, Bind::Srv(0), 7402, c0),
    );
    b.probe("no-rule-control", cl, Proto::Udp, (Where::Srv(0), 7403), Want::Blocked);
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters: vec![
            ("nt-orig", 1),
            ("nt-reply", 1),
            ("nt-orig-only", 1),
            ("untracked", 3),
            ("est", 1),
            ("new7401", 1),
        ],
        conntrack: true,
        tuples: vec![needles(&["udp".into(), orig(c0, sp, f.server(0), 7401)])],
        absent: vec![
            vec!["dport=7400 ".into()],
            vec!["dport=7402 ".into()],
            vec!["dport=7403 ".into()],
        ],
        lister: true,
        ..Default::default()
    }));
    b.finish(format!("ct.notrack.{}", f.tag()), "conntrack")
}

const CLASS_AA: u16 = 7501;
const CLASS_DA: u16 = 7502;
const CLASS_AD: u16 = 7503;
const CLASS_DD: u16 = 7504;
const UPDATE_OLD_FILL: u16 = 2000;
const UPDATE_NEW_FILL: u16 = 4000;
const UPDATE_ADDRS: u32 = 3000;

fn fill(base: u16, n: u16, suffix: &str) -> String {
    (0..n).map(|i| format!("{}{suffix}", base + i)).collect::<Vec<_>>().join(", ")
}

fn blk_addrs(f: Fam) -> (String, &'static str) {
    let list = (0..UPDATE_ADDRS)
        .map(|i| match f {
            Fam::V4 => format!("10.200.{}.{}", i / 256, i % 256),
            Fam::V6 => format!("fd00:ff::{i:x}"),
        })
        .collect::<Vec<_>>()
        .join(", ");
    (list, if f == Fam::V4 { "ipv4_addr" } else { "ipv6_addr" })
}

fn update_old(f: Fam) -> String {
    let t = f.table();
    let fill_a = fill(20_000, UPDATE_OLD_FILL, "");
    format!(
        r#"table {t} q {{
  set ports {{
    type inet_service
    elements = {{ {CLASS_AA}, {CLASS_AD}, {fill_a} }}
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    udp dport 9999 accept
    udp dport @ports counter accept comment "~old-allow"
  }}
}}
table {t} old {{
  chain oldc {{
    type filter hook forward priority 10; policy accept;
    counter comment "~old-count"
  }}
}}
"#
    )
}

fn update_replace_text(f: Fam) -> String {
    let t = f.table();
    let fill_b = fill(24_000, UPDATE_NEW_FILL, " : accept");
    let (addrs, ty) = blk_addrs(f);
    format!(
        r#"flush ruleset
table {t} q {{
  map pv {{
    type inet_service : verdict
    elements = {{ {CLASS_AA} : accept, {CLASS_DA} : accept, {fill_b} }}
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    udp dport 9999 accept
    udp dport vmap @pv counter comment "~new-vmap"
  }}
}}
table {t} extra {{
  set blk {{
    type {ty}
    elements = {{ {addrs} }}
  }}
  chain pre {{
    type filter hook forward priority -5; policy accept;
    {t} saddr @blk counter drop comment "~blk"
  }}
}}
"#
    )
}

fn update_inplace_text(f: Fam) -> String {
    let t = f.table();
    let fill_b = fill(24_000, UPDATE_NEW_FILL, "");
    let (addrs, ty) = blk_addrs(f);
    format!(
        r#"flush set {t} q ports
add element {t} q ports {{ {CLASS_AA}, {CLASS_DA}, {fill_b} }}
flush chain {t} q forward
add rule {t} q forward udp dport 9999 accept
add rule {t} q forward udp dport @ports counter accept comment "~new-allow"
add rule {t} q forward counter comment "~tail"
delete table {t} old
add table {t} extra
add set {t} extra blk {{ type {ty}; }}
add element {t} extra blk {{ {addrs} }}
add chain {t} extra pre {{ type filter hook forward priority -5; policy accept; }}
add rule {t} extra pre {t} saddr @blk counter drop comment "~blk"
"#
    )
}

fn update_controls(b: &mut B, label: &'static str, old: bool) {
    let mut dgrams = Vec::new();
    for (i, (port, allowed)) in [
        (CLASS_AA, true),
        (CLASS_AD, old),
        (CLASS_DA, !old),
        (CLASS_DD, false),
        (24_000, !old),
        (20_000, old),
    ]
    .into_iter()
    .enumerate()
    {
        dgrams.push(Dgram {
            src: 0,
            sport: 20_000 + i as u16,
            dport: port,
            mark: 0,
            want: allowed,
        });
    }
    b.steps.push(Step::Burst(Burst {
        label,
        from: Origin::Client(0),
        dst: Where::Srv(0),
        dgrams,
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
}

fn mixed_update_case(f: Fam, name: &str, text: String) -> Case {
    let mut b = B::new(f);
    for port in [CLASS_AA, CLASS_DA, CLASS_AD, CLASS_DD, 20_000, 24_000] {
        b.sink_quiet(Proto::Udp, Bind::Srv(0), port);
    }
    b.sinks.push(SinkSpec::fence(Bind::Srv(0), 9999));
    b.install("old", update_old(f));
    update_controls(&mut b, "before", true);
    b.steps.push(Step::Snap(SnapSpec {
        label: "before",
        lister: true,
        ..Default::default()
    }));
    let class = |name, port, old, new| UpdateClass { name, port, old, new };
    b.steps.push(Step::Update(Update {
        policy: Ruleset {
            label: "new",
            text,
            typed: None,
            ok: true,
        },
        classes: vec![
            class("both", CLASS_AA, true, true),
            class("old-only", CLASS_AD, true, false),
            class("new-only", CLASS_DA, false, true),
            class("neither", CLASS_DD, false, false),
        ],
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
    update_controls(&mut b, "after", false);
    b.steps.push(Step::Snap(SnapSpec {
        label: "after",
        lister: true,
        ..Default::default()
    }));
    b.finish(format!("update.{name}.{}", f.tag()), "update")
}

fn query_tables(f: Fam) -> String {
    let t = f.table();
    let (ty, a, b, c) = match f {
        Fam::V4 => ("ipv4_addr", "10.0.0.1", "10.1.0.0/24", "10.0.0.2"),
        Fam::V6 => ("ipv6_addr", "fd00:aa::1", "fd00:ab::/64", "fd00:aa::2"),
    };
    format!(
        "table {t} qs {{\n  set s {{\n    type {ty}\n    flags interval\n    elements = {{ {a}, {b} }}\n  }}\n  map m {{\n    type {ty} : verdict\n    elements = {{ {c} : drop }}\n  }}\n}}\n"
    )
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn query_step(label: &'static str, args: Vec<&'static str>, ok: bool) -> Step {
    Step::Cli(Cli {
        label,
        args,
        files: vec![],
        stdin: None,
        ok,
        stdout: true,
        reference_may_crash: false,
    })
}

fn query_cases(f: Fam) -> Vec<Case> {
    let (t, tag) = (f.table(), f.tag());
    let (inside, point, miss, mapkey) = match f {
        Fam::V4 => ("10.1.0.77", "10.0.0.1", "10.9.0.77", "10.0.0.2"),
        Fam::V6 => ("fd00:ab::77", "fd00:aa::1", "fd00:ac::1", "fd00:aa::2"),
    };
    let get = |label: &'static str, table: &'static str, name: &'static str, key: &'static str, ok: bool| {
        query_step(label, vec!["-j", "get", "element", t, table, name, "{", key, "}"], ok)
    };
    let (inside, point, miss, mapkey) = (leak(inside.into()), leak(point.into()), leak(miss.into()), leak(mapkey.into()));
    let mk = |name: &str, steps: Vec<Step>| {
        update_case_with(f, format!("cli.{name}.{tag}"), "cli", &query_tables(f), steps, Policy2::A, false)
    };
    let describe = |label: &'static str, words: &[&'static str], ok: bool| {
        let mut args = vec!["-j", "describe"];
        args.extend_from_slice(words);
        query_step(label, args, ok)
    };
    let json_get = leak(format!(
        r#"{{"nftables": [{{"flush": {{"ruleset": null}}}}, {{"add": {{"table": {{"family": "{t}", "name": "z"}}}}}}, {{"get": {{"element": {{"family": "{t}", "table": "qs", "name": "s", "elem": {{"set": ["{inside}"]}}}}}}}}]}}"#
    ));
    let json_describe = r#"{"nftables": [{"flush": {"ruleset": null}}, {"add": {"table": {"family": "ip", "name": "z"}}}, {"describe": "tcp dport"}]}"#;
    let mut out = vec![
        mk(
            "json_get_element",
            vec![
                get("get-interval-member", "qs", "s", inside, true),
                get("get-point", "qs", "s", point, true),
                get("get-miss", "qs", "s", miss, false),
                get("get-missing-set", "qs", "nosuchset", point, false),
            ],
        ),
        mk(
            "json_describe",
            vec![
                describe("describe-payload", &["tcp", "dport"], true),
                describe("describe-ct", &["ct", "state"], true),
                describe("describe-ct-mark", &["ct", "mark"], true),
                describe("describe-protocol", &["ip", "protocol"], true),
            ],
        ),
        mk(
            "json_input_get",
            vec![Step::Cli(Cli {
                label: "json-get",
                args: vec!["-j", "-f", "get.json"],
                files: vec![("get.json", json_get.into())],
                stdin: None,
                ok: false,
                stdout: false,
                reference_may_crash: false,
            })],
        ),
        mk(
            "json_input_describe",
            vec![Step::Cli(Cli {
                label: "json-describe",
                args: vec!["-j", "-f", "describe.json"],
                files: vec![("describe.json", json_describe.into())],
                stdin: None,
                ok: false,
                stdout: false,
                reference_may_crash: false,
            })],
        ),
    ];
    let map_element = mk("json_get_map_element", vec![get("get-map-element", "qs", "m", mapkey, true)]);
    let unknown_symbol = mk("json_describe_unknown_symbol", vec![describe("describe-unknown", &["nosuchthing"], true)]);
    let add_get = format!("add element {t} qs s {{ {} }}\nget element {t} qs s {{ {} }}\n", "10.7.0.1", "10.7.0.1");
    let add_get = if f == Fam::V6 { add_get.replace("10.7.0.1", "fd00:ad::1") } else { add_get };
    let get_inside_replacement = mk(
        "get_inside_replacement",
        vec![Step::Cli(Cli {
            label: "add-then-get",
            args: vec!["-f", "ag.nft"],
            files: vec![("ag.nft", add_get)],
            stdin: None,
            ok: false,
            stdout: true,
            reference_may_crash: false,
        })],
    );
    let keyword_chain_name = update_case_with(
        f,
        format!("cli.reject_keyword_chain_name.{tag}"),
        "cli",
        "",
        vec![Step::Cli(Cli {
            label: "keyword-name",
            args: vec!["-f", "kw.nft"],
            files: vec![("kw.nft", format!("add table {t} kw\nadd chain {t} kw fwd\n"))],
            stdin: None,
            ok: false,
            stdout: false,
            reference_may_crash: false,
        })],
        Policy2::A,
        false,
    );
    out.extend([map_element, unknown_symbol, get_inside_replacement, keyword_chain_name]);
    out
}

const PREFIX_SEED: u64 = 0x00c4_ab71;
const PREFIX_GENERATED: usize = 40;
const CONCAT_SEED: u64 = 0x00c4_ab72;
const CONCAT_GENERATED: usize = 14;

impl Lcg {
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn width_of(f: Fam) -> u32 {
    if f == Fam::V4 { 32 } else { 128 }
}

fn width_mask(width: u32) -> u128 {
    if width == 128 { u128::MAX } else { (1u128 << width) - 1 }
}

fn prefix_mask(width: u32, len: u32) -> u128 {
    width_mask(width) & !width_mask(width - len)
}

fn num_addr(f: Fam, n: u128) -> IpAddr {
    match f {
        Fam::V4 => std::net::Ipv4Addr::from(n as u32).into(),
        Fam::V6 => std::net::Ipv6Addr::from(n).into(),
    }
}

fn boundary_len(r: &mut Lcg, width: u32) -> u32 {
    let marks: &[u32] = if width == 32 {
        &[1, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 32]
    } else {
        &[1, 8, 16, 31, 32, 33, 48, 63, 64, 65, 96, 120, 127, 128]
    };
    if r.below(2) == 0 {
        marks[r.below(marks.len() as u64) as usize]
    } else {
        1 + r.below(width as u64) as u32
    }
}

fn prefix_generated_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let (t, width) = (f.table(), width_of(f));
    let mut r = Lcg(PREFIX_SEED);
    let mut rules = String::new();
    let mut ports: Vec<u16> = Vec::new();
    let mut matchers: Vec<Box<dyn Fn(u128) -> bool>> = Vec::new();
    for i in 0..PREFIX_GENERATED {
        let len = boundary_len(&mut r, width);
        let mut a = addr_num(f.client(r.below(4) as usize));
        if r.below(2) == 0 {
            a ^= 1u128 << (width - 1 - r.below(len as u64) as u32);
        }
        let net = a & prefix_mask(width, len);
        let port = 8000 + i as u16;
        rules.push_str(&format!(
            "    udp dport {port} {t} saddr {}/{len} counter drop comment \"g{i}\"\n",
            num_addr(f, net)
        ));
        ports.push(port);
        matchers.push(Box::new(move |s| s & prefix_mask(width, len) == net));
    }
    let mut ranges: Vec<(u128, u128)> = Vec::new();
    for k in 0..4 {
        let c = addr_num(f.client(k));
        let (lo, hi) = match r.below(4) {
            0 => continue,
            1 => (c - r.below(4) as u128, c + r.below(4) as u128),
            2 => (c + 1, c + 1 + r.below(4) as u128),
            _ => (c - 1 - r.below(4) as u128, c - 1),
        };
        ranges.push((lo, hi));
    }
    ranges.sort();
    let mut kept: Vec<(u128, u128)> = Vec::new();
    for rg in ranges {
        if kept.last().is_none_or(|l| rg.0 > l.1 + 1) {
            kept.push(rg);
        }
    }
    let elems = kept
        .iter()
        .map(|(lo, hi)| {
            if lo == hi {
                num_addr(f, *lo).to_string()
            } else {
                format!("{}-{}", num_addr(f, *lo), num_addr(f, *hi))
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let set_port = 8000 + PREFIX_GENERATED as u16;
    rules.push_str(&format!(
        "    udp dport {set_port} {t} saddr @blk counter drop comment \"g{PREFIX_GENERATED}\"\n"
    ));
    ports.push(set_port);
    let kept2 = kept.clone();
    matchers.push(Box::new(move |s| kept2.iter().any(|(lo, hi)| (*lo..=*hi).contains(&s))));
    let set_ty = if f == Fam::V6 { "ipv6_addr" } else { "ipv4_addr" };
    b.install(
        "prefix-generated",
        format!(
            "table {t} q {{\n  set blk {{\n    type {set_ty}\n    flags interval\n    elements = {{ {elems} }}\n  }}\n  chain forward {{\n    type filter hook forward priority filter; policy accept;\n    udp dport 9999 accept\n{rules}  }}\n}}\n"
        ),
    );
    let mut dgrams = Vec::new();
    let mut counts = vec![0u64; ports.len()];
    for (pi, port) in ports.iter().enumerate() {
        b.sink_quiet(Proto::Udp, Bind::Srv(0), *port);
        for src in 0..4 {
            let dropped = matchers[pi](addr_num(f.client(src)));
            counts[pi] += dropped as u64;
            dgrams.push(Dgram {
                src,
                sport: 20_000 + dgrams.len() as u16,
                dport: *port,
                mark: 0,
                want: !dropped,
            });
        }
    }
    b.sinks.push(SinkSpec::fence(Bind::Srv(0), 9999));
    b.steps.push(Step::Burst(Burst {
        label: "sources",
        from: Origin::Client(0),
        dst: Where::Srv(0),
        dgrams,
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
    let names: Vec<&'static str> = (0..ports.len()).map(|i| leak(format!("g{i}"))).collect();
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        counters: names.into_iter().zip(counts).collect(),
        lister: true,
        ..Default::default()
    }));
    let mut c = b.finish(format!("expr.prefix_generated.{}", f.tag()), "expressions");
    c.generated = Some((PREFIX_SEED, PREFIX_GENERATED + 1));
    c
}

const PORT_MASKS: [u16; 10] = [
    0xff00, 0xfff0, 0x0ff0, 0xf0f0, 0x00ff, 0xffff, 0xfffc, 0x8000, 0xff0f, 0xfffe,
];

fn concat_generated_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let (t, width) = (f.table(), width_of(f));
    let mut r = Lcg(CONCAT_SEED);
    let mut rules = String::new();
    let mut keys: Vec<(u128, u128, u16, u16)> = Vec::new();
    let mut ports: Vec<u16> = Vec::new();
    for _ in 0..CONCAT_GENERATED {
        let len = boundary_len(&mut r, width).min(width - 1);
        let amask = prefix_mask(width, len);
        let pmask = PORT_MASKS[r.below(PORT_MASKS.len() as u64) as usize];
        let base = 12_000 + r.below(3000) as u16;
        let key_addr = addr_num(f.client(r.below(4) as usize)) & amask;
        let key_port = base & pmask;
        rules.push_str(&format!(
            "    {t} saddr and {} . udp dport and {pmask:#x} vmap {{ {} . {key_port} : drop }}\n",
            num_addr(f, amask),
            num_addr(f, key_addr)
        ));
        keys.push((amask, key_addr, pmask, key_port));
        let inside = (0..16).find(|k| pmask & (1 << k) != 0).map(|k| 1u16 << k).unwrap_or(0);
        let outside = (0..16).find(|k| pmask & (1 << k) == 0).map(|k| 1u16 << k);
        let mut cands = vec![base, key_port, base.wrapping_add(1), base.wrapping_sub(1), base ^ inside];
        if let Some(o) = outside {
            cands.push(base ^ o);
            cands.push(key_port | o);
        }
        ports.extend(cands);
    }
    ports.retain(|p| *p != 9999);
    ports.sort();
    ports.dedup();
    b.install(
        "concat-generated",
        format!(
            "table {t} q {{\n  chain forward {{\n    type filter hook forward priority filter; policy accept;\n    udp dport 9999 accept\n{rules}  }}\n}}\n"
        ),
    );
    let mut dgrams = Vec::new();
    for port in &ports {
        b.sink_quiet(Proto::Udp, Bind::Srv(0), *port);
        for src in 0..4 {
            let s = addr_num(f.client(src));
            let dropped = keys
                .iter()
                .any(|(am, ka, pm, kp)| s & am == *ka && port & pm == *kp);
            dgrams.push(Dgram {
                src,
                sport: 20_000 + dgrams.len() as u16,
                dport: *port,
                mark: 0,
                want: !dropped,
            });
        }
    }
    b.sinks.push(SinkSpec::fence(Bind::Srv(0), 9999));
    b.steps.push(Step::Burst(Burst {
        label: "keys",
        from: Origin::Client(0),
        dst: Where::Srv(0),
        dgrams,
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        lister: true,
        ..Default::default()
    }));
    let mut c = b.finish(format!("expr.concat_generated.{}", f.tag()), "expressions");
    c.generated = Some((CONCAT_SEED, CONCAT_GENERATED));
    c
}

fn concat_full_width_case(f: Fam) -> Case {
    let mut b = B::new(f);
    let t = f.table();
    let key = f.client(1);
    let mask = num_addr(f, width_mask(width_of(f)));
    b.install(
        "concat-full-width",
        format!(
            "table {t} q {{\n  chain forward {{\n    type filter hook forward priority filter; policy accept;\n    udp dport 9999 accept\n    {t} saddr and {mask} . udp dport and 0xfff0 vmap {{ {key} . 12320 : drop }}\n  }}\n}}\n"
        ),
    );
    let mut dgrams = Vec::new();
    for port in [12321u16, 12336] {
        b.sink_quiet(Proto::Udp, Bind::Srv(0), port);
    }
    for (port, src) in [(12321u16, 1usize), (12321, 0), (12336, 1)] {
        dgrams.push(Dgram {
            src,
            sport: 20_000 + dgrams.len() as u16,
            dport: port,
            mark: 0,
            want: !(src == 1 && port == 12321),
        });
    }
    b.sinks.push(SinkSpec::fence(Bind::Srv(0), 9999));
    b.steps.push(Step::Burst(Burst {
        label: "keys",
        from: Origin::Client(0),
        dst: Where::Srv(0),
        dgrams,
        fence: sink_name(Proto::Udp, Bind::Srv(0), 9999),
        fence_port: 9999,
    }));
    b.steps.push(Step::Snap(SnapSpec {
        label: "end",
        lister: true,
        ..Default::default()
    }));
    b.finish(format!("expr.concat_full_width_mask.{}", f.tag()), "expressions")
}

fn all_cases() -> Vec<Case> {
    let mut v = Vec::new();
    for f in [Fam::V4, Fam::V6] {
        v.push(concat_case(f));
        v.push(concat_udp_case(f));
        v.push(jump_case(f));
        v.push(prefix_case(f));
        v.push(mark_case(f));
        v.push(prefix_generated_case(f));
        v.push(concat_generated_case(f));
        v.push(concat_full_width_case(f));
        v.push(single_mark_case(f));
        v.push(nat_case(f, Proto::Tcp));
        v.push(nat_case(f, Proto::Udp));
        v.push(nat_typed_case(f));
        v.push(nat_map_case(f));
        v.push(listing_case(f));
        v.push(stateful_case(f));
        v.extend(rejected_cases(f));
        v.extend(cli_cases(f));
        v.extend(query_cases(f));
        v.push(mixed_update_case(f, "mixed_replace", update_replace_text(f)));
        v.push(mixed_update_case(f, "mixed_inplace", update_inplace_text(f)));
        v.push(ct_states_case(f));
        v.push(ct_selectors_case(f, Proto::Udp));
        v.push(ct_selectors_case(f, Proto::Tcp));
        v.push(ct_mark_forward_case(f));
        v.push(ct_mark_local_case(f, Proto::Udp));
        v.push(ct_mark_local_case(f, Proto::Tcp));
        v.push(ct_zone_case(f));
        v.push(ct_notrack_case(f));
    }
    v
}

fn evidence_path() -> std::path::PathBuf {
    match std::env::var_os("QUALIFY_EVIDENCE") {
        Some(p) => p.into(),
        None => std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(".work")
            .join("qualify-evidence.json"),
    }
}

fn parallel(cases: &[Case], fault: Option<Fault>, filter: &[String]) -> Vec<CaseResult> {
    let queue = Mutex::new((0..cases.len()).collect::<Vec<_>>());
    let results: Mutex<Vec<Option<CaseResult>>> = Mutex::new((0..cases.len()).map(|_| None).collect());
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get()).min(8);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let Some(i) = queue.lock().unwrap().pop() else {
                        break;
                    };
                    let c = &cases[i];
                    let r = if !filter.is_empty() && !filter.iter().any(|f| c.id.contains(f.as_str())) {
                        skipped(c, "excluded by QUALIFY_FILTER")
                    } else {
                        run_case(c, fault, &format!("{i}"))
                    };
                    results.lock().unwrap()[i] = Some(r);
                }
            });
        }
    });
    results.into_inner().unwrap().into_iter().map(|r| r.unwrap()).collect()
}

#[test]
fn qualification() {
    let cases = all_cases();
    let fault = std::env::var("QUALIFY_FAULT").ok().map(|s| {
        Fault::parse(&s).unwrap_or_else(|| panic!("unknown QUALIFY_FAULT {s}"))
    });
    let filter: Vec<String> = std::env::var("QUALIFY_FILTER")
        .map(|s| s.split(',').map(|x| x.to_string()).collect())
        .unwrap_or_default();
    let strict = std::env::var("QUALIFY_STRICT").is_ok_and(|v| v == "1");
    let results = parallel(&cases, fault, &filter);
    let required: Vec<(&str, Fam)> = ["expressions", "nat", "stateful", "rejected", "cli", "conntrack", "update"]
        .into_iter()
        .flat_map(|r| [(r, Fam::V4), (r, Fam::V6)])
        .collect();
    let complete = filter.is_empty() && fault.is_none();
    let (json, qualified, unmet) = evidence_json(&results, &required, &[("mark_ranges", MARK_SEED), ("prefix_generated", PREFIX_SEED), ("concat_generated", CONCAT_SEED)], complete);
    let path = evidence_path();
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    std::fs::write(&path, &json).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    let mut bad = Vec::new();
    for r in &results {
        println!("{:<17} {:<44} {} ms", r.status.name(), r.id, r.ms);
        if matches!(r.status, Status::Failed | Status::KnownDivergence | Status::Intentional) {
            let d = r.detail.join("\n");
            println!("{}\n", d.lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n"));
        }
        if r.status == Status::Failed || (r.status == Status::Skipped && filter.is_empty()) {
            bad.push(r.id.clone());
        }
    }
    println!(
        "QUALIFICATION {} (evidence {}): {} cases, unmet rows: {:?}",
        if qualified { "QUALIFIED" } else { "NOT QUALIFIED" },
        path.display(),
        results.len(),
        unmet
    );
    assert!(bad.is_empty(), "failed or skipped cases: {bad:?}");
    if strict {
        assert!(qualified, "profile is not qualified: {unmet:?}");
    }
}

#[test]
fn harness_detects_faults() {
    let cases = all_cases();
    let find = |id: &str| cases.iter().find(|c| c.id == id).unwrap_or_else(|| panic!("no case {id}")).clone();
    let probes: [(Fault, &str, &str); 8] = [
        (Fault::DropNat, "nat.tcp.v4", "probe dnat"),
        (Fault::DropNat, "nat.udp.v6", "probe masq"),
        (Fault::UnmaskConcat, "expr.concat_vmap.v4", "probe masked-port-key"),
        (Fault::SplitReplace, "stateful.replace.v4", "canary-within-budget=false"),
        (Fault::SplitReplace, "update.mixed_replace.v4", "consistent=false"),
        (Fault::DropCt, "ct.notrack.v4", "probe untracked-both-ways"),
        (Fault::DropCt, "ct.mark_propagation_forward.v6", "probe meta-to-ct-and-back"),
        (Fault::DropCt, "ct.zones.v4", "snap z1"),
    ];
    for (i, (fault, id, expect)) in probes.into_iter().enumerate() {
        let r = run_case(&find(id), Some(fault), &format!("fault{i}"));
        let detail = r.detail.join("\n");
        assert_eq!(r.status, Status::Failed, "{fault:?} on {id} was not detected:\n{detail}");
        assert!(
            !r.detail.iter().any(|d| d.starts_with("reference:")),
            "{fault:?} on {id}: the reference world failed:\n{detail}"
        );
        assert!(detail.contains(expect), "{fault:?} on {id}: expected {expect:?} in\n{detail}");
    }
}

fn synthetic(id: &str, status: Status, marker: Marker) -> CaseResult {
    CaseResult {
        id: id.into(),
        row: "row",
        fam: Fam::V4,
        status,
        detail: vec!["difference text".into()],
        fronts: vec!["nft", "nfcrt"],
        reference: Vec::new(),
        ms: 0,
        marker,
        generated: None,
        notes: Vec::new(),
    }
}

const WHY: &str = "nft evaluates this command against a cache that exists in neither the old nor the new ruleset, so nfcrt deliberately reports the committed state";

#[test]
fn intentional_differences_do_not_block_but_others_do() {
    let required = [("row", Fam::V4)];
    let eval = |extra: CaseResult| {
        let rs = vec![synthetic("a", Status::Passed, Marker::None), extra];
        evidence_json(&rs, &required, &[], true)
    };
    let (json, qualified, unmet) = eval(synthetic("b", Status::Intentional, Marker::Intentional(WHY)));
    assert!(qualified, "intentional difference blocked qualification: {unmet:?}");
    assert!(json.contains("\"qualified\":true") && json.contains("\"intentional\":1"));
    assert!(json.contains("\"intentional_differences\":[{\"id\":\"b\"") && json.contains(&format!("\"justification\":\"{WHY}\"")));
    assert!(json.contains("\"known_divergences\":[]"));
    for (status, marker) in [
        (Status::KnownDivergence, Marker::Known("tracked")),
        (Status::Skipped, Marker::None),
        (Status::Failed, Marker::None),
    ] {
        let (json, qualified, unmet) = eval(synthetic("b", status, marker));
        assert!(!qualified && !unmet.is_empty(), "{status:?} must block qualification");
        assert!(json.contains("\"qualified\":false"));
    }
    let rs = vec![synthetic("a", Status::Intentional, Marker::Intentional(WHY))];
    assert!(!evidence_json(&rs, &required, &[], false).1, "an incomplete run cannot qualify");
    assert!(!evidence_json(&rs, &[("row", Fam::V6)], &[], true).1, "a required row without cases cannot qualify");
}

#[test]
fn markers_are_justified_and_exclusive() {
    assert!(!Marker::Intentional("").justified());
    assert!(!Marker::Intentional("short").justified());
    assert!(!Marker::Intentional(leak(" ".repeat(200))).justified());
    assert!(Marker::Intentional(WHY).justified());
    assert!(Marker::Known("").justified());
    let cases = all_cases();
    let intentional: Vec<&str> = cases
        .iter()
        .filter(|c| c.marker.intentional().is_some())
        .map(|c| c.id.as_str())
        .collect();
    assert!(!intentional.is_empty());
    for c in &cases {
        assert!(c.marker.justified(), "{} has an unjustified marker", c.id);
        if let Marker::Known(n) = c.marker {
            assert!(n.starts_with("CRAB-7-D"), "{}: known divergences carry their id", c.id);
        }
    }
    let mut ids: Vec<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    ids.sort();
    let n = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), n, "duplicate case ids");
}
