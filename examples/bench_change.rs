use std::time::Instant;
use crabtables::*;

fn main() {
    let mut socket = Socket::new().expect("open netfilter socket");
    let mut batch = Batch::new();
    batch.add_table(&Table::new(Family::Inet, "bench_change"));
    batch.add_chain(&Chain::new(Family::Inet, "bench_change", "input"));
    for port in 0..1000u16 {
        batch.add_rule(&RuleBuilder::new(Family::Inet, "bench_change", "input")
            .match_eq(Field::TcpDport, port).counter().accept().build());
    }
    let started = Instant::now();
    socket.commit(&batch).expect("commit benchmark batch");
    let elapsed = started.elapsed();
    let rules = socket.list_rules(Family::Inet, Some("bench_change"), Some("input"))
        .expect("list benchmark rules");
    assert_eq!(rules.len(), 1000, "completed rule count");
    let mut cleanup = Batch::new();
    cleanup.delete_table(Family::Inet, "bench_change");
    socket.commit(&cleanup).expect("delete benchmark table");
    println!("rules=1000 commit_ms={:.3}", elapsed.as_secs_f64() * 1000.0);
}
