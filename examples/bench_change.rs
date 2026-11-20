use std::time::Instant;
use crabtables::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut socket = Socket::new()?;
    let mut batch = Batch::new();
    batch.add_table(&Table::new(Family::Inet, "bench_change"));
    batch.add_chain(&Chain::new(Family::Inet, "bench_change", "input"));
    for port in 0..1000u16 {
        batch.add_rule(&RuleBuilder::new(Family::Inet, "bench_change", "input")
            .match_eq(Field::TcpDport, port).counter().accept().build());
    }
    let started = Instant::now();
    socket.commit(&batch)?;
    let elapsed = started.elapsed();
    let rules = socket.list_rules(Family::Inet, Some("bench_change"), Some("input"))?;
    assert_eq!(rules.len(), 1000, "completed rule count");
    let mut cleanup = Batch::new();
    cleanup.delete_table(Family::Inet, "bench_change");
    socket.commit(&cleanup)?;
    println!("rules=1000 commit_ms={:.3}", elapsed.as_secs_f64() * 1000.0);
    Ok(())
}
