# Benchmark workloads

`make bench-list` lists the workloads. `make bench` runs the Change tier by default.
Pass selectors through `BENCH_ARGS`, for example:

```sh
make bench BENCH_ARGS='--tier edit'
make bench-check BENCH_ARGS='--tier change --workload transaction'
make bench BENCH_ARGS='--tier change --workload transaction --dry-run'
```

Edit checks the selector and needs Python 3. Change commits 1,000 rules and verifies the
result count in a new network namespace. Build it with `cargo build --release --example
bench_change`. Change needs Linux, root, `CAP_NET_ADMIN`, and `unshare`. The measured
transaction excludes construction, listing, and cleanup. The local observed run took
less than a second after building; host load can change that cost.

The upstream benchmark compares loading and listing large sets and rules, and single
transactions across five frontends. It also needs nft, libnftables, and a release `nfcrt`
binary. Build it with `cargo build --release --features lang --example bench` and
`cargo build --release -p nfcrt`. Run it only when explicitly requested with
`make bench BENCH_ARGS='--tier full --workload upstream'`. Full is never selected by
the default tier. Its cost is unmeasured in this fork.

Use `--workload` to select names, `--area` to select an area, and `--skip` to exclude a
name. Repeat `--workload` or `--skip` for multiple names. Unknown or empty selections
fail. `make bench-check` checks prerequisites before workloads run. `--dry-run` prints
the commands without checking prerequisites or writing results.

Runs write logs and a summary under `.work/bench/`. A completed run is not a performance
verdict. The summary marks host readiness unestablished; use a quiet host or paired
busy-host evidence before comparing results. Packet throughput, tail latency, CPU and
memory attribution remain unmeasured; see CRAB-19.
