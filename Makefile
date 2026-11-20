.PHONY: test lint clean bench bench-list bench-check

test:
	python3 -B -m unittest discover -s tests -p test_bench.py
	cargo test --workspace --all-features --locked $(CARGO_TEST_FLAGS)

lint:
	cargo clippy --workspace --all-targets --locked

bench:
	python3 scripts/bench.py run $(BENCH_ARGS)

bench-list:
	python3 scripts/bench.py list

bench-check:
	python3 scripts/bench.py check $(BENCH_ARGS)

clean:
	find . -path './.git' -prune -o -path './.work' -prune -o -name target -type d -prune -exec rm -rf {} +
