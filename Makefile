.PHONY: test test-ci test-harness lint clean bench bench-list bench-check

test: test-harness
	cargo test --workspace --all-features --locked --lib --bins -- \
	    --skip asynchronous::tests::faulty_responses --skip socket::tests::faulty_responses

test-harness:
	python3 -B -m unittest discover -s tests -p test_bench.py

test-ci: test-harness
	cargo test --workspace --all-features --locked $(CARGO_TEST_FLAGS)
	python3 scripts/check-constants.py

lint:
	cargo clippy --workspace --all-targets --locked

bench:
	python3 scripts/bench.py run $(BENCH_ARGS)

bench-list:
	python3 scripts/bench.py list

bench-check:
	python3 scripts/bench.py check $(BENCH_ARGS)

clean:
	@if test -L ./target || { test -e ./target && ! test -d ./target; }; then \
	  printf '%s\n' 'make clean: ./target must be a local build directory' >&2; exit 1; \
	fi
	rm -rf -- ./target
