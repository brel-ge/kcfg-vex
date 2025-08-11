default: build

build:
  cargo build

release:
  cargo build --release

test:
  cargo test

clippy:
   cargo clippy --all-targets --all-features -- -D warnings

# Debug test targets
test-debug:
  RUST_BACKTRACE=1 cargo test -- --nocapture

test-debug-verbose:
  RUST_BACKTRACE=full RUST_LOG=debug cargo test -- --nocapture

debug-build-tests:
  cargo test --no-run
