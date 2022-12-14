#!/bin/bash
# Prerequisites
# 1. You need LLVM-COV tools:
# $ rustup component add llvm-tools-preview
# 2. and Rust wrappers for llvm-cov:
# $ cargo install cargo-binutils
# 3. The rust name demangler
# $ cargo install rustfilt
# 4. jq
# 5. genhtml
# $ sudo apt install lcov

RUSTFLAGS="-C instrument-coverage"
LLVM_PROFILE_FILE="./cov_raw/bulletproofs-plus-%m.profraw"

get_binaries() {
  files=$( RUSTFLAGS=$RUSTFLAGS cargo +nightly test --tests --no-run --message-format=json \
              | jq -r "select(.profile.test == true) | .filenames[]" \
              | grep -v dSYM - \
        );
  files=("${files[@]/#/-object }")
}

get_binaries

# Remove old coverage files
rm cov_raw/*profraw cov_raw/bulletproofs-plus.profdata cov_raw/bulletproofs-plus.lcov cov_raw/bulletproofs-plus.txt

RUSTFLAGS=$RUSTFLAGS LLVM_PROFILE_FILE=$LLVM_PROFILE_FILE cargo +nightly test --tests

cargo +nightly profdata -- \
  merge -sparse ./cov_raw/bulletproofs-plus-*.profraw -o ./cov_raw/bulletproofs-plus.profdata

cargo +nightly cov -- \
  export \
    --Xdemangler=rustfilt \
    --format=lcov \
    --show-branch-summary \
    --show-instantiation-summary \
    --show-region-summary \
    --ignore-filename-regex='/.cargo/registry' \
    --ignore-filename-regex="^/rustc" \
    --ignore-filename-regex="curve25519-dalek" \
    --instr-profile=cov_raw/bulletproofs-plus.profdata \
    $files \
    > cov_raw/bulletproofs-plus.lcov

cargo +nightly cov -- \
  show \
    --Xdemangler=rustfilt \
    --show-branch-summary \
    --show-instantiation-summary \
    --show-region-summary \
    --ignore-filename-regex='/.cargo/registry' \
    --ignore-filename-regex="^/rustc" \
    --ignore-filename-regex="curve25519-dalek" \
  --instr-profile=cov_raw/bulletproofs-plus.profdata \
    $files \
    > cov_raw/bulletproofs-plus.txt

if [ -z ${SKIP_HTML+x} ]; then
  genhtml -o coverage_report cov_raw/bulletproofs-plus.lcov
else
  echo "Skipping html generation"
fi
# open coverage_report/src/index.html