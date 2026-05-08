# Solana NoStd HMAC-SHA256

[![CI](https://github.com/blueshift-gg/solana-hmac-sha256/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-hmac-sha256/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/solana-hmac-sha256.svg)](https://crates.io/crates/solana-hmac-sha256)
[![docs.rs](https://docs.rs/solana-hmac-sha256/badge.svg)](https://docs.rs/solana-hmac-sha256)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/blueshift-gg/solana-hmac-sha256/blob/master/LICENSE)

A more efficient, `no_std` HMAC-SHA-256 for the Solana SVM. Built on [`solana-nostd-sha256`](https://crates.io/crates/solana-nostd-sha256), so every internal hash routes through the `sol_sha256` syscall on-chain and falls through to the `sha2` crate off-chain — the same API works in host code (tests, off-chain tooling).

## Quick start

```toml
[dependencies]
solana-hmac-sha256 = "0.3.0"
```

```rust
use solana_hmac_sha256::hmac_sha256;

let mac = hmac_sha256(b"key", b"message"); // -> [u8; 32]
```

The library is `#![no_std]`-clean for SBPF; no allocator setup required.

## Static syscalls

If your target supports the Upstream BPF / sBPFv3 static-syscall ABI, enable the `static-syscalls` feature. It transparently forwards to [`solana-nostd-sha256/static-syscalls`](https://crates.io/crates/solana-nostd-sha256), so the SBPF program calls `sol_sha256` directly instead of going through an `extern "C"` PLT relocation.

```toml
[dependencies]
solana-hmac-sha256 = { version = "0.3.0", features = ["static-syscalls"] }
```

## Benchmarks

On-chain compute unit cost per operation (4-byte key, 4-byte message — the bulk of the cost is the two `sol_sha256` syscalls and the SBPF entrypoint wrapper):

| function       | CU cost |
|----------------|--------:|
| `hmac_sha256`  |    1428 |

To reproduce, install `cargo build-sbf` (Solana CLI) and run:

```sh
cargo test --test sbpf --jobs 1
```

The benchmark compiles the function into its own SBPF program and runs it through [Mollusk](https://github.com/anza-xyz/mollusk) via [`svm-unit-test`](https://crates.io/crates/svm-unit-test).

## License

Licensed under the [MIT License](https://github.com/blueshift-gg/solana-hmac-sha256/blob/master/LICENSE). The license includes the standard "as-is" warranty disclaimer — use at your own risk.
