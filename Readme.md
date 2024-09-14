# solana-hmac-sha256
A simple implementation of HMAC Sha256 using `solana-nostd-sha256`

### Usage
To emulate the digest functionality of the `hmac` crate, use `HmacSha256`:

```rs
let mut h = HmacSha256::new(b"test");
h.update(b"test");
h.finalize(); // -> outputs [u8;32]
```

This is most useful for chaining hashes together.

To quickly produce a single hmac-sha256 hash, use the `hmac_sha256` function:

```rs
let h = hmac_sha256(b"test", b"test"); // -> [u8;32]
```