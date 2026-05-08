//! A more efficient, no_std HMAC-SHA-256 for the Solana SVM.
//!
//! Built on top of [`solana_nostd_sha256`], so on `target_os = "solana"`
//! every internal hash routes through the `sol_sha256` syscall. Off-Solana
//! it falls through to the `sha2` crate, so the same API works in host
//! code (tests, off-chain tooling).
#![no_std]

use solana_nostd_sha256::{HASH_LENGTH, hashv};

const BLOCK_SIZE: usize = 64;

/// One-shot HMAC-SHA-256.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HASH_LENGTH] {
    let mut key_block = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let hashed_key = hashv(&[key]);
        key_block[..HASH_LENGTH].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_key_pad = [0u8; BLOCK_SIZE];
    let mut outer_key_pad = [0u8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        inner_key_pad[i] = key_block[i] ^ 0x36;
        outer_key_pad[i] = key_block[i] ^ 0x5C;
    }

    let inner_hash = hashv(&[&inner_key_pad, message]);
    hashv(&[&outer_key_pad, &inner_hash])
}

#[cfg(test)]
mod tests {
    use crate::hmac_sha256;

    #[test]
    fn hmac_sha256_test() {
        let h = hmac_sha256(b"test", b"test");
        assert_eq!(
            h,
            [
                0x88, 0xcd, 0x21, 0x08, 0xb5, 0x34, 0x7d, 0x97, 0x3c, 0xf3, 0x9c, 0xdf, 0x90, 0x53,
                0xd7, 0xdd, 0x42, 0x70, 0x48, 0x76, 0xd8, 0xc9, 0xa9, 0xbd, 0x8e, 0x2d, 0x16, 0x82,
                0x59, 0xd3, 0xdd, 0xf7,
            ]
        )
    }
}
