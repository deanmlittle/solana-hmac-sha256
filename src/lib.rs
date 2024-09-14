use solana_nostd_sha256::{hashv, HASH_LENGTH};

/// # HmacSha256
/// 
/// Creates an HMAC with an updatable digest similar to how the standard `hmac` library works but using the raw Solana Sha256 syscall under the hood.
#[derive(Clone, Debug)]
pub struct HmacSha256 {
    outer_key_pad: [u8; 64],
    inner_key_pad: [u8; 64],
    digest: Vec<u8>,
}

const BLOCK_SIZE: usize = 64;

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; BLOCK_SIZE];

        if key.len() > BLOCK_SIZE {
            let hashed_key = hashv(&[key]);
            key_block[..HASH_LENGTH].copy_from_slice(&hashed_key);
            for i in HASH_LENGTH..BLOCK_SIZE {
                key_block[i] = 0;
            }
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut inner_key_pad = [0u8; BLOCK_SIZE];
        let mut outer_key_pad = [0u8; BLOCK_SIZE];

        for i in 0..BLOCK_SIZE {
            inner_key_pad[i] = key_block[i] ^ 0x36;
            outer_key_pad[i] = key_block[i] ^ 0x5C;
        }

        let digest = inner_key_pad.to_vec();

        Self {
            digest,
            outer_key_pad,
            inner_key_pad,
        }
    }

    #[inline(always)]
    pub fn update(&mut self, data: &[u8]) {
        self.digest.extend_from_slice(data);
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        self.digest.clear();
        self.digest.extend_from_slice(&self.inner_key_pad);
    }

    pub fn finalize(&self) -> [u8; 32] {
        let inner_hash = hashv(&[&self.digest]);
        hashv(&[&self.outer_key_pad, &inner_hash])
    }

    pub fn finalize_reset(&mut self) -> [u8; 32] {
        let result = self.finalize();
        self.reset();
        result
    }
}

/// #hmac_sha256
/// 
/// Quickly create a single hmac_sha256 hash
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let hashed_key = hashv(&[key]);
        key_block[..HASH_LENGTH].copy_from_slice(&hashed_key);
        for i in HASH_LENGTH..BLOCK_SIZE {
            key_block[i] = 0;
        }
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
    use crate::{hmac_sha256, HmacSha256};

    const HASH_TEST_TEST: [u8;32] = [0x88, 0xcd, 0x21, 0x08, 0xb5, 0x34, 0x7d, 0x97, 0x3c, 0xf3, 0x9c, 0xdf, 0x90, 0x53, 0xd7, 0xdd, 0x42, 0x70, 0x48, 0x76, 0xd8, 0xc9, 0xa9, 0xbd, 0x8e, 0x2d, 0x16, 0x82, 0x59, 0xd3, 0xdd, 0xf7];

    #[test]
    fn hmac_sha256_test() {
        let h = hmac_sha256(b"test", b"test");
        assert_eq!(h, HASH_TEST_TEST)
    }

    #[test]
    fn hmac_sha256_digest_type(){
        let mut h = HmacSha256::new(b"test");
        h.update(b"test");
        assert_eq!(h.finalize(), HASH_TEST_TEST)
    }

}