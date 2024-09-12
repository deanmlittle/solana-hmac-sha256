use core::ptr;
use solana_nostd_sha256::{hashv, HASH_LENGTH};

const BLOCK_SIZE: usize = 64;

pub fn hash(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; BLOCK_SIZE];

    unsafe {
        if key.len() > BLOCK_SIZE {
            // Hash the key if it is longer than the block size
            ptr::copy_nonoverlapping(hashv(&[key]).as_ptr(), key_block.as_mut_ptr(), HASH_LENGTH);
        } else {
            // Copy the key directly into the block
            ptr::copy_nonoverlapping(key.as_ptr(), key_block.as_mut_ptr(), key.len());
        }
    }

    // Prepare inner and outer padded keys using u64 for 8-byte chunk XORs
    let mut inner_key_pad = [0u8; BLOCK_SIZE];
    let mut outer_key_pad = [0u8; BLOCK_SIZE];

    unsafe {
        let key_block_chunks = key_block.as_ptr() as *const u64;
        let inner_chunks = inner_key_pad.as_mut_ptr() as *mut u64;
        let outer_chunks = outer_key_pad.as_mut_ptr() as *mut u64;

        // XOR key chunks with the padding bytes 0x36 and 0x5C
        for i in 0..(BLOCK_SIZE / 8) {
            let key_u64 = ptr::read_unaligned(key_block_chunks.add(i));
            ptr::write_unaligned(inner_chunks.add(i), key_u64 ^ 0x3636363636363636);
            ptr::write_unaligned(outer_chunks.add(i), key_u64 ^ 0x5C5C5C5C5C5C5C5C);
        }
    }

    // Perform the inner hash: H((key XOR ipad) || message)
    let inner_hash = hashv(&[&inner_key_pad, message]);

    // Perform the outer hash: H((key XOR opad) || inner_hash)
    hashv(&[&outer_key_pad, &inner_hash])
}


#[cfg(test)]
mod tests {
    use crate::hmac_sha256;

    #[test]
    fn fast_sha256_hmac_test() {
        let x = hmac_sha256(b"test", b"test");
        println!("{:?}", hex::encode(x));
    }

}