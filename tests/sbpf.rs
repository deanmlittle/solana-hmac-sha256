use solana_hmac_sha256::hmac_sha256;
use svm_unit_test::svm_test;

const KEY: [u8; 4] = *b"test";
const MSG: [u8; 4] = *b"test";

#[svm_test]
fn bench_hmac_sha256() {
    hmac_sha256(&KEY, &MSG);
}
