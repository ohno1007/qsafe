use sha2::{Digest, Sha256};

pub fn sha256(buf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(buf);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}
