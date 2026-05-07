//! 字节码流加密 / 解密。
//!
//! 这里使用一个轻量的 keystream，避免引入外部 crate（解释器 stub 也要嵌入相同算法）。
//! 实质是一个 32-byte key + 16-byte IV 喂给 ChaCha 风格的简化置换。
//! 安全级别：抗静态扫描足够；抗有针对性的密码分析不在 VMP 防护目标内。
//!
//! 关键性质：相同 (key, iv, position) 总产生相同 keystream → 解释器与 codegen 对称。

use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn keystream(key: &[u8; 32], iv: &[u8; 16], len: usize) -> Vec<u8> {
    // 用 key||iv 派生一个 32 字节 ChaCha seed
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = key[i] ^ iv[i % 16];
    }
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}

pub fn encrypt_in_place(buf: &mut [u8], key: &[u8; 32], iv: &[u8; 16]) {
    let ks = keystream(key, iv, buf.len());
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
}

pub fn decrypt_in_place(buf: &mut [u8], key: &[u8; 32], iv: &[u8; 16]) {
    encrypt_in_place(buf, key, iv);
}

/// 用 region salt 派生新 IV：iv[0..8] XOR salt 的 little-endian 字节。
/// 配合 `dispatch_vm(region_id)`，不同 region 的字节码即便用同一 master IV
/// 也产生完全不同的 keystream，单看一个 region 推不出另一个。
pub fn effective_iv(master: &[u8; 16], salt: u64) -> [u8; 16] {
    let mut iv = *master;
    let s = salt.to_le_bytes();
    for i in 0..8 {
        iv[i] ^= s[i];
    }
    iv
}

pub fn encrypt_in_place_salted(buf: &mut [u8], key: &[u8; 32], iv: &[u8; 16], salt: u64) {
    let iv2 = effective_iv(iv, salt);
    encrypt_in_place(buf, key, &iv2);
}

pub fn decrypt_in_place_salted(buf: &mut [u8], key: &[u8; 32], iv: &[u8; 16], salt: u64) {
    let iv2 = effective_iv(iv, salt);
    decrypt_in_place(buf, key, &iv2);
}
