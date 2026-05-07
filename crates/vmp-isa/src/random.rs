//! 基于 seed 的 ISA 随机化器。生成 [`IsaSpec`]。

use crate::opcode::VOp;
use crate::spec::{HandlerVariant, IsaSpec, OpEncoding};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;

pub struct IsaRandomizer {
    rng: ChaCha20Rng,
    pub variants_per_op: u8,
    pub encrypt: bool,
}

impl IsaRandomizer {
    pub fn new(seed: u64, variants_per_op: u8, encrypt: bool) -> Self {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
        Self {
            rng: ChaCha20Rng::from_seed(seed_bytes),
            variants_per_op: variants_per_op.max(1),
            encrypt,
        }
    }

    pub fn build(mut self) -> IsaSpec {
        let all_ops = VOp::all();
        let total_variants: usize =
            all_ops.len() * (self.variants_per_op as usize);
        // 1 字节 opcode 空间 = 256；预留少量空缺给非法值，便于 fuzz 检测。
        assert!(total_variants <= 220, "ISA 随机化变体数超过 opcode 容量");

        // 1) 生成可用 opcode 池并打乱
        let mut pool: Vec<u8> = (1u8..=255u8).collect();
        pool.shuffle(&mut self.rng);

        let mut op_table: HashMap<u16, OpEncoding> = HashMap::new();
        let mut op_reverse: [Option<(u16, u8)>; 256] = [None; 256];
        let mut cursor = 0usize;
        for op in all_ops {
            let mut variants = Vec::with_capacity(self.variants_per_op as usize);
            for _ in 0..self.variants_per_op {
                let opcode = pool[cursor];
                cursor += 1;
                let tweak: u8 = self.rng.gen();
                variants.push(HandlerVariant { opcode, tweak });
                op_reverse[opcode as usize] = Some((*op as u16, tweak));
            }
            op_table.insert(*op as u16, OpEncoding { variants });
        }

        // 2) 寄存器置换（恒等可能；保证是合法置换）
        let mut perm: [u8; 64] = [0; 64];
        let mut idx: Vec<u8> = (0u8..64u8).collect();
        idx.shuffle(&mut self.rng);
        for (i, v) in idx.iter().enumerate() {
            perm[i] = *v;
        }
        // 反置换
        let mut unperm: [u8; 64] = [0; 64];
        for i in 0..64u8 {
            unperm[perm[i as usize] as usize] = i;
        }

        // 3) 流密钥 / IV / mask
        let mut stream_key = [0u8; 32];
        self.rng.fill(&mut stream_key);
        let mut stream_iv = [0u8; 16];
        self.rng.fill(&mut stream_iv);
        let imm_rol: u32 = self.rng.gen_range(1..63);
        let branch_xor: u32 = self.rng.gen();

        // 4) 指纹
        let mut fp = [0u8; 8];
        self.rng.fill(&mut fp);

        IsaSpec {
            op_table,
            op_reverse,
            reg_perm: perm,
            reg_unperm: unperm,
            stream_key,
            imm_rol,
            branch_xor,
            stream_iv,
            encrypt: self.encrypt,
            fingerprint: fp,
        }
    }
}
