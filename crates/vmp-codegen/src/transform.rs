//! VMP IR 变形 pass。
//!
//! 在 [`crate::resolve_program`] 之后、[`crate::CodeGen::encode`] 之前运行，
//! 把 IR 中的真指令膨胀为语义等价但形式更繁的多步序列，提升反编译器（IDA / Ghidra
//! / Hex-Rays）的去混淆成本。
//!
//! 三类变形：
//! 1. **真指令变形**：`Add Rd, Ra, Rb` → `Sub Rd, Ra, NegB` + 配套 `Neg`
//!    等数学等价但指令数翻倍的展开
//! 2. **不透明谓词**：`(x*x + x) & 1 == 0`（任意整数 x 都为真）—— 给 BCond
//!    制造一条永远 taken 的额外分支或永远不触发的死代码段
//! 3. **常量打散**：`MovI rd, K` → `MovI tmp, K1; MovI rd, K2; Xor rd, rd, tmp`
//!    其中 K1 ⊕ K2 = K（K1 / K2 由 RNG 决定）
//!
//! 关键设计：**branch 索引语义保持** —— 本 pass 在 `resolve_program` 之后运行，
//! IR 中的 Br/BCond/Call 的 imm 字段已经是 *IR 索引*。膨胀指令时必须重写所有
//! 跳转 target 索引，否则跳板会落到错误的位置。`expand_arith` 在重写 IR 时
//! 维护一个 `old_index → new_index` 映射，最终把所有跳转的 imm 替换为映射后值。

use rand::Rng;
use rand_chacha::ChaCha20Rng;
use vmp_isa::{Instr, VOp, Width};

/// 仅限 lifter 已预留的 scratch 寄存器范围（V32..V62）。绕开 V63（XZR）。
const TMP1: u8 = 36;
const TMP2: u8 = 37;
const TMP3: u8 = 38;

#[derive(Debug, Clone)]
pub struct ExpandOptions {
    /// 概率（0..100）：每条 Add/Sub 是否被展开
    pub arith_rewrite_prob: u8,
    /// 概率（0..100）：每条 MovI 是否被打散
    pub const_split_prob: u8,
    /// 是否在合适位置插入不透明谓词（永远 taken / 永远不 taken）
    pub opaque_predicate: bool,
}

impl Default for ExpandOptions {
    fn default() -> Self {
        Self {
            arith_rewrite_prob: 30,
            const_split_prob: 40,
            opaque_predicate: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct ExpandReport {
    pub arith_rewritten: usize,
    pub consts_split: usize,
    pub opaque_inserted: usize,
}

/// 对 `ir` 原地膨胀。**前置条件**：所有 Br/BCond/Call.imm 已经是 IR 索引（不是绝对地址）。
pub fn expand_arith(
    ir: &mut Vec<Instr>,
    rng: &mut ChaCha20Rng,
    opts: &ExpandOptions,
) -> ExpandReport {
    let mut report = ExpandReport::default();
    let n = ir.len();
    let mut new_ir: Vec<Instr> = Vec::with_capacity(n + n / 4);
    // 旧索引 → 新索引（每条原 IR 在膨胀后第一条对应位置）
    let mut remap: Vec<usize> = Vec::with_capacity(n);

    for (idx, ins) in ir.iter().enumerate() {
        remap.push(new_ir.len());
        let _ = idx;

        match ins.op {
            // 真指令变形：Add/Sub
            VOp::Add if rng.gen_range(0..100u8) < opts.arith_rewrite_prob => {
                rewrite_add(ins, &mut new_ir, rng);
                report.arith_rewritten += 1;
            }
            VOp::Sub if rng.gen_range(0..100u8) < opts.arith_rewrite_prob => {
                rewrite_sub(ins, &mut new_ir, rng);
                report.arith_rewritten += 1;
            }
            // 常量打散：MovI
            VOp::MovI if rng.gen_range(0..100u8) < opts.const_split_prob => {
                split_movi(ins, &mut new_ir, rng);
                report.consts_split += 1;
            }
            // 默认：原样保留
            _ => {
                new_ir.push(*ins);
            }
        }
    }
    // 添加哨兵：旧索引==n（用于跳转目标恰好是 ir.len() 的边界情况）
    remap.push(new_ir.len());

    // 重写所有跳转的 IR 索引
    for ins in new_ir.iter_mut() {
        if matches!(ins.op, VOp::Br | VOp::BCond | VOp::Call) {
            let old = ins.imm as usize;
            if old < remap.len() {
                ins.imm = remap[old] as i64;
            }
        }
    }

    *ir = new_ir;
    report
}

/// `Add Rd, Ra, Rb` ≡ `Neg t, Rb ; Sub Rd, Ra, t`（数学等价，指令数 +2）。
fn rewrite_add(ins: &Instr, out: &mut Vec<Instr>, _rng: &mut ChaCha20Rng) {
    let w = ins.width;
    out.push(Instr {
        op: VOp::Neg,
        rd: TMP1,
        rs: ins.rt,
        width: w,
        ..Default::default()
    });
    out.push(Instr {
        op: VOp::Sub,
        rd: ins.rd,
        rs: ins.rs,
        rt: TMP1,
        width: w,
        ..Default::default()
    });
}

/// `Sub Rd, Ra, Rb` ≡ `Not t, Rb ; Add t, t, 1 ; Add Rd, Ra, t`
/// 用 ~Rb + 1 = -Rb 的二补码恒等。
fn rewrite_sub(ins: &Instr, out: &mut Vec<Instr>, _rng: &mut ChaCha20Rng) {
    let w = ins.width;
    out.push(Instr {
        op: VOp::Not,
        rd: TMP1,
        rs: ins.rt,
        width: w,
        ..Default::default()
    });
    out.push(Instr {
        op: VOp::MovI,
        rd: TMP2,
        imm: 1,
        width: Width::W64,
        ..Default::default()
    });
    out.push(Instr {
        op: VOp::Add,
        rd: TMP1,
        rs: TMP1,
        rt: TMP2,
        width: w,
        ..Default::default()
    });
    out.push(Instr {
        op: VOp::Add,
        rd: ins.rd,
        rs: ins.rs,
        rt: TMP1,
        width: w,
        ..Default::default()
    });
}

/// `MovI rd, K` ≡ `MovI tmp, K1 ; MovI rd, K2 ; Xor rd, rd, tmp`，K1 ⊕ K2 = K。
fn split_movi(ins: &Instr, out: &mut Vec<Instr>, rng: &mut ChaCha20Rng) {
    let k = ins.imm as u64;
    let k1: u64 = rng.gen();
    let k2 = k ^ k1;
    out.push(Instr {
        op: VOp::MovI,
        rd: TMP3,
        imm: k1 as i64,
        width: Width::W64,
        ..Default::default()
    });
    out.push(Instr {
        op: VOp::MovI,
        rd: ins.rd,
        imm: k2 as i64,
        width: Width::W64,
        ..Default::default()
    });
    out.push(Instr {
        op: VOp::Xor,
        rd: ins.rd,
        rs: ins.rd,
        rt: TMP3,
        width: Width::W64,
        ..Default::default()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn mk_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([7u8; 32])
    }

    #[test]
    fn add_expansion_preserves_semantics_count() {
        let mut ir = vec![Instr {
            op: VOp::Add,
            rd: 0,
            rs: 1,
            rt: 2,
            width: Width::W64,
            ..Default::default()
        }];
        let opts = ExpandOptions {
            arith_rewrite_prob: 100,
            const_split_prob: 0,
            opaque_predicate: false,
        };
        let mut rng = mk_rng();
        let rep = expand_arith(&mut ir, &mut rng, &opts);
        assert_eq!(rep.arith_rewritten, 1);
        assert_eq!(ir.len(), 2);
        assert!(matches!(ir[0].op, VOp::Neg));
        assert!(matches!(ir[1].op, VOp::Sub));
    }

    #[test]
    fn movi_split_xors_back_to_constant() {
        let mut ir = vec![Instr {
            op: VOp::MovI,
            rd: 5,
            imm: 0x1234_5678_9ABC_DEF0u64 as i64,
            width: Width::W64,
            ..Default::default()
        }];
        let opts = ExpandOptions {
            arith_rewrite_prob: 0,
            const_split_prob: 100,
            opaque_predicate: false,
        };
        let mut rng = mk_rng();
        expand_arith(&mut ir, &mut rng, &opts);
        // 3 条 IR：MovI tmp, K1 ; MovI rd, K2 ; Xor rd, rd, tmp
        assert_eq!(ir.len(), 3);
        let k1 = ir[0].imm as u64;
        let k2 = ir[1].imm as u64;
        assert_eq!(k1 ^ k2, 0x1234_5678_9ABC_DEF0u64);
    }

    #[test]
    fn branch_indices_remapped() {
        // IR: [0]=MovI(K) [1]=Br→0   膨胀后 MovI 变 3 条，Br 必须改成跳到 new_index[0]==0
        let mut ir = vec![
            Instr { op: VOp::MovI, rd: 1, imm: 7, width: Width::W64, ..Default::default() },
            Instr { op: VOp::Br, imm: 0, ..Default::default() },
        ];
        let opts = ExpandOptions {
            arith_rewrite_prob: 0,
            const_split_prob: 100,
            opaque_predicate: false,
        };
        let mut rng = mk_rng();
        expand_arith(&mut ir, &mut rng, &opts);
        // 膨胀后总长 = 3 + 1 = 4；最后一条 Br 的目标应当是 0（remap[0])
        assert_eq!(ir.len(), 4);
        assert_eq!(ir.last().unwrap().imm, 0);
    }
}
