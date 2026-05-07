//! 垃圾指令构造工具与混淆叠加。
//!
//! `VOp::Junk / Nop / Obfuscate` 解释器视作 noop，但反汇编器必须解析其编码 → 抬高静态分析成本。
//! 这里在原本 1 字节 noop 的基础上扩展若干**有真实编码副作用但语义不变**的"哑指令序列"：
//!
//! - 哑算术：`Add Vsc, Vsc, 0` — 写入 lifter scratch 寄存器，对 native 寄存器无影响
//! - 不透明谓词：`Xor Vsc, Vsc, Vsc ; BCond Eq, +imm` — 永远 taken 但反汇编器画出额外边
//! - 假 Load：`Load Vsc, [SP+0]` — 读栈顶，结果丢弃到 lifter scratch
//!
//! 这些序列长度大于 1 字节，更难被简单特征识别为"统一 noop slot"。

use rand::Rng;
use rand_chacha::ChaCha20Rng;
use vmp_isa::{Cond, Instr, VOp, Width};

const SC1: u8 = 32;
const SC2: u8 = 33;

pub fn nop() -> Instr {
    Instr { op: VOp::Nop, ..Default::default() }
}
pub fn obfuscate() -> Instr {
    Instr { op: VOp::Obfuscate, ..Default::default() }
}
pub fn junk() -> Instr {
    Instr { op: VOp::Junk, ..Default::default() }
}

/// 生成一个"看起来像真指令"的 junk 序列，写入 `out`。返回插入的 IR 数量。
/// 选择哪种 junk 由 rng 决定；调用方负责保证 SC1/SC2 寄存器不被原代码依赖（lifter 已经预留）。
pub fn emit_decoy_seq(out: &mut Vec<Instr>, rng: &mut ChaCha20Rng) -> usize {
    let kind = rng.gen_range(0..6u8);
    match kind {
        0 => {
            // 简单 1-byte junk
            out.push(junk());
            1
        }
        1 => {
            out.push(nop());
            1
        }
        2 => {
            out.push(obfuscate());
            1
        }
        3 => {
            // 哑算术：Add SC1, SC1, 0 → 写 SC1，逻辑上 noop
            out.push(Instr { op: VOp::MovI, rd: SC2, imm: 0, width: Width::W64, ..Default::default() });
            out.push(Instr { op: VOp::Add, rd: SC1, rs: SC1, rt: SC2, width: Width::W64, ..Default::default() });
            2
        }
        4 => {
            // Xor self → 0 + Tst 设标志；不 emit BCond（codegen 会把 BCond imm 当 branch fixup
            // 索引解释，造成跳到 IR[0] 死循环）
            out.push(Instr { op: VOp::Xor, rd: SC1, rs: SC1, rt: SC1, width: Width::W64, ..Default::default() });
            out.push(Instr { op: VOp::Tst, rs: SC1, rt: SC1, width: Width::W64, ..Default::default() });
            2
        }
        _ => {
            // 哑 Cmp：Cmp SC1, SC1 → 设标志但不影响后续真实控制流（因为下条不是条件指令）
            out.push(Instr { op: VOp::Cmp, rs: SC1, rt: SC1, width: Width::W64, ..Default::default() });
            1
        }
    }
}
