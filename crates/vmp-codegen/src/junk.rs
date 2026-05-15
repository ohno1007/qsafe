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

// CRITICAL: junk 寄存器必须跟 lifter scratch (V32/V33/V34) 错开。
// lifter 把 ADRP+ADD 这样的多 native 指令展开成多条 IR，中间用 V32 暂存
// 立即数；如果 junk 在 MovI(V32, imm) 和 Add(x0, x0, V32) 之间被插入并
// 写 V32，立即数就丢了 (regr from junk_density>0 + ADRP+ADD imm pattern).
// V62 = LOAD_BIAS_REG, V63 = XZR (interpreter 每周期重置)，也不能动。
// V60/V61 是 lifter 不碰的高位 scratch。
const SC1: u8 = 60;
const SC2: u8 = 61;

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
///
/// **关键约束**：junk 在两条相邻 lifted IR 之间插入，所以**绝不能**改任何
/// 被原代码依赖的状态：
///   - 不写 V0..V31（ARM64 X0..X30 + SP）
///   - 不写 lifter scratch V32/V33/V34
///   - 不写 V62 (load_bias) / V63 (XZR)
///   - 不动 NZCV (flags) —— 不发 Tst / Cmp / ALU-flag-update
///   - 不动栈
///
/// 只能写 V60/V61，且只能用 不影响 flags 的 ALU op（Add/Or/Xor/And）。
pub fn emit_decoy_seq(out: &mut Vec<Instr>, rng: &mut ChaCha20Rng) -> usize {
    let kind = rng.gen_range(0..4u8);
    match kind {
        0 => {
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
        _ => {
            // MovI SC2=0; Add SC1 = SC1 + SC2  → SC1 不变, 不改 flags
            out.push(Instr { op: VOp::MovI, rd: SC2, imm: 0, width: Width::W64, ..Default::default() });
            out.push(Instr { op: VOp::Add, rd: SC1, rs: SC1, rt: SC2, width: Width::W64, ..Default::default() });
            2
        }
    }
}
