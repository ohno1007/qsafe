//! ARMv7 (armeabi-v7a) lifter — 32-bit ARM 指令集骨架。
//!
//! 工程目标：覆盖 APK 在低端机上 `lib/armeabi-v7a/*.so` 跑的 32-bit ARM 子集。
//!
//! 范围（增量加表）：
//! - **ARM 模式**（4 字节定长指令）：MOV/ADD/SUB/CMP/B/BL/LDR/STR
//! - **Thumb 模式**（16-bit / 32-bit 混合）：留接口；本骨架只识别 ARM 32-bit 模式
//!
//! VM 寄存器映射（与 ARM64 兼容布局复用）：
//!   ARM R0..R12 → V0..V12
//!   ARM SP (R13) → V13；ARM LR (R14) → V14；ARM PC (R15) → V15
//!   lifter scratch 仍用 V32..V35（与 ARM64 一致；ARM32 寄存器只占 16 个 vreg
//!   不与 scratch 冲突）。
//!
//! 当前实现：MVP — 识别少数指令；其它返回 Trap，保留扩展点供后续按 ARM ARM 加表。

use crate::lifter::{LiftReport, LiftedFunction, Lifter};
use byteorder::{ByteOrder, LittleEndian};
use vmp_core::{Error, Result};
use vmp_isa::{Cond, Instr, VOp, Width};

const SCRATCH: u8 = 32;

#[derive(Default)]
pub struct Arm32Lifter {
    pub strict: bool,
    /// Thumb 模式 lift（指令为 16/32-bit 混合）。当前未实现，预留接口。
    pub thumb: bool,
}

impl Lifter for Arm32Lifter {
    fn arch_name(&self) -> &'static str {
        "arm"
    }

    fn lift(&mut self, code: &[u8], base: u64) -> Result<LiftedFunction> {
        if self.thumb {
            // 转交给 Thumb lifter
            return crate::thumb::ThumbLifter { strict: self.strict }.lift(code, base);
        }
        if code.len() % 4 != 0 {
            return Err(Error::lift(base, "ARM32 代码长度必须是 4 的倍数"));
        }
        let mut report = LiftReport::default();
        report.total_input = code.len() / 4;

        let mut ir: Vec<Instr> = Vec::with_capacity(report.total_input);
        let mut native_to_ir: Vec<usize> = Vec::with_capacity(report.total_input);

        for i in 0..report.total_input {
            let raw = LittleEndian::read_u32(&code[i * 4..i * 4 + 4]);
            let pc = base + (i as u64) * 4 + 8; // ARM PC = current + 8（pipelined）
            native_to_ir.push(ir.len());
            match decode_arm32(raw, pc) {
                Ok(decoded) => {
                    ir.extend(decoded.into_iter());
                    report.lifted += 1;
                }
                Err(msg) => {
                    if self.strict {
                        return Err(Error::lift(pc, msg));
                    }
                    report.skipped += 1;
                    report.notes.push(format!(
                        "@{:#x}: 未支持指令 0x{:08x} ({})",
                        pc, raw, msg
                    ));
                    ir.push(Instr { op: VOp::Trap, ..Default::default() });
                }
            }
        }
        Ok(LiftedFunction { ir, native_to_ir, report })
    }
}

/// ARM32 解码主分发。返回 1..N 条 IR。
fn decode_arm32(raw: u32, pc: u64) -> std::result::Result<Vec<Instr>, &'static str> {
    let cond = ((raw >> 28) & 0xF) as u8;
    // cond=0xF (NV) — 无条件指令，特殊处理
    if cond == 0xF {
        return Err("ARM32 unconditional 指令族未实现");
    }
    let arm_cond = Cond::from_u8(cond);

    // 大类 op1[27:25] = bits 27:25
    let op1 = (raw >> 25) & 0x7;
    match op1 {
        0b000 | 0b001 => decode_data_proc(raw, arm_cond),
        0b010 | 0b011 => decode_load_store(raw, arm_cond),
        0b101 => decode_branch(raw, pc, arm_cond),
        _ => Err("ARM32 op1 子类未实现"),
    }
}

/// Data Processing / MSR / MRS / MUL —— 仅识别基本 MOV/ADD/SUB/CMP（imm 与 reg）。
fn decode_data_proc(raw: u32, cond: Cond) -> std::result::Result<Vec<Instr>, &'static str> {
    let i_bit = (raw >> 25) & 1;
    let opcode = (raw >> 21) & 0xF;
    let s_bit = (raw >> 20) & 1;
    let rn = ((raw >> 16) & 0xF) as u8;
    let rd = ((raw >> 12) & 0xF) as u8;

    // operand2
    let op2_val: i64 = if i_bit == 1 {
        // imm12: rotate_imm[11:8] * 2 ROR imm8[7:0]
        let imm8 = (raw & 0xFF) as u32;
        let rot = ((raw >> 8) & 0xF) * 2;
        (imm8.rotate_right(rot)) as i64
    } else {
        // 寄存器形：仅识别 LSL #0 (即直接是 Rm)
        let rm = (raw & 0xF) as u8;
        // shift_imm/shift_type — 简化
        if (raw >> 4) & 0xFF != 0 {
            return Err("ARM32 data-proc 寄存器移位未实现");
        }
        // 用 MovR 把 Rm 装到 SCRATCH 当 op2，再走 imm 路径
        // 这里直接返回 IR 序列
        let _ = rm;
        return decode_dp_reg(opcode, s_bit, rn, rd, rm, cond);
    };

    let mut out: Vec<Instr> = Vec::with_capacity(4);
    out.push(Instr {
        op: VOp::MovI,
        rd: SCRATCH,
        imm: op2_val,
        width: Width::W64,
        ..Default::default()
    });

    let vop = match opcode {
        0b0010 => VOp::Sub, // SUB
        0b0100 => VOp::Add, // ADD
        0b0000 => VOp::And, // AND
        0b1100 => VOp::Or,  // ORR
        0b0001 => VOp::Xor, // EOR
        0b1101 => {
            // MOV Rd, op2 — 直接 MovI
            return Ok(vec![Instr {
                op: VOp::MovI,
                rd,
                imm: op2_val,
                width: Width::W32,
                ..Default::default()
            }]);
        }
        0b1010 => {
            // CMP Rn, op2
            return Ok(vec![
                Instr {
                    op: VOp::MovI,
                    rd: SCRATCH,
                    imm: op2_val,
                    width: Width::W64,
                    ..Default::default()
                },
                Instr {
                    op: VOp::Cmp,
                    rs: rn,
                    rt: SCRATCH,
                    width: Width::W32,
                    ..Default::default()
                },
            ]);
        }
        _ => return Err("ARM32 data-proc opcode 未实现"),
    };
    let _ = cond;
    out.push(Instr {
        op: vop,
        rd,
        rs: rn,
        rt: SCRATCH,
        width: Width::W32,
        ..Default::default()
    });
    if s_bit == 1 {
        out.push(Instr {
            op: VOp::Tst,
            rs: rd,
            rt: rd,
            width: Width::W32,
            ..Default::default()
        });
    }
    Ok(out)
}

fn decode_dp_reg(
    opcode: u32,
    s_bit: u32,
    rn: u8,
    rd: u8,
    rm: u8,
    _cond: Cond,
) -> std::result::Result<Vec<Instr>, &'static str> {
    let vop = match opcode {
        0b0010 => VOp::Sub,
        0b0100 => VOp::Add,
        0b0000 => VOp::And,
        0b1100 => VOp::Or,
        0b0001 => VOp::Xor,
        0b1101 => {
            return Ok(vec![Instr {
                op: VOp::MovR,
                rd,
                rs: rm,
                ..Default::default()
            }]);
        }
        _ => return Err("ARM32 dp-reg opcode 未实现"),
    };
    let mut out = vec![Instr {
        op: vop,
        rd,
        rs: rn,
        rt: rm,
        width: Width::W32,
        ..Default::default()
    }];
    if s_bit == 1 {
        out.push(Instr {
            op: VOp::Tst,
            rs: rd,
            rt: rd,
            width: Width::W32,
            ..Default::default()
        });
    }
    Ok(out)
}

/// LDR / STR （immediate offset 简化版）。
fn decode_load_store(raw: u32, _cond: Cond) -> std::result::Result<Vec<Instr>, &'static str> {
    let i_bit = (raw >> 25) & 1;
    let p_bit = (raw >> 24) & 1; // 1=pre-indexed/offset, 0=post-indexed
    let u_bit = (raw >> 23) & 1; // 1=add, 0=sub
    let b_bit = (raw >> 22) & 1; // 1=byte, 0=word
    let l_bit = (raw >> 20) & 1; // 1=load, 0=store
    let rn = ((raw >> 16) & 0xF) as u8;
    let rd = ((raw >> 12) & 0xF) as u8;

    if i_bit == 1 {
        return Err("ARM32 LDR/STR scaled register 未实现");
    }
    if p_bit == 0 {
        return Err("ARM32 LDR/STR post-index 未实现");
    }
    let imm12 = (raw & 0xFFF) as i64;
    let off = if u_bit == 1 { imm12 } else { -imm12 };
    let width = if b_bit == 1 { Width::W8 } else { Width::W32 };

    Ok(vec![Instr {
        op: if l_bit == 1 { VOp::Load } else { VOp::Store },
        rd,
        rs: rn,
        imm: off,
        width,
        ..Default::default()
    }])
}

/// B / BL：bits 27:24 = 1010(B) / 1011(BL)
fn decode_branch(raw: u32, pc: u64, cond: Cond) -> std::result::Result<Vec<Instr>, &'static str> {
    let l_bit = (raw >> 24) & 1;
    let imm24 = (raw & 0x00FF_FFFF) as i64;
    let off = if imm24 & (1 << 23) != 0 {
        imm24 | !((1 << 24) - 1)
    } else {
        imm24
    } * 4;
    let target = (pc as i64 + off) as u64;
    let op = if l_bit == 1 { VOp::Call } else { VOp::Br };
    if matches!(cond, Cond::Al) {
        Ok(vec![Instr { op, imm: target as i64, ..Default::default() }])
    } else {
        // 条件分支
        Ok(vec![Instr {
            op: VOp::BCond,
            cond,
            imm: target as i64,
            ..Default::default()
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mov_imm_ok() {
        // mov r0, #42 (ARM): cond=AL e3a0002a
        let raw = 0xE3A0_002Au32;
        let mut bytes = [0u8; 4];
        LittleEndian::write_u32(&mut bytes, raw);
        let mut lifter = Arm32Lifter::default();
        let lifted = lifter.lift(&bytes, 0x1000).unwrap();
        assert!(lifted.ir.iter().any(|i| matches!(i.op, VOp::MovI) && i.imm == 42));
    }
}
