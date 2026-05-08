//! x86_64 lifter — 可变长指令骨架。
//!
//! x86 解码空间庞大且变长（1..15 字节）；生产路径建议接 `iced-x86` crate
//! （`features = ["decoder", "no_std"]` 可剥成 ~150 KB）—— 当前版本不引入额外
//! 依赖以保持工作区精简，**只识别少量 prologue/epilogue 指令**：
//!   - REX.W MOV r64, imm64 (`0x48 0xB8 + 8B imm`)
//!   - REX.W ADD r64, r/m64 (`0x48 0x01 ...`)
//!   - REX.W RET (`0xC3`)
//!   - PUSH r64 / POP r64 (`0x50..0x57` / `0x58..0x5F`)
//!   - CALL rel32 (`0xE8 + 4B imm`)
//!   - JMP rel32 (`0xE9 + 4B imm`)
//!
//! 寄存器映射（x86_64 → V0..V15）：
//!   RAX=V0, RCX=V1, RDX=V2, RBX=V3, RSP=V4, RBP=V5, RSI=V6, RDI=V7,
//!   R8..R15=V8..V15
//!
//! 不在覆盖范围内的指令返回 Trap；上层 protect 路径会跳过该函数。

use crate::lifter::{LiftReport, LiftedFunction, Lifter};
use byteorder::{ByteOrder, LittleEndian};
use vmp_core::{Error, Result};
use vmp_isa::{Instr, VOp, Width};

#[derive(Default)]
pub struct X86_64Lifter {
    pub strict: bool,
}

impl Lifter for X86_64Lifter {
    fn arch_name(&self) -> &'static str {
        "x86_64"
    }
    fn lift(&mut self, code: &[u8], base: u64) -> Result<LiftedFunction> {
        let mut report = LiftReport::default();
        let mut ir: Vec<Instr> = Vec::new();
        let mut native_to_ir: Vec<usize> = Vec::new();

        let mut i = 0usize;
        while i < code.len() {
            let pc = base + i as u64;
            native_to_ir.push(ir.len());
            match decode_one(&code[i..], pc) {
                Ok((decoded, len)) => {
                    ir.extend(decoded.into_iter());
                    report.lifted += 1;
                    i += len;
                    report.total_input += 1;
                }
                Err(msg) => {
                    if self.strict {
                        return Err(Error::lift(pc, msg));
                    }
                    report.skipped += 1;
                    report.notes.push(format!("@{:#x}: 未支持指令 ({})", pc, msg));
                    ir.push(Instr { op: VOp::Trap, ..Default::default() });
                    report.total_input += 1;
                    // 安全推进：x86 变长，未识别时按 1 字节步进。这会导致后续位置错乱，
                    // 但 strict=false 路径只是产出 Trap 占位，不要求 100% 正确解码。
                    i += 1;
                }
            }
        }
        Ok(LiftedFunction { ir, native_to_ir, report })
    }
}

fn decode_one(bytes: &[u8], pc: u64) -> std::result::Result<(Vec<Instr>, usize), &'static str> {
    if bytes.is_empty() {
        return Err("EOF");
    }
    let b0 = bytes[0];

    // REX prefix?
    let (rex, rest_off) = if (b0 & 0xF0) == 0x40 {
        (b0, 1)
    } else {
        (0, 0)
    };
    let rex_w = (rex & 0x08) != 0;
    let _rex_r = (rex & 0x04) != 0;
    let _rex_b = (rex & 0x01) != 0;
    if rest_off >= bytes.len() {
        return Err("EOF after REX");
    }
    let op = bytes[rest_off];

    // RET
    if op == 0xC3 {
        return Ok((vec![Instr { op: VOp::Ret, ..Default::default() }], rest_off + 1));
    }
    // PUSH r64 (0x50..0x57)
    if (0x50..=0x57).contains(&op) {
        let reg = (op - 0x50) as u8;
        return Ok((
            vec![Instr { op: VOp::Push, rd: reg, ..Default::default() }],
            rest_off + 1,
        ));
    }
    // POP r64 (0x58..0x5F)
    if (0x58..=0x5F).contains(&op) {
        let reg = (op - 0x58) as u8;
        return Ok((
            vec![Instr { op: VOp::Pop, rd: reg, ..Default::default() }],
            rest_off + 1,
        ));
    }
    // MOV r64, imm64: 48 B8+rd ib*8
    if rex_w && (0xB8..=0xBF).contains(&op) {
        if bytes.len() < rest_off + 1 + 8 {
            return Err("MOV imm64 截断");
        }
        let reg = (op - 0xB8) as u8;
        let imm = LittleEndian::read_u64(&bytes[rest_off + 1..rest_off + 9]) as i64;
        return Ok((
            vec![Instr {
                op: VOp::MovI,
                rd: reg,
                imm,
                width: Width::W64,
                ..Default::default()
            }],
            rest_off + 9,
        ));
    }
    // CALL rel32: E8 ib*4
    if op == 0xE8 {
        if bytes.len() < rest_off + 5 {
            return Err("CALL rel32 截断");
        }
        let rel = LittleEndian::read_i32(&bytes[rest_off + 1..rest_off + 5]) as i64;
        let target = (pc as i64 + (rest_off + 5) as i64 + rel) as u64;
        return Ok((
            vec![Instr {
                op: VOp::Call,
                imm: target as i64,
                ..Default::default()
            }],
            rest_off + 5,
        ));
    }
    // JMP rel32: E9 ib*4
    if op == 0xE9 {
        if bytes.len() < rest_off + 5 {
            return Err("JMP rel32 截断");
        }
        let rel = LittleEndian::read_i32(&bytes[rest_off + 1..rest_off + 5]) as i64;
        let target = (pc as i64 + (rest_off + 5) as i64 + rel) as u64;
        return Ok((
            vec![Instr {
                op: VOp::Br,
                imm: target as i64,
                ..Default::default()
            }],
            rest_off + 5,
        ));
    }
    // NOP
    if op == 0x90 {
        return Ok((vec![Instr { op: VOp::Nop, ..Default::default() }], rest_off + 1));
    }
    // INT3
    if op == 0xCC {
        return Ok((vec![Instr { op: VOp::Trap, ..Default::default() }], rest_off + 1));
    }
    // INC r64 / DEC r64：REX.W + FF /0 (inc) / FF /1 (dec) reg
    if rex_w && op == 0xFF && bytes.len() >= rest_off + 2 {
        let modrm = bytes[rest_off + 1];
        let rm = modrm & 7;
        let reg_op = (modrm >> 3) & 7;
        let mod_field = (modrm >> 6) & 3;
        if mod_field == 0b11 {
            match reg_op {
                0 => {
                    return Ok((
                        vec![
                            Instr { op: VOp::MovI, rd: 32, imm: 1, width: Width::W64, ..Default::default() },
                            Instr { op: VOp::Add, rd: rm, rs: rm, rt: 32, width: Width::W64, ..Default::default() },
                        ],
                        rest_off + 2,
                    ));
                }
                1 => {
                    return Ok((
                        vec![
                            Instr { op: VOp::MovI, rd: 32, imm: 1, width: Width::W64, ..Default::default() },
                            Instr { op: VOp::Sub, rd: rm, rs: rm, rt: 32, width: Width::W64, ..Default::default() },
                        ],
                        rest_off + 2,
                    ));
                }
                _ => {}
            }
        }
    }
    // ADD r/m64, r64 : REX.W + 0x01 + ModR/M (mod=11 → reg-reg)
    if rex_w && op == 0x01 && bytes.len() >= rest_off + 2 {
        let modrm = bytes[rest_off + 1];
        if (modrm >> 6) == 0b11 {
            let dst = modrm & 7;
            let src = (modrm >> 3) & 7;
            return Ok((
                vec![Instr {
                    op: VOp::Add, rd: dst, rs: dst, rt: src, width: Width::W64,
                    ..Default::default()
                }],
                rest_off + 2,
            ));
        }
    }
    // SUB r/m64, r64 : REX.W + 0x29 + ModR/M
    if rex_w && op == 0x29 && bytes.len() >= rest_off + 2 {
        let modrm = bytes[rest_off + 1];
        if (modrm >> 6) == 0b11 {
            let dst = modrm & 7;
            let src = (modrm >> 3) & 7;
            return Ok((
                vec![Instr {
                    op: VOp::Sub, rd: dst, rs: dst, rt: src, width: Width::W64,
                    ..Default::default()
                }],
                rest_off + 2,
            ));
        }
    }
    // MOV r/m64, r64 : REX.W + 0x89 + ModR/M
    if rex_w && op == 0x89 && bytes.len() >= rest_off + 2 {
        let modrm = bytes[rest_off + 1];
        if (modrm >> 6) == 0b11 {
            let dst = modrm & 7;
            let src = (modrm >> 3) & 7;
            return Ok((
                vec![Instr { op: VOp::MovR, rd: dst, rs: src, ..Default::default() }],
                rest_off + 2,
            ));
        }
    }
    // XOR r/m64, r64 : REX.W + 0x31 + ModR/M
    if rex_w && op == 0x31 && bytes.len() >= rest_off + 2 {
        let modrm = bytes[rest_off + 1];
        if (modrm >> 6) == 0b11 {
            let dst = modrm & 7;
            let src = (modrm >> 3) & 7;
            return Ok((
                vec![Instr {
                    op: VOp::Xor, rd: dst, rs: dst, rt: src, width: Width::W64,
                    ..Default::default()
                }],
                rest_off + 2,
            ));
        }
    }
    // AND r/m64, r64 : REX.W + 0x21
    if rex_w && op == 0x21 && bytes.len() >= rest_off + 2 {
        let modrm = bytes[rest_off + 1];
        if (modrm >> 6) == 0b11 {
            let dst = modrm & 7;
            let src = (modrm >> 3) & 7;
            return Ok((
                vec![Instr {
                    op: VOp::And, rd: dst, rs: dst, rt: src, width: Width::W64,
                    ..Default::default()
                }],
                rest_off + 2,
            ));
        }
    }
    // OR r/m64, r64 : REX.W + 0x09
    if rex_w && op == 0x09 && bytes.len() >= rest_off + 2 {
        let modrm = bytes[rest_off + 1];
        if (modrm >> 6) == 0b11 {
            let dst = modrm & 7;
            let src = (modrm >> 3) & 7;
            return Ok((
                vec![Instr {
                    op: VOp::Or, rd: dst, rs: dst, rt: src, width: Width::W64,
                    ..Default::default()
                }],
                rest_off + 2,
            ));
        }
    }
    // CMP r/m64, r64 : REX.W + 0x39
    if rex_w && op == 0x39 && bytes.len() >= rest_off + 2 {
        let modrm = bytes[rest_off + 1];
        if (modrm >> 6) == 0b11 {
            let dst = modrm & 7;
            let src = (modrm >> 3) & 7;
            return Ok((
                vec![Instr {
                    op: VOp::Cmp, rs: dst, rt: src, width: Width::W64,
                    ..Default::default()
                }],
                rest_off + 2,
            ));
        }
    }
    // Jcc rel32：0F 8x ib*4
    if op == 0x0F && bytes.len() >= rest_off + 6 {
        let cc = bytes[rest_off + 1];
        if cc & 0xF0 == 0x80 {
            let cond = match cc & 0xF {
                0x4 => vmp_isa::Cond::Eq,  // JE
                0x5 => vmp_isa::Cond::Ne,  // JNE
                0xC => vmp_isa::Cond::Lt,  // JL  (signed)
                0xD => vmp_isa::Cond::Ge,  // JGE
                0xE => vmp_isa::Cond::Le,  // JLE
                0xF => vmp_isa::Cond::Gt,  // JG
                _ => return Err("Jcc cond 未实现"),
            };
            let rel = LittleEndian::read_i32(&bytes[rest_off + 2..rest_off + 6]) as i64;
            let target = (pc as i64 + (rest_off + 6) as i64 + rel) as u64;
            return Ok((
                vec![Instr { op: VOp::BCond, cond, imm: target as i64, ..Default::default() }],
                rest_off + 6,
            ));
        }
    }
    // Jcc rel8: 0x70..0x7F + ib
    if (0x70..=0x7F).contains(&op) && bytes.len() >= rest_off + 2 {
        let cond = match op & 0xF {
            0x4 => vmp_isa::Cond::Eq,
            0x5 => vmp_isa::Cond::Ne,
            0xC => vmp_isa::Cond::Lt,
            0xD => vmp_isa::Cond::Ge,
            0xE => vmp_isa::Cond::Le,
            0xF => vmp_isa::Cond::Gt,
            _ => return Err("Jcc rel8 cond 未实现"),
        };
        let rel = bytes[rest_off + 1] as i8 as i64;
        let target = (pc as i64 + (rest_off + 2) as i64 + rel) as u64;
        return Ok((
            vec![Instr { op: VOp::BCond, cond, imm: target as i64, ..Default::default() }],
            rest_off + 2,
        ));
    }
    // JMP rel8：EB ib
    if op == 0xEB && bytes.len() >= rest_off + 2 {
        let rel = bytes[rest_off + 1] as i8 as i64;
        let target = (pc as i64 + (rest_off + 2) as i64 + rel) as u64;
        return Ok((
            vec![Instr { op: VOp::Br, imm: target as i64, ..Default::default() }],
            rest_off + 2,
        ));
    }
    // CDQE / CWDE：REX.W + 0x98 (cdqe) / 0x98 (cwde)
    // 简化：noop（VM 寄存器无 32/64 区分）
    if rex_w && op == 0x98 {
        return Ok((vec![Instr { op: VOp::Nop, ..Default::default() }], rest_off + 1));
    }

    Err("x86_64 指令未实现")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ret_decodes() {
        let mut l = X86_64Lifter::default();
        let r = l.lift(&[0xC3], 0x1000).unwrap();
        assert!(matches!(r.ir.first().unwrap().op, VOp::Ret));
    }

    #[test]
    fn movabs_decodes() {
        // mov rax, 0x1122334455667788  →  48 B8 88 77 66 55 44 33 22 11
        let bytes = [0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        let mut l = X86_64Lifter::default();
        let r = l.lift(&bytes, 0x4000).unwrap();
        let i = r.ir.first().unwrap();
        assert!(matches!(i.op, VOp::MovI));
        assert_eq!(i.rd, 0);
        assert_eq!(i.imm as u64, 0x1122_3344_5566_7788);
    }
}
