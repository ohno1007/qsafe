//! ARMv7 Thumb 模式 lifter 骨架。
//!
//! Thumb 是 16-bit 与 32-bit 混合指令集。32-bit 指令第 1 个 16-bit 字以 0xE800..0xFFFF
//! 区域表示；其余为 16-bit 指令。
//!
//! 范围（MVP）：
//! - T1 16-bit:
//!   - MOV (imm) `00100 Rd imm8`
//!   - MOV (reg high) `01000110 D Rm Rd`
//!   - ADD (3-bit imm) `0001110 imm3 Rn Rd`
//!   - ADD (8-bit imm) `00110 Rd imm8`
//!   - SUB / CMP 类似
//!   - BX `010001110 Rm 000`
//!   - B (cond) `1101 cond imm8`
//!   - B (uncond) `11100 imm11`
//!   - LDR / STR (PC-relative / SP-relative)
//! - 32-bit (T2)：留扩展位 —— 大多数 NDK -mthumb 编译器会用到，需要 Phase 7 完整实现
//!
//! 寄存器：R0..R7 (low) + R8..R15 (high)，映射 V0..V15。

use crate::lifter::{LiftReport, LiftedFunction, Lifter};
use byteorder::{ByteOrder, LittleEndian};
use vmp_core::{Error, Result};
use vmp_isa::{Cond, Instr, VOp, Width};

const SCRATCH: u8 = 32;

#[derive(Default)]
pub struct ThumbLifter {
    pub strict: bool,
}

impl Lifter for ThumbLifter {
    fn arch_name(&self) -> &'static str {
        "thumb"
    }
    fn lift(&mut self, code: &[u8], base: u64) -> Result<LiftedFunction> {
        if code.len() % 2 != 0 {
            return Err(Error::lift(base, "Thumb 代码长度必须是 2 的倍数"));
        }
        let mut report = LiftReport::default();
        let mut ir: Vec<Instr> = Vec::new();
        let mut native_to_ir: Vec<usize> = Vec::new();

        let mut i = 0usize;
        while i < code.len() {
            let pc = base + i as u64 + 4; // Thumb PC = current + 4 (pipelined)
            let half = LittleEndian::read_u16(&code[i..i + 2]);
            // 32-bit T2 prefix：0xE800..0xFFFF（部分子集）
            let is_t2 = (half & 0xF800) == 0xE800
                || (half & 0xF800) == 0xF000
                || (half & 0xF800) == 0xF800;
            native_to_ir.push(ir.len());
            report.total_input += 1;
            if is_t2 && i + 4 <= code.len() {
                // 32-bit T2 指令 —— 当前简化为 Trap，Phase 7 补完
                report.skipped += 1;
                ir.push(Instr { op: VOp::Trap, ..Default::default() });
                i += 4;
            } else {
                match decode_t1(half, pc) {
                    Ok(decoded) => {
                        ir.extend(decoded.into_iter());
                        report.lifted += 1;
                    }
                    Err(msg) => {
                        if self.strict {
                            return Err(Error::lift(pc, msg));
                        }
                        report.skipped += 1;
                        report.notes.push(format!("@{:#x}: T1 0x{:04x} ({})", pc, half, msg));
                        ir.push(Instr { op: VOp::Trap, ..Default::default() });
                    }
                }
                i += 2;
            }
        }
        Ok(LiftedFunction { ir, native_to_ir, report })
    }
}

fn decode_t1(half: u16, pc: u64) -> std::result::Result<Vec<Instr>, &'static str> {
    // MOV (imm)：00100 Rd imm8 → Rd = imm8
    if half & 0xF800 == 0x2000 {
        let rd = ((half >> 8) & 7) as u8;
        let imm = (half & 0xFF) as i64;
        return Ok(vec![Instr { op: VOp::MovI, rd, imm, width: Width::W32, ..Default::default() }]);
    }
    // ADD (8-bit imm)：00110 Rd imm8
    if half & 0xF800 == 0x3000 {
        let rd = ((half >> 8) & 7) as u8;
        let imm = (half & 0xFF) as i64;
        return Ok(vec![
            Instr { op: VOp::MovI, rd: SCRATCH, imm, width: Width::W32, ..Default::default() },
            Instr { op: VOp::Add, rd, rs: rd, rt: SCRATCH, width: Width::W32, ..Default::default() },
        ]);
    }
    // SUB (8-bit imm)：00111 Rd imm8
    if half & 0xF800 == 0x3800 {
        let rd = ((half >> 8) & 7) as u8;
        let imm = (half & 0xFF) as i64;
        return Ok(vec![
            Instr { op: VOp::MovI, rd: SCRATCH, imm, width: Width::W32, ..Default::default() },
            Instr { op: VOp::Sub, rd, rs: rd, rt: SCRATCH, width: Width::W32, ..Default::default() },
        ]);
    }
    // CMP (8-bit imm)：00101 Rn imm8
    if half & 0xF800 == 0x2800 {
        let rn = ((half >> 8) & 7) as u8;
        let imm = (half & 0xFF) as i64;
        return Ok(vec![
            Instr { op: VOp::MovI, rd: SCRATCH, imm, width: Width::W32, ..Default::default() },
            Instr { op: VOp::Cmp, rs: rn, rt: SCRATCH, width: Width::W32, ..Default::default() },
        ]);
    }
    // B (cond)：1101 cond imm8
    if half & 0xF000 == 0xD000 {
        let cond = ((half >> 8) & 0xF) as u8;
        let imm8 = (half & 0xFF) as i8 as i64;
        let target = (pc as i64 + imm8 * 2) as u64;
        if cond == 0xE {
            // AL → 直接跳
            return Ok(vec![Instr { op: VOp::Br, imm: target as i64, ..Default::default() }]);
        }
        if cond == 0xF {
            return Err("T1 SVC（cond=0xF）应走 SVC 路径");
        }
        return Ok(vec![Instr {
            op: VOp::BCond,
            cond: Cond::from_u8(cond),
            imm: target as i64,
            ..Default::default()
        }]);
    }
    // B (uncond)：11100 imm11
    if half & 0xF800 == 0xE000 {
        let imm11 = (half & 0x7FF) as i32;
        let off = if imm11 & 0x400 != 0 { imm11 | !0x7FF } else { imm11 } as i64 * 2;
        let target = (pc as i64 + off) as u64;
        return Ok(vec![Instr { op: VOp::Br, imm: target as i64, ..Default::default() }]);
    }
    // BX Rm：010001110 Rm 000
    if half & 0xFF87 == 0x4700 {
        let rm = ((half >> 3) & 0xF) as u8;
        return Ok(vec![Instr { op: VOp::IndirectBr, rd: rm, ..Default::default() }]);
    }
    // NOP：1011_1111 0000_0000 (BF00)
    if half == 0xBF00 {
        return Ok(vec![Instr { op: VOp::Nop, ..Default::default() }]);
    }
    Err("T1 编码未实现")
}
