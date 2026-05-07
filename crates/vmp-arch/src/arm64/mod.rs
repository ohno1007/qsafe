//! ARM64 (AArch64) lifter。
//!
//! 范围说明：本实现覆盖最常见的指令模式（数据处理立即数 / 寄存器、加载存储、跳转、
//! 比较、MOV*、NOP），足以让 lift → encode → interpret 全链路对一段算术 / 控制流密集的
//! 函数闭环。**未覆盖的指令**会被记录到 [`LiftReport`] 并发射 `VOp::Trap`，由上层决定：
//! - 跳过该函数（不保护）；
//! - 切换为「混合模式」：未知指令保留原生形式，由 stub 在 native 段执行。
//!
//! 关于完备性：AArch64 编码空间庞大，要做到 100% 覆盖需要分阶段加表。该模块的结构
//! 已经按 `op0` 大类拆分，便于增量补全。

mod decode;

use crate::lifter::{LiftReport, LiftedFunction, Lifter};
use byteorder::{ByteOrder, LittleEndian};
use vmp_core::{Error, Result};
use vmp_isa::{Cond, Instr, VOp, Width};

#[derive(Default)]
pub struct Arm64Lifter {
    pub strict: bool,
}

impl Lifter for Arm64Lifter {
    fn arch_name(&self) -> &'static str {
        "aarch64"
    }

    fn lift(&mut self, code: &[u8], base: u64) -> Result<LiftedFunction> {
        if code.len() % 4 != 0 {
            return Err(Error::lift(base, "ARM64 代码长度必须是 4 的倍数"));
        }
        let mut report = LiftReport::default();
        report.total_input = code.len() / 4;

        // 单遍：把每条 native 指令解码成 1..N 条 IR；记录 native_pc → ir_index。
        // **不在这里解析分支目标** —— branch ins.imm 保留为目标的绝对虚拟地址，
        // 由 vmp_codegen::resolve_program 做全局多函数解析。
        let mut ir: Vec<Instr> = Vec::with_capacity(report.total_input);
        let mut native_to_ir: Vec<usize> = Vec::with_capacity(report.total_input);

        for i in 0..report.total_input {
            let raw = LittleEndian::read_u32(&code[i * 4..i * 4 + 4]);
            native_to_ir.push(ir.len());
            match decode::decode(raw, base + (i as u64) * 4) {
                Ok(decoded) => {
                    ir.extend(decoded.into_iter());
                    report.lifted += 1;
                }
                Err(msg) => {
                    if self.strict {
                        return Err(Error::lift(base + (i as u64) * 4, msg));
                    }
                    report.skipped += 1;
                    report.notes.push(format!(
                        "@{:#x}: 未支持指令 0x{:08x} ({})",
                        base + (i as u64) * 4,
                        raw,
                        msg
                    ));
                    ir.push(Instr { op: VOp::Trap, ..Default::default() });
                }
            }
        }

        Ok(LiftedFunction { ir, native_to_ir, report })
    }
}

/// ARM64 → VM 寄存器映射：直接 1:1（X0..X30 → V0..V30，SP → V31）。
pub fn map_reg(arm64: u8, sp_is_zr: bool) -> u8 {
    if arm64 == 31 {
        if sp_is_zr {
            // 把 XZR 视作专门的 R32 ... 这里复用 V31 表示 SP；XZR 用 V0 写废区。
            // 简化：当作一个保留 reg：V0 不能被破坏，所以用第 31 号 + 一个写丢弃约定
            31
        } else {
            31
        }
    } else {
        arm64 & 0x1F
    }
}

/// 把 native imm 跳转的目标地址写到 IR 指令的 imm 字段。
pub fn target_addr(base_pc: u64, offset_bytes: i64) -> u64 {
    (base_pc as i64 + offset_bytes) as u64
}

pub use decode::Width as DecodeWidth;
#[allow(dead_code)]
fn _force_use_width(w: Width, c: Cond) -> (Width, Cond) {
    (w, c)
}
