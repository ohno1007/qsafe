//! 多函数全局分支解析。
//!
//! lifter 输出 IR 时，分支指令的 `imm` 是目标的**绝对虚拟地址**。本 pass 把它转换为：
//!   - **本 region 内分支**：目标 IR 的索引（codegen 之后再算字节偏移）
//!   - **跨 region 调用**（BL <另一函数入口>）：`VOp::CallRegion`，imm = 目标 region_id
//!     运行时由 stub 的 `NestedDispatchHost` 递归 dispatch_vm 完成 —— 每个 region
//!     仍是独立加密单元，BL 跨边界不影响 per-region IV salt。
//!   - 其它（跳到未保护的地址 / 中间标签）：`VOp::Trap` 占位，由上层决定回退策略。

use std::collections::HashMap;
use vmp_isa::{Instr, VOp};

#[derive(Debug, Clone)]
pub struct FunctionRegion {
    pub name: String,
    /// 函数在原 ELF 中的虚拟入口地址
    pub vaddr: u64,
    /// 函数 native 字节大小
    pub size: u64,
    /// lifter 输出的 IR（branch imm 仍是绝对地址）
    pub ir: Vec<Instr>,
    /// native_pc（按 4 字节步长的索引） → 该 native 指令对应的第一条 IR 的索引
    pub native_to_ir: Vec<usize>,
}

#[derive(Debug, Default)]
pub struct ResolveReport {
    pub intra_branches: usize,
    pub cross_region_calls: usize,
    pub unresolved: usize,
    /// (function_name, native_offset) 列表，用于诊断
    pub unresolved_targets: Vec<(String, u64)>,
}

/// 对所有 region 的 IR 做就地修改，把 branch imm 从绝对地址变成最终形式。
pub fn resolve_program(funcs: &mut [FunctionRegion]) -> ResolveReport {
    // 先建立 "函数入口虚拟地址 → region_id" 的全局表。
    let entry_to_region: HashMap<u64, usize> = funcs
        .iter()
        .enumerate()
        .map(|(i, f)| (f.vaddr, i))
        .collect();

    let mut report = ResolveReport::default();

    for func in funcs.iter_mut() {
        let func_start = func.vaddr;
        let func_end = func_start + func.size;
        let native_to_ir = func.native_to_ir.clone();
        let func_name = func.name.clone();

        for ins in func.ir.iter_mut() {
            match ins.op {
                VOp::Br | VOp::BCond | VOp::Call => {
                    let target_abs = ins.imm as u64;

                    // 本 region 内：转 IR 索引。
                    if target_abs >= func_start && target_abs < func_end {
                        let off = (target_abs - func_start) as usize;
                        if off % 4 == 0 {
                            let native_idx = off / 4;
                            if native_idx < native_to_ir.len() {
                                ins.imm = native_to_ir[native_idx] as i64;
                                report.intra_branches += 1;
                                continue;
                            }
                        }
                        // 落到非 4 字节对齐位置 → 视作未解析
                    }

                    // 是另一个被保护函数的入口：仅 Call (BL) 转 CallRegion；
                    // Br / BCond 跨函数 = tail-call 优化，目前不支持，标 Trap。
                    if let Some(&target_region) = entry_to_region.get(&target_abs) {
                        if matches!(ins.op, VOp::Call) {
                            ins.op = VOp::CallRegion;
                            ins.imm = target_region as i64;
                            report.cross_region_calls += 1;
                            continue;
                        }
                    }

                    // 其余情形：未知目标。
                    report.unresolved += 1;
                    report.unresolved_targets.push((func_name.clone(), target_abs));
                    *ins = Instr { op: VOp::Trap, ..Default::default() };
                }
                _ => {}
            }
        }
    }

    report
}
