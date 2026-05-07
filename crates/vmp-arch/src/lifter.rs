use vmp_core::Result;
use vmp_isa::Instr;

#[derive(Debug, Default)]
pub struct LiftReport {
    pub total_input: usize,
    pub lifted: usize,
    pub skipped: usize,
    pub fallback_native: usize,
    pub notes: Vec<String>,
}

/// 一个被 lift 出来的函数。
///
/// `ir` 中的分支指令（Br/BCond/Call）`imm` 字段是 **目标的绝对虚拟地址**（不是 IR 索引）。
/// 由 `vmp_codegen::resolve_program` 做全局解析后才会改成：
///   - 本 region 内分支：IR 索引（codegen 再展成字节偏移）
///   - 跨 region 调用：CallRegion + 目标 region_id
pub struct LiftedFunction {
    pub ir: Vec<Instr>,
    /// native_pc 索引（base + i*4，指令对齐 4） → IR 序列中第 i 个 native 指令对应的第一条 IR 索引。
    /// 全局解析时用它把"绝对地址"映回 IR 索引。
    pub native_to_ir: Vec<usize>,
    pub report: LiftReport,
}

pub trait Lifter: Send {
    fn arch_name(&self) -> &'static str;
    fn lift(&mut self, code: &[u8], base: u64) -> Result<LiftedFunction>;
}
