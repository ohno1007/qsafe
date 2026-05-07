//! x86_64 lifter 的占位实现（feature = "x86_64"）。
//!
//! 此处仅给出骨架 —— 真实实现需要一个 x86 解码器（自写或 iced-x86）。
//! 接口已与 ARM64 lifter 对齐，后续填充时不影响其它 crate。

use crate::lifter::{LiftedFunction, Lifter};
use vmp_core::{Error, Result};

#[derive(Default)]
pub struct X86_64Lifter;

impl Lifter for X86_64Lifter {
    fn arch_name(&self) -> &'static str {
        "x86_64"
    }
    fn lift(&mut self, _code: &[u8], _base: u64) -> Result<LiftedFunction> {
        Err(Error::internal("x86_64 lifter 尚未实现 — 等待集成 iced-x86 或自写解码器"))
    }
}
