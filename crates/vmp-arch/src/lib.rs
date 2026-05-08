//! vmp-arch
//!
//! 架构抽象 + 各架构 lifter。后续要支持 x86_64 时只需新增子模块并实现 [`Lifter`]。

pub mod lifter;
#[cfg(feature = "arm64")]
pub mod arm64;
#[cfg(feature = "arm32")]
pub mod arm32;
#[cfg(feature = "arm32")]
pub mod thumb;
#[cfg(feature = "x86_64")]
pub mod x86_64;

pub use lifter::{LiftReport, LiftedFunction, Lifter};

use vmp_core::{Arch, Result};

/// 工厂：根据架构返回对应 lifter 实例。
pub fn make_lifter(arch: Arch) -> Result<Box<dyn Lifter>> {
    match arch {
        #[cfg(feature = "arm64")]
        Arch::Arm64 => Ok(Box::new(arm64::Arm64Lifter::default())),
        #[cfg(feature = "arm32")]
        Arch::Arm32 => Ok(Box::new(arm32::Arm32Lifter::default())),
        #[cfg(feature = "x86_64")]
        Arch::X86_64 => Ok(Box::new(x86_64::X86_64Lifter::default())),
        _ => Err(vmp_core::Error::UnsupportedArch(arch)),
    }
}

/// 短便利包装：让外部调用方拿到 lifter 后直接 lift。
pub fn lift(arch: Arch, code: &[u8], base: u64) -> Result<LiftedFunction> {
    let mut lifter = make_lifter(arch)?;
    lifter.lift(code, base)
}
