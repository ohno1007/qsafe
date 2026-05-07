//! vmp-core
//!
//! 通用类型与抽象。所有上层 crate 都依赖本模块。
//!
//! 设计目标：
//! - 与具体架构 / 操作系统解耦
//! - 提供 `Arch` / `ObjectFormat` 等枚举供后续扩展（x86、Windows）
//! - 统一错误类型，便于跨 crate 传播

pub mod arch;
pub mod config;
pub mod error;
pub mod region;

pub use arch::{Arch, ObjectFormat, Os};
pub use config::{ProtectConfig, ProtectLevel};
pub use error::{Error, Result};
pub use region::{CodeRegion, ProtectedRegion, Symbol};
