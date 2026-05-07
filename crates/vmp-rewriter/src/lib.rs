//! vmp-rewriter
//!
//! 把 [`vmp_stub::StubBlob`] 嵌入到原 ELF / .so / .a 静态库的工具，并在原代码段写入
//! 跳板，使受保护函数被首次调用时把控制权交给 VM 解释器。
//!
//! 支持的目标：
//! - **ET_EXEC 可执行 ELF** —— 在 e_entry 指向的函数入口写跳板，把整个 _start 重定向。
//! - **ET_DYN 共享库 / PIE** —— 对每个被保护的导出函数入口写跳板（不依赖 e_entry）。
//! - **AR(.a) 静态库** —— 解 archive，对每个 `.o` 成员独立 rewrite，再重写 archive。
//!
//! 当前实现做的：
//! 1. 在 ELF 末尾追加一段新的 program-header `PT_LOAD` segment，承载：
//!    - 整个 stub blob（pack_blob 的输出）
//!    - 每个 region 一段 16-byte 跳板（trampoline），用于把 region_id 装到 X16，
//!      然后通过 `BRK #0xQVMP` 触发外部 dispatcher。
//! 2. 给每个被保护函数的 native entry 写 4-byte `B <trampoline>`（imm26 偏移）。
//! 3. 修复 ELF program-header 表 + section-header 表，让 readelf 看得见新段。
//!
//! 「外部 dispatcher」可以是：
//! - 同进程加载的 LD_PRELOAD .so（用 vmp-runtime 改成 cdylib 形态，注册 SIGTRAP handler）
//! - 一个 launcher 二进制 ptrace 注入
//!
//! 当前版本只实现 1 + 2 + 3 的字节级写入；运行时 dispatcher 留接口位（详见 README）。
//!
//! 设计原则：本 crate 不做高强度 ELF 重排，避免触碰 dynsym / rela / eh_frame。
//! 我们只追加新段、修改 e_phoff、e_phnum，必要时把 `.text` 中函数入口写一条 B 指令。

pub mod armor;
pub mod elf_writer;
pub mod patcher;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RewriteError {
    #[error("不支持的二进制类型")]
    Unsupported,
    #[error("解析失败: {0}")]
    Parse(String),
    #[error("跳板偏移超出 B-imm26 范围（±128MB），无法写跳板")]
    BranchTooFar,
    #[error("内部错误: {0}")]
    Internal(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RewriteError>;

pub use armor::{apply_armor, ArmorOptions, ArmorReport};
pub use elf_writer::{rewrite_elf, RewriteOptions, RewriteReport};
pub use patcher::{TrampolineKind, ARM64_BRK_QVMP_BASE};
