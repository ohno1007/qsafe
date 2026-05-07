//! vmp-loader
//!
//! 解析二进制对象文件并抽取：
//! - 架构 / 操作系统
//! - 代码区（vaddr + bytes）
//! - 函数符号（如有）
//!
//! 通过 [`goblin`] 同时支持 ELF / PE / Mach-O；本骨架只对 ELF + PE 做了实现，
//! Mach-O 留待后续。

pub mod ar;
pub mod elf;
pub mod pe;

use goblin::Object;
use vmp_core::{Arch, CodeRegion, Error, ObjectFormat, Os, Result, Symbol};

/// 二进制类型：可执行 / 共享库 / 静态库归档。决定 vmp-rewriter 走哪条 patch 路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryKind {
    /// 可执行 ELF (ET_EXEC) — 修改 e_entry / 在 .text 写跳板
    Executable,
    /// 共享库 ELF (ET_DYN) — .so / PIE，没有固定 entry，需要 hook export 函数
    SharedObject,
    /// AR(.a) 静态库 —— 内含若干 .o，rewriter 需逐个处理 + 重写 archive
    StaticArchive,
    /// PE / Mach-O / 未知
    Other,
}

#[derive(Debug)]
pub struct LoadedObject {
    pub arch: Arch,
    pub os: Os,
    pub format: ObjectFormat,
    pub kind: BinaryKind,
    pub code: Vec<CodeRegion>,
    pub symbols: Vec<Symbol>,
    pub entry: u64,
    pub raw: Vec<u8>,
}

pub fn load(bytes: Vec<u8>) -> Result<LoadedObject> {
    // 先判断是不是 AR 静态库（magic = "!<arch>\n"）。
    if bytes.len() >= 8 && &bytes[..8] == b"!<arch>\n" {
        return ar::parse(bytes);
    }

    let format = ObjectFormat::from_magic(&bytes)
        .ok_or_else(|| Error::parse("无法识别对象文件类型"))?;
    match Object::parse(&bytes).map_err(|e| Error::parse(format!("goblin: {e}")))? {
        Object::Elf(e) => elf::parse(&bytes, e, format),
        Object::PE(p) => pe::parse(&bytes, p, format),
        Object::Mach(_) => Err(Error::UnsupportedFormat(ObjectFormat::MachO)),
        _ => Err(Error::UnsupportedFormat(format)),
    }
}
