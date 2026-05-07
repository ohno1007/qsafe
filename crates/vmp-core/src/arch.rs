//! 架构 / OS / 对象格式 抽象。
//!
//! 添加新架构（如 x86_64）只需扩展枚举并提供对应 lifter 实现。

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    Arm64,
    X86_64,
    X86,
    Arm32,
}

impl Arch {
    pub fn pointer_width(&self) -> usize {
        match self {
            Arch::Arm64 | Arch::X86_64 => 8,
            Arch::X86 | Arch::Arm32 => 4,
        }
    }

    pub fn instr_alignment(&self) -> usize {
        match self {
            Arch::Arm64 => 4,
            Arch::Arm32 => 4,
            Arch::X86 | Arch::X86_64 => 1,
        }
    }

    /// 通用寄存器数量（含 SP/LR，但不含 PC、标志位等）。
    pub fn gpr_count(&self) -> usize {
        match self {
            Arch::Arm64 => 32,
            Arch::Arm32 => 16,
            Arch::X86_64 => 16,
            Arch::X86 => 8,
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Arch::Arm64 => f.write_str("aarch64"),
            Arch::X86_64 => f.write_str("x86_64"),
            Arch::X86 => f.write_str("x86"),
            Arch::Arm32 => f.write_str("arm"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    Linux,
    Windows,
    Macos,
    Android,
    Ios,
    Bare,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectFormat {
    Elf,
    Pe,
    MachO,
    Raw,
}

impl ObjectFormat {
    pub fn from_magic(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        match &buf[..4] {
            [0x7f, b'E', b'L', b'F'] => Some(ObjectFormat::Elf),
            [b'M', b'Z', _, _] => Some(ObjectFormat::Pe),
            [0xCF, 0xFA, 0xED, 0xFE] | [0xFE, 0xED, 0xFA, 0xCF] => Some(ObjectFormat::MachO),
            [0xCE, 0xFA, 0xED, 0xFE] | [0xFE, 0xED, 0xFA, 0xCE] => Some(ObjectFormat::MachO),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub arch: Arch,
    pub os: Os,
    pub format: ObjectFormat,
}
