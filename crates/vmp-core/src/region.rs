//! 描述「待保护代码区」与「符号」。

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    /// 在原始对象文件 / 内存映像中的虚拟地址
    pub vaddr: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct CodeRegion {
    pub vaddr: u64,
    pub bytes: Vec<u8>,
}

impl CodeRegion {
    pub fn end(&self) -> u64 {
        self.vaddr + self.bytes.len() as u64
    }
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.vaddr && addr < self.end()
    }
}

/// 已转换为 VM 字节码的函数。`patch_addr` / `patch_len` 描述原始机器码区域，
/// 加壳器将在该区域写入跳板（VENTER），跳到 stub 中的解释器。
#[derive(Debug, Clone)]
pub struct ProtectedRegion {
    pub symbol: Symbol,
    pub bytecode: Vec<u8>,
    pub patch_addr: u64,
    pub patch_len: u64,
    /// 在 stub 中分配给该函数 bytecode 的偏移
    pub bytecode_offset: u64,
}
