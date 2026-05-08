//! VM 运行时状态。

use vmp_core::{Error, Result};
use vmp_isa::{Cond, Width};

/// 64 个 64-bit 通用寄存器：
/// - V0..V31: 与 ARM64 X0..X30 + SP 对齐（x86 lifter 也会复用前 16 项）
/// - V32..V63: lifter 私有 scratch，不与任何 native 寄存器冲突
pub const REG_COUNT: usize = 64;
/// 32 个 128-bit 浮点 / NEON 寄存器（对应 ARM64 V0..V31 / Q0..Q31）。
/// 标量 FP 取低 32/64 bit，向量取整 128 bit（向量算术目前未实现，留扩展点）。
pub const FREG_COUNT: usize = 32;
pub const STACK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct Flags {
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
}

impl Flags {
    pub fn update_arith(&mut self, res: u64, w: Width, c: bool, v: bool) {
        let bits = (w.bytes() * 8) as u32;
        self.n = ((res >> (bits - 1)) & 1) != 0;
        self.z = (res & w.mask()) == 0;
        self.c = c;
        self.v = v;
    }

    pub fn update_logical(&mut self, res: u64, w: Width) {
        let bits = (w.bytes() * 8) as u32;
        self.n = ((res >> (bits - 1)) & 1) != 0;
        self.z = (res & w.mask()) == 0;
        self.c = false;
        self.v = false;
    }

    pub fn matches(&self, c: Cond) -> bool {
        match c {
            Cond::Eq => self.z,
            Cond::Ne => !self.z,
            Cond::Cs => self.c,
            Cond::Cc => !self.c,
            Cond::Mi => self.n,
            Cond::Pl => !self.n,
            Cond::Vs => self.v,
            Cond::Vc => !self.v,
            Cond::Hi => self.c && !self.z,
            Cond::Ls => !self.c || self.z,
            Cond::Ge => self.n == self.v,
            Cond::Lt => self.n != self.v,
            Cond::Gt => !self.z && (self.n == self.v),
            Cond::Le => self.z || (self.n != self.v),
            Cond::Al => true,
            Cond::Nv => false,
        }
    }
}

#[derive(Debug)]
pub struct VmState {
    pub regs: [u64; REG_COUNT],
    /// NEON / FP 寄存器：每个 128-bit。
    pub fregs: [u128; FREG_COUNT],
    pub flags: Flags,
    pub pc: u64,
    pub stack: Vec<u64>,
    pub max_stack: usize,
}

impl Default for VmState {
    fn default() -> Self {
        Self::new()
    }
}

impl VmState {
    pub fn new() -> Self {
        Self {
            regs: [0; REG_COUNT],
            fregs: [0u128; FREG_COUNT],
            flags: Flags::default(),
            pc: 0,
            stack: Vec::with_capacity(256),
            max_stack: STACK_SIZE,
        }
    }

    pub fn push(&mut self, v: u64) -> Result<()> {
        if self.stack.len() >= self.max_stack {
            return Err(Error::vm("E4"));
        }
        self.stack.push(v);
        Ok(())
    }

    pub fn pop(&mut self) -> Result<u64> {
        self.stack.pop().ok_or_else(|| Error::vm("E5"))
    }
}

/// 与宿主进程交互的桥接。stub / 测试 harness 各有自己的实现。
pub trait HostBridge {
    /// 从宿主地址空间读取
    fn load(&mut self, addr: u64, width: Width) -> Result<u64>;
    /// 向宿主地址空间写入
    fn store(&mut self, addr: u64, value: u64, width: Width) -> Result<()>;
    /// 调用 native 函数指针，最多 8 个参数（按 ABI），返回值 in r0
    fn native_call(&mut self, target: u64, args: &[u64]) -> Result<u64>;
    /// 系统调用（架构相关）
    fn syscall(&mut self, no: u64, args: &[u64]) -> Result<u64>;
    /// 跨 region 调用（仅 GPR 路径，向后兼容）：BL 跳到另一个被保护函数时触发。
    /// FP-aware 路径请实现 `vm_call_region_fp`，默认 fallback 到这个。
    fn vm_call_region(&mut self, _region_id: u64, _args: &[u64]) -> Result<u64> {
        Err(vmp_core::Error::vm("HostBridge::vm_call_region 未实现"))
    }

    /// FP-aware 跨 region 调用：传 GPR V0..V7 + FREG D0..D7（低 64 位），
    /// 返回 (GPR V0, FREG D0 低 64 位)。AAPCS64 调用约定 GPR/FPR 各自传值。
    fn vm_call_region_fp(
        &mut self,
        region_id: u64,
        gpr_args: &[u64; 8],
        fpr_args: &[u64; 8],
    ) -> Result<(u64, u64)> {
        let _ = fpr_args;
        let r = self.vm_call_region(region_id, gpr_args)?;
        Ok((r, 0))
    }

    /// 把原 ELF 的非代码加载段（.rodata / .data / .bss）映射到指定 vaddr。
    /// dispatch_vm 启动时一次性调用所有段；linux 端用 mmap MAP_FIXED 实现。
    /// `prot` 位：0x1=R, 0x2=W, 0x4=X。本地测试 host 可以默认 noop（让 unsafe 写入直接生效）。
    fn map_data(&mut self, _vaddr: u64, _bytes: &[u8], _prot: u8) -> Result<()> {
        Ok(())
    }

    /// 混合执行：让宿主在真实 ARM 寄存器上跑一条原 native 指令。
    ///
    /// `raw_instr` = 4 字节原始 ARM 指令字节（little-endian u32）；`gpr` / `fpr` /
    /// `nzcv` 是入参出参（双向）：宿主把 VM 的 X0..X30 / V0..V31 / NZCV 拷到
    /// 真实寄存器，跑指令，再拷回。
    ///
    /// 默认实现 = 拒绝（返回 Err）。LinuxHost 在 aarch64 上提供真实实现：
    /// - 维护一个 RWX thunk 页
    /// - 模板：load regs → 执行 raw_instr（patch 进 thunk）→ save regs → ret
    /// - 不能跨指令边界（PC 相关指令、syscall 等不能这条路；那些 lifter 必须解码）
    fn native_exec(
        &mut self,
        raw_instr: u32,
        gpr: &mut [u64; 31],
        fpr: &mut [u128; 32],
        nzcv: &mut u32,
    ) -> Result<()> {
        let _ = (raw_instr, gpr, fpr, nzcv);
        Err(vmp_core::Error::vm("E:hybrid-not-supported"))
    }
}
