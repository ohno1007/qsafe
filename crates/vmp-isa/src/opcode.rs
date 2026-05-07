//! 语义指令枚举。所有 lifter 都把目标架构指令翻译成这些 `VOp`。
//!
//! 这是「语义层」，在所有构建之间稳定。物理编码（实际 byte 形式）由
//! [`crate::IsaSpec`] 决定，每次构建随机化。

use std::fmt;

/// 操作宽度。Debug/Display 在 release 模式只显示数字，不暴露 enum 名称字符串。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Width {
    W8,
    W16,
    W32,
    W64,
}

impl fmt::Debug for Width {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        {
            f.write_str(match self {
                Width::W8 => "W8",
                Width::W16 => "W16",
                Width::W32 => "W32",
                Width::W64 => "W64",
            })
        }
        #[cfg(not(debug_assertions))]
        {
            write!(f, "w{}", self.bytes() * 8)
        }
    }
}

impl Width {
    pub fn bytes(self) -> usize {
        match self {
            Width::W8 => 1,
            Width::W16 => 2,
            Width::W32 => 4,
            Width::W64 => 8,
        }
    }
    pub fn mask(self) -> u64 {
        match self {
            Width::W8 => 0xFF,
            Width::W16 => 0xFFFF,
            Width::W32 => 0xFFFF_FFFF,
            Width::W64 => u64::MAX,
        }
    }
    pub fn from_bytes(b: usize) -> Option<Self> {
        match b {
            1 => Some(Width::W8),
            2 => Some(Width::W16),
            4 => Some(Width::W32),
            8 => Some(Width::W64),
            _ => None,
        }
    }
}

/// 条件码（与 ARM64 cond 对齐，但语义上是通用的）
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Cond {
    Eq = 0,
    Ne = 1,
    Cs = 2,
    Cc = 3,
    Mi = 4,
    Pl = 5,
    Vs = 6,
    Vc = 7,
    Hi = 8,
    Ls = 9,
    Ge = 10,
    Lt = 11,
    Gt = 12,
    Le = 13,
    Al = 14,
    Nv = 15,
}

impl fmt::Debug for Cond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        {
            f.write_str(match self {
                Cond::Eq => "Eq",
                Cond::Ne => "Ne",
                Cond::Cs => "Cs",
                Cond::Cc => "Cc",
                Cond::Mi => "Mi",
                Cond::Pl => "Pl",
                Cond::Vs => "Vs",
                Cond::Vc => "Vc",
                Cond::Hi => "Hi",
                Cond::Ls => "Ls",
                Cond::Ge => "Ge",
                Cond::Lt => "Lt",
                Cond::Gt => "Gt",
                Cond::Le => "Le",
                Cond::Al => "Al",
                Cond::Nv => "Nv",
            })
        }
        #[cfg(not(debug_assertions))]
        {
            write!(f, "c{:x}", *self as u8)
        }
    }
}

impl Cond {
    pub fn from_u8(v: u8) -> Self {
        // Safe: 0..=15 总有效；其它值统一视为 AL
        match v & 0xF {
            0 => Cond::Eq,
            1 => Cond::Ne,
            2 => Cond::Cs,
            3 => Cond::Cc,
            4 => Cond::Mi,
            5 => Cond::Pl,
            6 => Cond::Vs,
            7 => Cond::Vc,
            8 => Cond::Hi,
            9 => Cond::Ls,
            10 => Cond::Ge,
            11 => Cond::Lt,
            12 => Cond::Gt,
            13 => Cond::Le,
            14 => Cond::Al,
            _ => Cond::Nv,
        }
    }
}

/// 语义操作码。
///
/// 注意：这里没有「寄存器编号」之类的东西 —— 那部分由 [`crate::Operand`] 描述。
/// 这里只列出语义类别。
///
/// Debug/Display 实现在 `release` 模式只暴露 `v<hex>` 形式的数字编号，绝对不会
/// 把 "Nop"/"MovR"/"Add" 这种助记符写到 .rodata —— 防止逆向直接拿到 VM 操作码字典。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum VOp {
    Nop = 0,
    // ---- 数据传输 ----
    MovR = 1,    // Rd = Rs
    MovI = 2,    // Rd = imm
    Load = 3,    // Rd = mem[Rs+imm], width
    Store = 4,   // mem[Rs+imm] = Rd, width
    Push = 5,
    Pop = 6,
    // ---- ALU ----
    Add = 10,
    Sub = 11,
    Mul = 12,
    UDiv = 13,
    SDiv = 14,
    And = 15,
    Or = 16,
    Xor = 17,
    Shl = 18,
    LShr = 19,
    AShr = 20,
    Ror = 21,
    Neg = 22,
    Not = 23,
    /// Rd = matches(cond) ? Rs : Rt
    CSel = 24,
    // ---- 比较 ----
    Cmp = 30, // 设置 NZCV (标志位)
    Tst = 31, // and 后只更新标志位
    // ---- 控制流 ----
    Br = 40,    // 无条件跳转 (相对，offset 在 imm 中)
    BCond = 41, // 条件跳转 (cond 在 op-extra 中)
    Call = 42,  // 调用 vm 内部偏移
    Ret = 43,
    // ---- VM <-> 宿主 切换 ----
    /// 通过宿主调用 native 函数（按指针）。
    NativeCall = 50,
    /// 退出 VM，回到 stub 调用方（带返回值）。
    VExit = 51,
    /// 重新进入 VM 一段新代码。
    VEnter = 52,
    /// 跨 region 调用：imm = 目标 region_id；args 在 V0..V7；返回值 V0。
    /// 由 stub 的 NestedDispatchHost 在 host bridge 里递归 dispatch_vm 实现。
    /// 这条指令让"多函数 / 跨函数 BL" 不需要全局合并字节码池就能工作，
    /// 同时保留 per-region 独立加密（每个 region 各自 IV salt）。
    CallRegion = 53,
    // ---- 系统 ----
    Syscall = 60,
    Trap = 61,
    // ---- 反分析 ----
    /// 仅消耗指针；解释器以非平凡方式 noop。
    Junk = 70,
    /// 把当前 PC 与一个魔术常量混淆，提高静态分析难度。
    Obfuscate = 71,

    // ---- FP / NEON 标量 ----
    /// FP load: vreg[Rd] (低 width 位) = mem[regs[Rs] + imm]，width=W32 单精度，W64 双精度，W128 整 Q
    FLoad = 80,
    /// FP store
    FStore = 81,
    /// FP move register: vreg[Rd] = vreg[Rs]
    FMovR = 82,
    /// FP move from GPR: vreg[Rd] 低 width 位 = regs[Rs]
    FMovFromGpr = 83,
    /// FP move to GPR: regs[Rd] = vreg[Rs] 低 width 位
    FMovToGpr = 84,
    /// FP arithmetic: F[Rd] = F[Rs] op F[Rt]，width 决定单 / 双
    FAdd = 85,
    FSub = 86,
    FMul = 87,
    FDiv = 88,
    /// FP compare: 设 NZCV
    FCmp = 89,
    /// FP→Int 截断（toward zero）
    FCvtZS = 90,
    /// Int→FP（signed）
    SCvtF = 91,

    // ---- Atomics（LSE + LL/SC，单线程 VM 环境下 LL/SC 退化为普通 load/store）----
    /// Atomic add: tmp = mem[Rs] ; mem[Rs] = tmp + Rt ; Rd = tmp
    AtomicAdd = 100,
    /// Atomic swap: tmp = mem[Rs] ; mem[Rs] = Rt ; Rd = tmp
    AtomicSwap = 101,
    /// Compare-and-swap: cmp_val=Rd_in ; if mem[Rs]==Rd_in then mem[Rs]=Rt ; Rd_out = old mem[Rs]
    /// （为简化把 Rd 同时作为输入输出。lifter 会在前面 emit MovR 备份）
    AtomicCas = 102,
    /// 内存屏障：单线程 VM 环境下 noop
    Barrier = 103,
}

pub const VOP_COUNT: usize = 64; // 上限；实际枚举值不超过此数

impl VOp {
    pub fn from_u16(v: u16) -> Option<Self> {
        // 简化：用 transmute 不安全，所以列举一遍
        let result = match v {
            0 => VOp::Nop,
            1 => VOp::MovR,
            2 => VOp::MovI,
            3 => VOp::Load,
            4 => VOp::Store,
            5 => VOp::Push,
            6 => VOp::Pop,
            10 => VOp::Add,
            11 => VOp::Sub,
            12 => VOp::Mul,
            13 => VOp::UDiv,
            14 => VOp::SDiv,
            15 => VOp::And,
            16 => VOp::Or,
            17 => VOp::Xor,
            18 => VOp::Shl,
            19 => VOp::LShr,
            20 => VOp::AShr,
            21 => VOp::Ror,
            22 => VOp::Neg,
            23 => VOp::Not,
            24 => VOp::CSel,
            30 => VOp::Cmp,
            31 => VOp::Tst,
            40 => VOp::Br,
            41 => VOp::BCond,
            42 => VOp::Call,
            43 => VOp::Ret,
            50 => VOp::NativeCall,
            51 => VOp::VExit,
            52 => VOp::VEnter,
            53 => VOp::CallRegion,
            60 => VOp::Syscall,
            61 => VOp::Trap,
            70 => VOp::Junk,
            71 => VOp::Obfuscate,
            80 => VOp::FLoad,
            81 => VOp::FStore,
            82 => VOp::FMovR,
            83 => VOp::FMovFromGpr,
            84 => VOp::FMovToGpr,
            85 => VOp::FAdd,
            86 => VOp::FSub,
            87 => VOp::FMul,
            88 => VOp::FDiv,
            89 => VOp::FCmp,
            90 => VOp::FCvtZS,
            91 => VOp::SCvtF,
            100 => VOp::AtomicAdd,
            101 => VOp::AtomicSwap,
            102 => VOp::AtomicCas,
            103 => VOp::Barrier,
            _ => return None,
        };
        Some(result)
    }

    pub fn all() -> &'static [VOp] {
        &[
            VOp::Nop,
            VOp::MovR,
            VOp::MovI,
            VOp::Load,
            VOp::Store,
            VOp::Push,
            VOp::Pop,
            VOp::Add,
            VOp::Sub,
            VOp::Mul,
            VOp::UDiv,
            VOp::SDiv,
            VOp::And,
            VOp::Or,
            VOp::Xor,
            VOp::Shl,
            VOp::LShr,
            VOp::AShr,
            VOp::Ror,
            VOp::Neg,
            VOp::Not,
            VOp::CSel,
            VOp::Cmp,
            VOp::Tst,
            VOp::Br,
            VOp::BCond,
            VOp::Call,
            VOp::Ret,
            VOp::NativeCall,
            VOp::VExit,
            VOp::VEnter,
            VOp::CallRegion,
            VOp::Syscall,
            VOp::Trap,
            VOp::Junk,
            VOp::Obfuscate,
            VOp::FLoad,
            VOp::FStore,
            VOp::FMovR,
            VOp::FMovFromGpr,
            VOp::FMovToGpr,
            VOp::FAdd,
            VOp::FSub,
            VOp::FMul,
            VOp::FDiv,
            VOp::FCmp,
            VOp::FCvtZS,
            VOp::SCvtF,
            VOp::AtomicAdd,
            VOp::AtomicSwap,
            VOp::AtomicCas,
            VOp::Barrier,
        ]
    }
}

impl fmt::Debug for VOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        {
            return f.write_str(self.debug_name());
        }
        #[cfg(not(debug_assertions))]
        {
            write!(f, "v{:02x}", *self as u16)
        }
    }
}

impl fmt::Display for VOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl VOp {
    /// 助记符表 —— 仅 debug build 内嵌。release 下整个 match 表会被 dead-code-eliminate。
    #[cfg(debug_assertions)]
    fn debug_name(&self) -> &'static str {
        match self {
            VOp::Nop => "Nop",
            VOp::MovR => "MovR",
            VOp::MovI => "MovI",
            VOp::Load => "Load",
            VOp::Store => "Store",
            VOp::Push => "Push",
            VOp::Pop => "Pop",
            VOp::Add => "Add",
            VOp::Sub => "Sub",
            VOp::Mul => "Mul",
            VOp::UDiv => "UDiv",
            VOp::SDiv => "SDiv",
            VOp::And => "And",
            VOp::Or => "Or",
            VOp::Xor => "Xor",
            VOp::Shl => "Shl",
            VOp::LShr => "LShr",
            VOp::AShr => "AShr",
            VOp::Ror => "Ror",
            VOp::Neg => "Neg",
            VOp::Not => "Not",
            VOp::CSel => "CSel",
            VOp::Cmp => "Cmp",
            VOp::Tst => "Tst",
            VOp::Br => "Br",
            VOp::BCond => "BCond",
            VOp::Call => "Call",
            VOp::Ret => "Ret",
            VOp::NativeCall => "NativeCall",
            VOp::VExit => "VExit",
            VOp::VEnter => "VEnter",
            VOp::CallRegion => "CallRegion",
            VOp::Syscall => "Syscall",
            VOp::Trap => "Trap",
            VOp::Junk => "Junk",
            VOp::Obfuscate => "Obfuscate",
            VOp::FLoad => "FLoad",
            VOp::FStore => "FStore",
            VOp::FMovR => "FMovR",
            VOp::FMovFromGpr => "FMovFromGpr",
            VOp::FMovToGpr => "FMovToGpr",
            VOp::FAdd => "FAdd",
            VOp::FSub => "FSub",
            VOp::FMul => "FMul",
            VOp::FDiv => "FDiv",
            VOp::FCmp => "FCmp",
            VOp::FCvtZS => "FCvtZS",
            VOp::SCvtF => "SCvtF",
            VOp::AtomicAdd => "AtomicAdd",
            VOp::AtomicSwap => "AtomicSwap",
            VOp::AtomicCas => "AtomicCas",
            VOp::Barrier => "Barrier",
        }
    }
}
