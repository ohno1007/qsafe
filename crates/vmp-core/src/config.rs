//! 保护配置。CLI 与各模块通过此结构沟通。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectLevel {
    /// 仅 lift 关键函数，体积/性能优先
    Light,
    /// 默认：lift 全部用户代码
    Standard,
    /// 强混淆：开启随机 ISA、垃圾指令、handler 复制、字节码加密
    Heavy,
    /// 极限：在 Heavy 基础上加多层加密、反调试、handler 多态
    Paranoid,
}

impl Default for ProtectLevel {
    fn default() -> Self {
        ProtectLevel::Standard
    }
}

#[derive(Debug, Clone)]
pub struct ProtectConfig {
    pub level: ProtectLevel,
    /// 随机化种子；同一种子 ⇒ 同一 ISA 编码（便于复现 / 调试）
    pub seed: u64,
    /// 是否对字节码加密（XOR + ChaCha 风格的轻量流加密）
    pub encrypt_bytecode: bool,
    /// 是否插入垃圾指令
    pub insert_junk: bool,
    /// handler 复制（同一语义多份不同形态）
    pub handler_duplication: u8,
    /// 反调试模块开关
    pub anti_debug: bool,
    /// 反虚拟机开关
    pub anti_vm: bool,
    /// 待保护函数白名单（空 ⇒ 全部用户函数）
    pub include_funcs: Vec<String>,
    /// 黑名单（永远不 lift）
    pub exclude_funcs: Vec<String>,
}

impl Default for ProtectConfig {
    fn default() -> Self {
        Self::from_level(ProtectLevel::Standard)
    }
}

impl ProtectConfig {
    pub fn from_level(level: ProtectLevel) -> Self {
        match level {
            ProtectLevel::Light => Self {
                level,
                seed: 0xC0FFEE,
                encrypt_bytecode: false,
                insert_junk: false,
                handler_duplication: 1,
                anti_debug: false,
                anti_vm: false,
                include_funcs: vec![],
                exclude_funcs: vec![],
            },
            ProtectLevel::Standard => Self {
                level,
                seed: 0xDEADBEEF,
                encrypt_bytecode: true,
                insert_junk: true,
                handler_duplication: 2,
                anti_debug: false,
                anti_vm: false,
                include_funcs: vec![],
                exclude_funcs: vec![],
            },
            ProtectLevel::Heavy => Self {
                level,
                seed: 0xA5A5_A5A5,
                encrypt_bytecode: true,
                insert_junk: true,
                handler_duplication: 4,
                anti_debug: true,
                anti_vm: false,
                include_funcs: vec![],
                exclude_funcs: vec![],
            },
            ProtectLevel::Paranoid => Self {
                level,
                seed: 0xFEED_FACE_DEAD_BEEF,
                encrypt_bytecode: true,
                insert_junk: true,
                // duplication=4 ≈ 208/220 opcode cap. Paranoid 的额外混淆来自
                // **每个 region 独立 IsaSpec** (v2 blob): 同一 VOp 在 funcA 跟
                // funcB 的 opcode 完全不同, 比单纯把 variants 拉到 8 强得多.
                handler_duplication: 4,
                anti_debug: true,
                anti_vm: true,
                include_funcs: vec![],
                exclude_funcs: vec![],
            },
        }
    }
}
