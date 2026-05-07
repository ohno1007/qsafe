//! vmp-protect
//!
//! 反分析能力。当前模块以「策略 + 字节码模板」形式提供，运行时由 stub 真正执行。
//!
//! - [`anti_debug`] : 检测调试器（PTRACE_ME_TRACED / IsDebuggerPresent / proc/self/status TracerPid）
//! - [`anti_vm`]    : 检测沙盒 / hypervisor 标志
//! - [`integrity`]  : 计算字节码 SHA-256，stub 启动时校验

pub mod anti_debug;
pub mod anti_vm;
pub mod integrity;

use vmp_core::ProtectConfig;

#[derive(Debug, Default)]
pub struct ProtectionPlan {
    pub anti_debug_enabled: bool,
    pub anti_vm_enabled: bool,
    pub integrity_check: Option<[u8; 32]>,
}

pub fn plan(cfg: &ProtectConfig, bytecode: &[u8]) -> ProtectionPlan {
    ProtectionPlan {
        anti_debug_enabled: cfg.anti_debug,
        anti_vm_enabled: cfg.anti_vm,
        integrity_check: Some(integrity::sha256(bytecode)),
    }
}
