//! vmp-protect
//!
//! 反分析能力的**真实可执行**实现 + 策略描述（CodeGen 阶段消费 + Runtime 阶段执行）。
//!
//! 设计：所有检测项以 [`ProtectFlags`] 位标志开关 → 既可在 CodeGen 阶段决定要嵌入
//! 哪些 stub 入口字节码，也可在 Runtime 阶段（cdylib / vmp-runtime）由配置 / 环境
//! 变量动态启停。
//!
//! - 静态层：`vmp_protect::plan(cfg, bc)` 计算 SHA-256 完整性 hash + 策略描述
//! - 运行时层：`vmp_protect::run_checks(flags) -> Verdict` 实际探测调试器 / dump
//!   工具 / hook 框架 / VM / 模拟器 / 注入。返回详细 Verdict，调用方决定如何响应
//!   （sileng log / abort / corrupt VM state）

pub mod anti_debug;
pub mod anti_dump;
pub mod anti_emulator;
pub mod anti_hook;
pub mod anti_ida;
pub mod anti_inject;
pub mod anti_unpack;
pub mod anti_vm;
pub mod hwbp;
pub mod integrity;

use vmp_core::ProtectConfig;

bitflags::bitflags! {
    /// 反分析检测项位掩码。每一位对应一个检测策略；位置 1 即启用。
    /// 默认 [`ProtectFlags::DEFAULT_HEAVY`] 启用全部低开销项；高开销项（如 page-crypto）
    /// 由调用方按需打开。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProtectFlags: u32 {
        const ANTI_DEBUG_PTRACE        = 1 << 0;
        const ANTI_DEBUG_TRACER_PID    = 1 << 1;
        const ANTI_DEBUG_PRCTL_DUMP    = 1 << 2;
        const ANTI_DEBUG_TIMING        = 1 << 3;
        /// 反 dump：检测 /proc/self/mem 被打开 / mprotect RX 段被复制
        const ANTI_DUMP_PROC_MEM       = 1 << 4;
        /// 反 hook：扫描 PLT/GOT 是否被 frida-gum / xhook 修改
        const ANTI_HOOK_PLT            = 1 << 5;
        /// 反 hook：扫描函数入口是否被 inline-hook（5 字节 jmp / B 跳板）
        const ANTI_HOOK_INLINE         = 1 << 6;
        /// 反 IDA：检测 IDA debug server / IDA stub 字符串
        const ANTI_IDA                 = 1 << 7;
        /// 反脱壳：完整性 SHA-256 校验代码段
        const ANTI_UNPACK_INTEGRITY    = 1 << 8;
        /// 反 VM (hypervisor 位 / DMI vendor / 时间膨胀)
        const ANTI_VM                  = 1 << 9;
        /// 反模拟器：Android QEMU / Genymotion / BlueStacks
        const ANTI_EMULATOR            = 1 << 10;
        /// 反注入：扫 /proc/self/maps 找 frida / xposed / substrate
        const ANTI_INJECT_FRIDA        = 1 << 11;
        const ANTI_INJECT_XPOSED       = 1 << 12;
        const ANTI_INJECT_SUBSTRATE    = 1 << 13;
        /// 硬件断点检测：读 ARM64 DBGBVR/DBGBCR via signal context；x86 DR0..7
        const HWBP_DETECT              = 1 << 14;
        /// 硬件断点占坑：占满 4 个 BCR / 4 个 DR 让攻击者无槽位可下
        const HWBP_OCCUPY              = 1 << 15;

        /// 默认 heavy：所有低开销项
        const DEFAULT_HEAVY = Self::ANTI_DEBUG_PTRACE.bits()
            | Self::ANTI_DEBUG_TRACER_PID.bits()
            | Self::ANTI_DEBUG_PRCTL_DUMP.bits()
            | Self::ANTI_DEBUG_TIMING.bits()
            | Self::ANTI_DUMP_PROC_MEM.bits()
            | Self::ANTI_HOOK_PLT.bits()
            | Self::ANTI_HOOK_INLINE.bits()
            | Self::ANTI_IDA.bits()
            | Self::ANTI_UNPACK_INTEGRITY.bits()
            | Self::ANTI_VM.bits()
            | Self::ANTI_EMULATOR.bits()
            | Self::ANTI_INJECT_FRIDA.bits()
            | Self::ANTI_INJECT_XPOSED.bits()
            | Self::ANTI_INJECT_SUBSTRATE.bits()
            | Self::HWBP_DETECT.bits();

        /// Paranoid：DEFAULT_HEAVY + 占坑硬件断点
        const PARANOID = Self::DEFAULT_HEAVY.bits() | Self::HWBP_OCCUPY.bits();
    }
}

impl ProtectFlags {
    /// 从环境变量 `QVMP_FLAGS` 解析（"+" 分隔关键字，如 `anti_debug+anti_hook`）。
    /// 未设置时 fallback 到 `DEFAULT_HEAVY`。
    pub fn from_env() -> Self {
        let val = std::env::var("QVMP_FLAGS").ok();
        match val.as_deref() {
            None => Self::DEFAULT_HEAVY,
            Some("paranoid") => Self::PARANOID,
            Some("none") => Self::empty(),
            Some(s) => parse_keywords(s),
        }
    }
}

fn parse_keywords(s: &str) -> ProtectFlags {
    let mut f = ProtectFlags::empty();
    for kw in s.split(|c: char| c == '+' || c == ',' || c == ' ') {
        let bit = match kw.trim().to_lowercase().as_str() {
            "anti_debug" => {
                ProtectFlags::ANTI_DEBUG_PTRACE
                    | ProtectFlags::ANTI_DEBUG_TRACER_PID
                    | ProtectFlags::ANTI_DEBUG_PRCTL_DUMP
                    | ProtectFlags::ANTI_DEBUG_TIMING
            }
            "anti_dump" => ProtectFlags::ANTI_DUMP_PROC_MEM,
            "anti_hook" => ProtectFlags::ANTI_HOOK_PLT | ProtectFlags::ANTI_HOOK_INLINE,
            "anti_ida" => ProtectFlags::ANTI_IDA,
            "anti_unpack" => ProtectFlags::ANTI_UNPACK_INTEGRITY,
            "anti_vm" => ProtectFlags::ANTI_VM,
            "anti_emulator" | "anti_emu" => ProtectFlags::ANTI_EMULATOR,
            "anti_inject" => {
                ProtectFlags::ANTI_INJECT_FRIDA
                    | ProtectFlags::ANTI_INJECT_XPOSED
                    | ProtectFlags::ANTI_INJECT_SUBSTRATE
            }
            "hwbp" => ProtectFlags::HWBP_DETECT,
            "hwbp_occupy" => ProtectFlags::HWBP_OCCUPY,
            "" => ProtectFlags::empty(),
            _ => ProtectFlags::empty(),
        };
        f |= bit;
    }
    f
}

/// 一次反分析探测的综合结论。**单一布尔不够**：用户可能想区分 "TracerPid != 0"
/// 与 "frida 进程在 maps 里"，前者打日志即可，后者直接 abort。
#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub debugger_attached: bool,
    pub debugger_evidence: Vec<&'static str>,
    pub dump_in_progress: bool,
    pub dump_evidence: Vec<&'static str>,
    pub hooks_present: bool,
    pub hook_evidence: Vec<&'static str>,
    pub ida_attached: bool,
    pub ida_evidence: Vec<&'static str>,
    pub vm_or_emulator: bool,
    pub vm_evidence: Vec<&'static str>,
    pub injection_present: bool,
    pub inject_evidence: Vec<&'static str>,
    pub hwbp_count: u32,
    pub integrity_failed: bool,
}

impl Verdict {
    pub fn any_threat(&self) -> bool {
        self.debugger_attached
            || self.dump_in_progress
            || self.hooks_present
            || self.ida_attached
            || self.vm_or_emulator
            || self.injection_present
            || self.hwbp_count > 0
            || self.integrity_failed
    }
}

/// 顶层入口：按 flags 跑所有启用项；返回综合 Verdict。
pub fn run_checks(flags: ProtectFlags, expected_text_hash: Option<&[u8; 32]>) -> Verdict {
    let mut v = Verdict::default();

    // === 反调试 ===
    if flags.contains(ProtectFlags::ANTI_DEBUG_PTRACE) {
        if anti_debug::ptrace_traceme_self_test() {
            v.debugger_attached = true;
            v.debugger_evidence.push("ptrace_traceme_failed");
        }
    }
    if flags.contains(ProtectFlags::ANTI_DEBUG_TRACER_PID) {
        if let Some(pid) = anti_debug::tracer_pid() {
            if pid != 0 {
                v.debugger_attached = true;
                v.debugger_evidence.push("tracer_pid_nonzero");
            }
        }
    }
    if flags.contains(ProtectFlags::ANTI_DEBUG_PRCTL_DUMP) {
        anti_debug::prctl_set_undumpable();
    }
    if flags.contains(ProtectFlags::ANTI_DEBUG_TIMING) {
        if anti_debug::timing_anomaly() {
            v.debugger_attached = true;
            v.debugger_evidence.push("timing_anomaly");
        }
    }

    // === 反 dump ===
    if flags.contains(ProtectFlags::ANTI_DUMP_PROC_MEM) {
        if anti_dump::proc_self_mem_open_count() > 0 {
            v.dump_in_progress = true;
            v.dump_evidence.push("proc_self_mem_open");
        }
    }

    // === 反 hook ===
    if flags.contains(ProtectFlags::ANTI_HOOK_PLT) {
        if anti_hook::plt_got_modified() {
            v.hooks_present = true;
            v.hook_evidence.push("plt_got_modified");
        }
    }
    if flags.contains(ProtectFlags::ANTI_HOOK_INLINE) {
        if anti_hook::inline_hook_in_libc() {
            v.hooks_present = true;
            v.hook_evidence.push("inline_hook_libc");
        }
    }

    // === 反 IDA ===
    if flags.contains(ProtectFlags::ANTI_IDA) {
        let ev = anti_ida::detect();
        if !ev.is_empty() {
            v.ida_attached = true;
            v.ida_evidence.extend(ev);
        }
    }

    // === 反脱壳：完整性 ===
    if flags.contains(ProtectFlags::ANTI_UNPACK_INTEGRITY) {
        if let Some(expected) = expected_text_hash {
            if !anti_unpack::verify_text_hash(expected) {
                v.integrity_failed = true;
            }
        }
    }

    // === 反 VM ===
    if flags.contains(ProtectFlags::ANTI_VM) {
        let ev = anti_vm::detect_vm();
        if !ev.is_empty() {
            v.vm_or_emulator = true;
            v.vm_evidence.extend(ev);
        }
    }

    // === 反模拟器 ===
    if flags.contains(ProtectFlags::ANTI_EMULATOR) {
        let ev = anti_emulator::detect();
        if !ev.is_empty() {
            v.vm_or_emulator = true;
            v.vm_evidence.extend(ev);
        }
    }

    // === 反注入 ===
    if flags.contains(ProtectFlags::ANTI_INJECT_FRIDA) {
        if anti_inject::frida_in_maps() {
            v.injection_present = true;
            v.inject_evidence.push("frida_in_maps");
        }
    }
    if flags.contains(ProtectFlags::ANTI_INJECT_XPOSED) {
        if anti_inject::xposed_in_maps() {
            v.injection_present = true;
            v.inject_evidence.push("xposed_in_maps");
        }
    }
    if flags.contains(ProtectFlags::ANTI_INJECT_SUBSTRATE) {
        if anti_inject::substrate_in_maps() {
            v.injection_present = true;
            v.inject_evidence.push("substrate_in_maps");
        }
    }

    // === 硬件断点 ===
    if flags.contains(ProtectFlags::HWBP_DETECT) {
        v.hwbp_count = hwbp::count_set();
    }
    if flags.contains(ProtectFlags::HWBP_OCCUPY) {
        hwbp::occupy_all();
    }

    v
}

#[derive(Debug)]
pub struct ProtectionPlan {
    pub flags: ProtectFlags,
    pub integrity_check: Option<[u8; 32]>,
}

impl Default for ProtectionPlan {
    fn default() -> Self {
        Self {
            flags: ProtectFlags::empty(),
            integrity_check: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_from_env_keywords() {
        std::env::set_var("QVMP_FLAGS", "anti_debug+anti_hook");
        let f = ProtectFlags::from_env();
        assert!(f.contains(ProtectFlags::ANTI_DEBUG_PTRACE));
        assert!(f.contains(ProtectFlags::ANTI_HOOK_PLT));
        assert!(!f.contains(ProtectFlags::ANTI_VM));
        std::env::remove_var("QVMP_FLAGS");
    }

    #[test]
    fn flags_paranoid_includes_default_heavy() {
        let p = ProtectFlags::PARANOID;
        let h = ProtectFlags::DEFAULT_HEAVY;
        assert!(p.contains(h));
        assert!(p.contains(ProtectFlags::HWBP_OCCUPY));
    }

    #[test]
    fn run_checks_empty_returns_clean() {
        let v = run_checks(ProtectFlags::empty(), None);
        // 不开任何检查 → 结论必然 clean
        assert!(!v.any_threat());
    }
}

pub fn plan(cfg: &ProtectConfig, bytecode: &[u8]) -> ProtectionPlan {
    let mut flags = ProtectFlags::empty();
    if cfg.anti_debug {
        flags |= ProtectFlags::ANTI_DEBUG_PTRACE
            | ProtectFlags::ANTI_DEBUG_TRACER_PID
            | ProtectFlags::ANTI_DEBUG_PRCTL_DUMP
            | ProtectFlags::ANTI_DEBUG_TIMING;
    }
    if cfg.anti_vm {
        flags |= ProtectFlags::ANTI_VM | ProtectFlags::ANTI_EMULATOR;
    }
    ProtectionPlan {
        flags,
        integrity_check: Some(integrity::sha256(bytecode)),
    }
}
