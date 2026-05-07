//! 反调试策略。
//!
//! 这里给出 **策略描述**，具体执行由 stub 在运行时基于 OS / arch 完成：
//! - Linux/Android: prctl(PR_SET_DUMPABLE, 0) + 读 /proc/self/status:TracerPid + ptrace(PTRACE_TRACEME)
//! - Windows:       IsDebuggerPresent + CheckRemoteDebuggerPresent + NtQueryInformationProcess
//! - macOS/iOS:     sysctl P_TRACED + ptrace(PT_DENY_ATTACH)
//!
//! stub 中的实现可以选择其中一个或多个，被 [`Strategy`] 描述。

use vmp_core::Os;

#[derive(Debug, Clone, Copy)]
pub enum Strategy {
    PtraceTraceMe,
    ProcStatusTracerPid,
    PrctlDumpable,
    SysctlPTraced,
    IsDebuggerPresent,
    CheckRemoteDebuggerPresent,
    NtQueryInformationProcess,
    PtDenyAttach,
}

pub fn default_strategies(os: Os) -> Vec<Strategy> {
    match os {
        Os::Linux | Os::Android => vec![
            Strategy::PtraceTraceMe,
            Strategy::ProcStatusTracerPid,
            Strategy::PrctlDumpable,
        ],
        Os::Windows => vec![
            Strategy::IsDebuggerPresent,
            Strategy::CheckRemoteDebuggerPresent,
            Strategy::NtQueryInformationProcess,
        ],
        Os::Macos | Os::Ios => vec![Strategy::PtDenyAttach, Strategy::SysctlPTraced],
        Os::Bare => vec![],
    }
}
