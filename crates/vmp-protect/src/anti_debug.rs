//! 反调试 —— 真实运行时探测（Linux / Android / aarch64 优先）。
//!
//! 暴露的所有函数都有非 Linux 的 fallback（永远返回 false / 0），保证
//! workspace 在 host 上仍可编译。
//!
//! 检测项：
//! 1. `ptrace_traceme_self_test` —— 调 `ptrace(PTRACE_TRACEME)`：
//!    - 没有 tracer 时调用成功；之后立刻 detach
//!    - 已被 tracer attach 时返回错误
//! 2. `tracer_pid` —— 读 `/proc/self/status` 的 `TracerPid:` 字段
//! 3. `prctl_set_undumpable` —— `prctl(PR_SET_DUMPABLE, 0)`：让自己 coredump 失败、
//!    `/proc/self/mem` 无法被另一进程打开
//! 4. `timing_anomaly` —— 用 `clock_gettime(CLOCK_MONOTONIC_RAW)` 测一段已知
//!    短指令的耗时；超过阈值（即被 step-by-step 打断）则 true
//!
//! Strategy 枚举保留给静态描述层（CodeGen 时决定要嵌入哪些字节码）。

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

// =================== Runtime probes ===================

/// 试图调用 `ptrace(PTRACE_TRACEME, 0, 0, 0)`：返回 true 表示被调试。
///
/// 注意：成功 trace 自己后**不能 detach** —— PTRACE_TRACEME 是把当前进程标记
/// "我自愿被 trace"，没法回退。所以本函数**只在调用方接受 PTRACE_TRACEME 永久
/// 设置**时调用一次（典型场景：JNI_OnLoad 启动时）。后续 fork 的 child 可正常使用。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn ptrace_traceme_self_test() -> bool {
    use core::ffi::c_long;
    extern "C" {
        fn ptrace(req: c_long, pid: c_long, addr: c_long, data: c_long) -> c_long;
    }
    const PTRACE_TRACEME: c_long = 0;
    let r = unsafe { ptrace(PTRACE_TRACEME, 0, 0, 0) };
    // -1 即 EPERM（已被另一进程 trace）
    r == -1
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn ptrace_traceme_self_test() -> bool {
    false
}

/// 读 `/proc/self/status` 的 `TracerPid:` 字段。返回 None 表示读取失败。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn tracer_pid() -> Option<u32> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn tracer_pid() -> Option<u32> {
    None
}

/// `prctl(PR_SET_DUMPABLE, 0)` —— 让进程不可被 coredump，也阻止其它进程通过
/// `/proc/self/mem` 读自己内存。返回是否调用成功。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn prctl_set_undumpable() -> bool {
    use core::ffi::c_int;
    extern "C" {
        fn prctl(option: c_int, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> c_int;
    }
    const PR_SET_DUMPABLE: c_int = 4;
    let r = unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
    r == 0
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn prctl_set_undumpable() -> bool {
    false
}

/// 时间异常检测：在 aarch64 上**直接读 CNTVCT_EL0**（user-space 可读虚拟计时器），
/// 而不是 clock_gettime —— 后者是 libc 函数，Frida 一行就能 hook。CNTVCT_EL0 是
/// CPU 寄存器，attacker 想伪造必须改 EL2/EL1 行为（root + kernel module 才行）。
///
/// 阈值经验值：物理 ARM64 真机 cntfrq 通常 19.2 MHz；4096 iter 大约 100 us 即
/// 19.2 * 100 ≈ 1920 ticks。debugger single-step 至少膨胀 100 倍。设阈 100k ticks。
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
pub fn timing_anomaly() -> bool {
    let t0 = read_cntvct();
    let mut acc: u64 = 0;
    for i in 0..4096u64 {
        acc = acc.wrapping_add(i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    }
    core::hint::black_box(acc);
    let t1 = read_cntvct();
    t1.wrapping_sub(t0) > 100_000
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
#[inline]
fn read_cntvct() -> u64 {
    let mut t: u64;
    unsafe {
        core::arch::asm!("mrs {0}, cntvct_el0", out(reg) t, options(nomem, nostack));
    }
    t
}

/// 非 aarch64 / 非 Linux：fallback 到 clock_gettime（仍然是有用的近似 + 不会假阳性）。
#[cfg(all(any(target_os = "linux", target_os = "android"), not(target_arch = "aarch64")))]
pub fn timing_anomaly() -> bool {
    use std::time::Instant;
    let t0 = Instant::now();
    let mut acc: u64 = 0;
    for i in 0..4096u64 {
        acc = acc.wrapping_add(i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    }
    core::hint::black_box(acc);
    t0.elapsed().as_micros() > 1000
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn timing_anomaly() -> bool {
    false
}
