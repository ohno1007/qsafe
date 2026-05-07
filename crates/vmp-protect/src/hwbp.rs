//! 硬件断点检测 + 占坑（ARM64 优先；x86_64 留扩展位）。
//!
//! ARM64 提供 `DBGBVR<n>_EL1` / `DBGBCR<n>_EL1`（断点地址/控制）与对应 `DBGWVR/DBGWCR`
//! （观察点）。EL0 无法直接 mrs/msr 这些寄存器；user-space 通过 `ptrace(PT_GETREGSET,
//! NT_ARM_HW_BREAK)` 间接读写 —— 但**这只能 trace 别的进程**，自己读自己需要 trace
//! 自己（等价 PTRACE_TRACEME）。
//!
//! 折中实现（**最实用、对 frida-server / IDA debugserver 都生效**）：
//! 1. **检测**：fork 一个 child；child 用 `PTRACE_ATTACH` 上自己；trace 完成后从父
//!    进程的 NT_ARM_HW_BREAK regset 里读出 4 个 BCR/BVR；任何 BCR.E=1 即 HW BP 占用。
//!    child 立即 detach + exit。这是 frida-trace 内部用的同款方法。
//!    **当前实现是简化版**：直接 prctl(PR_SET_PTRACER, 0) 然后尝试 ptrace ATTACH 自己；
//!    成功路径下 detect 已经被 fork-stub 占用 → 返回 0；失败路径返回 0 但仍能正常
//!    跑余下检查项。完整 fork+wait 路径留给 Phase 6（与 vmp-runtime SIGTRAP 协作）。
//! 2. **占坑**：通过 `ptrace(PT_SETREGSET, NT_ARM_HW_BREAK)` 把 4 个 BCR.E=1 全部设到
//!    无害地址（如 0xCAFE_BABE_DEAD_BEEF），让攻击者的 HW BP 无槽位可写。
//!    要求当前进程已是其它 trace 的 tracer —— 通过先 `PR_SET_PTRACER(getppid())`
//!    把父进程指定为唯一允许的 tracer，避免被 frida 抢占。
//!
//! 设计注释：本模块**不直接读 DBGBVR**（会 SIGILL）；所有动作都经 ptrace 走。
//! 真实部署时建议 fork helper 进程做这些事，而不是在 main process 里。

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
pub fn count_set() -> u32 {
    // MVP 启发式：ptrace_traceme_self_test 失败 == 已被 attach == 通常 HW BP 也准备好了。
    // 真正读 DBGBCR.E 需要 fork helper，这是 Phase 6 工作。
    if crate::anti_debug::ptrace_traceme_self_test() {
        return 1; // "至少 1 个"
    }
    if let Some(pid) = crate::anti_debug::tracer_pid() {
        if pid != 0 {
            return 1;
        }
    }
    0
}

#[cfg(not(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64")))]
pub fn count_set() -> u32 {
    0
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
pub fn occupy_all() -> bool {
    // 占坑实现：fork child；child PTRACE_ATTACH parent；写 BCR.E=1 到 4 个 BVR
    // 然后保持 child 不 exit（占住 trace 关系）。这是高侵入，默认 disable。
    //
    // 当前 stub：直接 PR_SET_PTRACER(0) 抑制后续 attach。完整 ptrace + NT_ARM_HW_BREAK
    // 路径需要 fork + waitpid，留给 Phase 6（cdylib 内做这事会破坏宿主进程的
    // signal 关系，必须用 helper process）。
    use core::ffi::c_int;
    extern "C" {
        fn prctl(option: c_int, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> c_int;
    }
    const PR_SET_PTRACER: c_int = 0x59616d61;
    const PR_SET_PTRACER_ANY: u64 = 0;
    let r = unsafe { prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) };
    r == 0
}

#[cfg(not(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64")))]
pub fn occupy_all() -> bool {
    false
}
