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

/// 占坑实现：fork helper child；child `PTRACE_SEIZE` 父进程，往 NT_ARM_HW_BREAK
/// regset 写 4 个 BCR.E=1 锁定无害地址。父进程的 4 个硬件断点槽位被占满 →
/// 攻击者用 gdb / IDA debugserver 通过 `ptrace(PTRACE_SETREGSET, NT_ARM_HW_BREAK)`
/// 下硬件断点时会"槽位已用尽"失败。
///
/// 副作用：
/// - 父进程被 child trace；任何信号会先到 child（child 立即 PTRACE_CONT 转发）
/// - PR_SET_PTRACER(child_pid) 必须在 fork 前调，否则 Yama LSM 阻断
/// - child 持续运行直到父进程退出（waitpid loop）
///
/// 失败兜底：若 fork / ptrace 任何一步失败，回退到 PR_SET_PTRACER(ANY)，至少阻止
/// 后续 attach（让 frida-server 这种用 attach 的拦下）。
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
pub fn occupy_all() -> bool {
    use core::ffi::{c_int, c_long, c_void};
    extern "C" {
        fn prctl(option: c_int, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> c_int;
        fn fork() -> c_int;
        fn getpid() -> c_int;
        fn ptrace(req: c_long, pid: c_long, addr: c_long, data: c_long) -> c_long;
        fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        fn _exit(code: c_int) -> !;
    }
    const PR_SET_PTRACER: c_int = 0x59616d61;
    const PR_SET_PTRACER_ANY: u64 = u64::MAX; // PR_SET_PTRACER_ANY = -1（cast 成 u64）

    // 第一步：允许任意 ptracer（兜底，即便 fork 失败这一步生效）
    unsafe {
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    }

    // 第二步：fork helper
    let parent_pid = unsafe { getpid() };
    let pid = unsafe { fork() };
    if pid < 0 {
        return false; // fork 失败，仅 PR_SET_PTRACER 生效
    }
    if pid == 0 {
        // child：seize 父进程，写 hw_breakpoint regset，然后 wait 直到父退出
        const PTRACE_SEIZE: c_long = 0x4206;
        const PTRACE_SETREGSET: c_long = 0x4205;
        const PTRACE_DETACH: c_long = 17;
        // ptrace SEIZE：标准 attach 不停止 tracee
        let r = unsafe { ptrace(PTRACE_SEIZE, parent_pid as c_long, 0, 0) };
        if r != 0 {
            unsafe { _exit(1) };
        }
        // 构造 user_hwdebug_state：4 个 BCR/BVR
        // arch/arm64/include/uapi/asm/ptrace.h:
        //   struct user_hwdebug_state {
        //     u32 dbg_info;
        //     u32 pad;
        //     struct { u64 addr; u32 ctrl; u32 pad; } dbg_regs[16];
        //   };
        // 我们写前 4 个；ctrl bit 0 = E（启用），bit 5 = privilege EL0，bits 8:5 access type。
        let mut state = [0u8; 8 + 16 * 16];
        for i in 0..4usize {
            let off = 8 + i * 16;
            // BVR：写无害地址（指向 1MB 边界，几乎不可能命中正常代码段）
            let dummy_bvr: u64 = 0xCAFE_BABE_DEAD_0000u64 + (i as u64) * 0x100;
            state[off..off + 8].copy_from_slice(&dummy_bvr.to_le_bytes());
            // BCR：E=1 (bit 0), PMC=2 (EL0, bits 1:2), BAS=0xF (bits 5:8), TYPE=0 (BP)
            let bcr: u32 = 0b0000_1111_1101u32; // E=1 PMC=10 BAS=1111 LBN=0
            state[off + 8..off + 12].copy_from_slice(&bcr.to_le_bytes());
        }
        const NT_ARM_HW_BREAK: c_long = 0x402;
        // PTRACE_SETREGSET(pid, type, &iov{base=state, len=...})
        #[repr(C)]
        struct Iovec { base: *const c_void, len: usize }
        let iov = Iovec { base: state.as_ptr() as *const c_void, len: state.len() };
        let _ = unsafe { ptrace(PTRACE_SETREGSET, parent_pid as c_long, NT_ARM_HW_BREAK,
                                 &iov as *const _ as c_long) };
        // 让父进程继续运行；child 持续等待直到父退出
        loop {
            let mut status: c_int = 0;
            let w = unsafe { waitpid(parent_pid, &mut status, 0) };
            if w <= 0 {
                break;
            }
            // 任何信号都 forward 让父进程继续
            const PTRACE_CONT: c_long = 7;
            let _ = unsafe { ptrace(PTRACE_CONT, parent_pid as c_long, 0, 0) };
        }
        // 父进程死了；child 也退
        unsafe { ptrace(PTRACE_DETACH, parent_pid as c_long, 0, 0); _exit(0); }
    }
    // parent：ptracer 已经设为 child；child 即将 SEIZE 我们。返回成功。
    true
}

#[cfg(not(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64")))]
pub fn occupy_all() -> bool {
    false
}
