//! SIGTRAP handler 注册。BRK 跳板触发 SIGTRAP 后，handler 在这里把控制权转给 dispatch_vm。
//!
//! 平台支持：
//! - Linux / Android aarch64：完整实现（sigaction 注册 + ucontext 解析 + dispatch + PC 推进）
//! - 其它平台：stub（install 调用 noop）
//!
//! 实现思路（aarch64 Linux）：
//! 1. handler 被调用时，`info->si_addr` 指向触发 BRK 的 PC（即跳板的 brk 那条）。
//! 2. 跳板格式（vmp_rewriter::patcher::build_brk_trampoline 输出）：
//!    ```
//!    pc-4:  mov  x16, #region_id
//!    pc:    brk  #0x5156|low8(region_id)
//!    pc+4:  nop
//!    pc+8:  b    .
//!    ```
//!    region_id 既在 `mov x16` 的 imm16，也在 BRK 的 imm16 低 8 位（QV magic + low8）。
//! 3. handler 从 ucontext 取 X0..X7（GPR 参数）/ D0..D7（FP 参数），调 dispatch_vm。
//! 4. 把返回值写回 X0；并把 PC 推进到跳板末尾的 `b .` 之后 —— 即直接跳出本函数
//!    （等价 `ret`），因为原函数入口 4 字节已经被 rewriter 替换为 `b <trampoline>`。

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn install_sigtrap_handler() {
    use core::mem::MaybeUninit;
    use core::ptr;

    #[repr(C)]
    struct SigAction {
        sa_flags: i32,
        sa_handler: usize,
        sa_mask: [u64; 1],
        sa_restorer: usize,
    }
    const SA_SIGINFO: i32 = 0x0000_0004;
    const SIGTRAP: i32 = 5;

    extern "C" {
        fn sigaction(signum: i32, act: *const SigAction, oldact: *mut SigAction) -> i32;
    }

    let mut act: SigAction = unsafe { MaybeUninit::zeroed().assume_init() };
    act.sa_flags = SA_SIGINFO;
    act.sa_handler = sigtrap_handler as *const () as usize;
    unsafe {
        sigaction(SIGTRAP, &act, ptr::null_mut());
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn install_sigtrap_handler() {
    // Windows / macOS / 其它：暂未实现
}

// ============================================================================
// SIGTRAP handler — Linux/Android aarch64
// ============================================================================
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
extern "C" fn sigtrap_handler(
    _sig: i32,
    info: *mut SiginfoT,
    ctx: *mut core::ffi::c_void,
) {
    use crate::resolver::dispatch_region_with_fp;

    unsafe {
        if info.is_null() || ctx.is_null() {
            return;
        }
        let pc = (*info).si_addr as u64;

        // 跳板格式：pc-4 = mov x16,#region_id；从该指令 imm16 字段恢复
        let mov_inst = core::ptr::read_unaligned((pc - 4) as *const u32);
        let region_id = ((mov_inst >> 5) & 0xFFFF) as u64;

        // ucontext_t @ ctx 的 mcontext.regs[0..30] 为 X0..X29，pc=mcontext.pc
        // Bionic / glibc 都用相同布局：
        //   ucontext_t {
        //     uc_flags: u64,
        //     uc_link: *mut ucontext_t,
        //     uc_stack: stack_t (24B),
        //     uc_sigmask: u64 (Bionic 16B / glibc 128B —— 此处用 Linux uapi 8B)
        //     pad ...
        //     mcontext (sigcontext)
        //   }
        // 不直接依赖 libc 类型；用偏移量手动找 mcontext —— 在 Linux aarch64 上
        // mcontext 位于 ucontext_t 偏移 176 字节处（16 + 16 + 24 + 128 = 184 glibc）。
        //
        // 为了避免在不同 libc 下偏移漂移，我们采用 **稳健做法**：直接在 ctx 起点
        // 之后的 1024 字节中搜 fault_addr == pc 的 8 字节（mcontext.pc）。
        let region_id_u32 = region_id as u32;
        let scan = core::slice::from_raw_parts(ctx as *const u8, 1024);
        let mut mc_pc_off: Option<usize> = None;
        for i in (0..scan.len().saturating_sub(8)).step_by(8) {
            let v = core::ptr::read_unaligned(scan.as_ptr().add(i) as *const u64);
            if v == pc {
                mc_pc_off = Some(i);
                break;
            }
        }
        let mc_pc_off = match mc_pc_off {
            Some(o) => o,
            None => return,
        };
        // mcontext 中 fault_addr 紧邻 regs/pc/sp 的实际布局如下（sigcontext aarch64）：
        //   u64 fault_address;   // [+0]
        //   u64 regs[31];        // [+8 .. +256)
        //   u64 sp;              // [+256]
        //   u64 pc;              // [+264]    ← 我们扫到这里
        //   u64 pstate;          // [+272]
        // 因此：sigcontext_base = mc_pc_off - 264
        if mc_pc_off < 264 {
            return;
        }
        let sc_off = mc_pc_off - 264;
        let regs_ptr = (ctx as *mut u8).add(sc_off + 8) as *mut u64;
        let pc_ptr = (ctx as *mut u8).add(sc_off + 264) as *mut u64;

        // 收集 X0..X7 GPR 参数；FP 参数（D0..D7）暂忽略 — 留给 Phase 5 完整化。
        let mut gpr: [u64; 8] = [0; 8];
        for i in 0..8 {
            gpr[i] = *regs_ptr.add(i);
        }
        let _ = region_id_u32;

        let ret = dispatch_region_with_fp(region_id as usize, &gpr).unwrap_or(0);

        // 写回 X0
        *regs_ptr = ret;
        // 把 PC 推进到 trampoline 末尾后的下一条 —— 实际上原函数入口的字节已被
        // rewriter 替换为 `b <trampoline>`，所以从 trampoline 内 ret 等价于跳过
        // trampoline + 让原函数结束。最稳的做法：把 PC 设到 caller 的 LR（X30）。
        let lr = *regs_ptr.add(30);
        *pc_ptr = lr;
    }
}

#[cfg(not(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64")))]
extern "C" fn sigtrap_handler(
    _sig: i32,
    _info: *mut SiginfoT,
    _ctx: *mut core::ffi::c_void,
) {
    // 非 aarch64-linux：handler 占位，永不实际运行（install_sigtrap_handler 不注册）
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct SiginfoT {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    _pad0: i32,
    /// SIGTRAP/BRK：si_addr 指向触发 BRK 的指令地址
    pub si_addr: *mut core::ffi::c_void,
    _pad1: [u64; 14],
}
