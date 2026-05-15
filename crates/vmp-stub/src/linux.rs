//! Linux 主机桥接：通过 `svc #0` 真实下发系统调用 + 直接读写宿主进程地址空间。
//!
//! 仅在 `target_os = "linux"` 上启用。aarch64 / x86_64 / arm 共用同一接口，但 `raw_syscall`
//! 由架构特化（这里仅实现 aarch64；新增其它架构按 ARM ABI 模式照葫芦画瓢即可）。

use vmp_core::{Error, Result};
use vmp_interpreter::HostBridge;
use vmp_isa::Width;

pub struct LinuxHost {
    pub allow_raw_memory: bool,
}

impl Default for LinuxHost {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxHost {
    /// signal-safe 构造: no syscall/no TLS access. 不能在 new() 里调
    /// `Instant::now()` —— bionic clock_gettime 走 vDSO 可能 touch TLS,
    /// 在 SIGTRAP handler 路径上 reentrant 风险.
    pub fn new() -> Self {
        Self {
            allow_raw_memory: true,
        }
    }
}

impl HostBridge for LinuxHost {
    fn load(&mut self, addr: u64, w: Width) -> Result<u64> {
        if !self.allow_raw_memory {
            return Err(Error::vm("LinuxHost: 已禁用裸地址加载"));
        }
        unsafe {
            let v = match w {
                Width::W8 => *(addr as *const u8) as u64,
                Width::W16 => *(addr as *const u16) as u64,
                Width::W32 => *(addr as *const u32) as u64,
                Width::W64 => *(addr as *const u64),
            };
            Ok(v)
        }
    }

    fn store(&mut self, addr: u64, value: u64, w: Width) -> Result<()> {
        if !self.allow_raw_memory {
            return Err(Error::vm("LinuxHost: 已禁用裸地址写入"));
        }
        unsafe {
            match w {
                Width::W8 => *(addr as *mut u8) = value as u8,
                Width::W16 => *(addr as *mut u16) = value as u16,
                Width::W32 => *(addr as *mut u32) = value as u32,
                Width::W64 => *(addr as *mut u64) = value,
            }
        }
        Ok(())
    }

    fn native_call(&mut self, target: u64, args: &[u64]) -> Result<u64> {
        // 兼容入口: GPR-only. FP 路径见 `native_call_fp`.
        if target == 0 || target & 3 != 0 || target < 0x1000 {
            return Err(Error::vm("native_call: target 不合法"));
        }
        let mut g = [0u64; 8];
        for (i, v) in args.iter().take(8).enumerate() {
            g[i] = *v;
        }
        let f = [0u64; 8];
        let (r, _) = unsafe { call_with_fp(target, &g, &f) };
        Ok(r)
    }

    fn native_call_fp(
        &mut self,
        target: u64,
        gpr_args: &[u64; 8],
        fpr_args: &[u64; 8],
    ) -> Result<(u64, u64)> {
        if target == 0 || target & 3 != 0 || target < 0x1000 {
            return Err(Error::vm("native_call_fp: target 不合法"));
        }
        let r = unsafe { call_with_fp(target, gpr_args, fpr_args) };
        Ok(r)
    }

    fn syscall(&mut self, no: u64, args: &[u64]) -> Result<u64> {
        // eprintln 路径删除 — signal handler 中不能走 stdio.
        let mut a = [0u64; 6];
        for (i, v) in args.iter().take(6).enumerate() {
            a[i] = *v;
        }
        Ok(unsafe { raw_syscall(no, a[0], a[1], a[2], a[3], a[4], a[5]) })
    }

    fn map_data(&mut self, vaddr: u64, bytes: &[u8], prot: u8) -> Result<()> {
        let page = 0x1000u64;
        let aligned_addr = vaddr & !(page - 1);
        let off_in_page = (vaddr - aligned_addr) as usize;
        let total = (off_in_page + bytes.len() + page as usize - 1) & !(page as usize - 1);
        let prot_rw = 0x1u64 | 0x2u64;
        let flags = 0x10u64 | 0x20u64 | 0x02u64;
        let mmap_no: u64 = 222;
        let r = unsafe {
            raw_syscall(mmap_no, aligned_addr, total as u64, prot_rw, flags, u64::MAX, 0)
        };
        log::debug!(
            "[map_data] mmap_fixed vaddr={:#x} aligned={:#x} total={:#x} → {:#x} (errno={})",
            vaddr, aligned_addr, total, r, (r as i64).wrapping_neg()
        );
        if (r as i64) < 0 && (r as i64) > -4096 {
            return Err(vmp_core::Error::vm("E:mmap"));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), vaddr as *mut u8, bytes.len());
        }
        let want_prot = (prot as u64) & 0x7;
        if want_prot != prot_rw && want_prot != 0 {
            let mprotect_no: u64 = 226;
            let _ = unsafe { raw_syscall(mprotect_no, aligned_addr, total as u64, want_prot, 0, 0, 0) };
        }
        log::debug!("[map_data] copied {} bytes to {:#x}; first 8 bytes = {:?}", bytes.len(), vaddr,
            unsafe { std::slice::from_raw_parts(vaddr as *const u8, 8.min(bytes.len())) });
        Ok(())
    }
}

/// AAPCS64 函数调用蹦床: 装载 GPR x0..x7 + FP/SIMD v0..v7 (低 64 位) → blr target
/// → 读回 (x0, d0 低 64 位). 这是替代 `transmute::<_, F8>(p)` 的核心: Rust
/// 的 `extern "C"` 调用约定只搬 GPR, FP/SIMD 寄存器从来不被显式加载.
///
/// 用 naked extern "C" 函数包: target 在 x0, gpr_ptr 在 x1, fpr_ptr 在 x2 (AAPCS).
/// 我们先用 x16/x17 暂存指针 (x16/x17 是平台 scratch, 调用约定允许任意覆盖),
/// 再 ldp 从 gpr_ptr 把 x0..x7 装好, ldp d0..d7 从 fpr_ptr 装 FP. blr x16 调
/// 用. 返回 fpr 在 x1 (AAPCS 16-byte struct return → x0,x1).
///
/// 用 `global_asm!` 而非 `asm!` 避免 Rust 寄存器分配器的复杂性: 这里我们对
/// 整个调用规约负责, 不让编译器插手.
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
core::arch::global_asm!(
    ".globl qvmp_call_with_fp",
    ".type  qvmp_call_with_fp, %function",
    "qvmp_call_with_fp:",
    // x0 = target, x1 = gpr_ptr (&[u64;8]), x2 = fpr_ptr (&[u64;8])
    "stp x29, x30, [sp, #-16]!",
    "mov x29, sp",
    "mov x16, x0",                 // x16 = target (preserved across the ldp's)
    "mov x17, x2",                 // x17 = fpr_ptr
    // 装载 GPR x0..x7 from gpr_ptr (was x1).
    "ldp x6, x7, [x1, #48]",       // load x6/x7 first since x1 is loaded last
    "ldp x4, x5, [x1, #32]",
    "ldp x2, x3, [x1, #16]",
    "ldp x0, x1, [x1]",            // overwrites x1 (no longer needed)
    // 装载 FP v0..v7 from fpr_ptr (saved in x17).
    "ldp d0, d1, [x17]",
    "ldp d2, d3, [x17, #16]",
    "ldp d4, d5, [x17, #32]",
    "ldp d6, d7, [x17, #48]",
    "blr x16",
    // x0 = gpr return; put fpr return in x1 (AAPCS 16-byte struct return slot).
    "fmov x1, d0",
    "ldp x29, x30, [sp], #16",
    "ret",
    ".size qvmp_call_with_fp, . - qvmp_call_with_fp",
);

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
extern "C" {
    fn qvmp_call_with_fp(target: u64, gpr: *const u64, fpr: *const u64) -> CallRet;
}

#[repr(C)]
struct CallRet {
    gpr: u64,
    fpr: u64,
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
unsafe fn call_with_fp(target: u64, gpr: &[u64; 8], fpr: &[u64; 8]) -> (u64, u64) {
    let r = unsafe { qvmp_call_with_fp(target, gpr.as_ptr(), fpr.as_ptr()) };
    (r.gpr, r.fpr)
}

#[cfg(not(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64")))]
unsafe fn call_with_fp(target: u64, gpr: &[u64; 8], _fpr: &[u64; 8]) -> (u64, u64) {
    // 非 aarch64 build (host CLI 测试): 退化为 GPR-only transmute.
    type F8 = extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64;
    let p = target as *const ();
    let r = unsafe {
        (core::mem::transmute::<_, F8>(p))(
            gpr[0], gpr[1], gpr[2], gpr[3], gpr[4], gpr[5], gpr[6], gpr[7],
        )
    };
    (r, 0)
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
unsafe fn raw_syscall(no: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    // Linux/Android aarch64 syscall ABI：
    //   - syscall 号在 X8；参数 X0..X5；返回值 X0
    //   - 内核保留 X19..X29 / SP；可能改写 X1..X18 与 NZCV
    // 用 inlateout/lateout 显式告知编译器这些寄存器在 svc 后值不可靠，
    // 否则编译器可能误以为参数寄存器 / flag 仍保留旧值并做错误的后续访问 → SIGSEGV。
    core::arch::asm!(
        "svc #0",
        in("x8") no,
        inlateout("x0") a0 => ret,
        inlateout("x1") a1 => _,
        inlateout("x2") a2 => _,
        inlateout("x3") a3 => _,
        inlateout("x4") a4 => _,
        inlateout("x5") a5 => _,
        lateout("x6") _,
        lateout("x7") _,
        lateout("x8") _,
        lateout("x9") _,
        lateout("x10") _,
        lateout("x11") _,
        lateout("x12") _,
        lateout("x13") _,
        lateout("x14") _,
        lateout("x15") _,
        lateout("x16") _,
        lateout("x17") _,
        options(nostack),
    );
    ret
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64"))]
unsafe fn raw_syscall(no: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    // Linux x86_64 syscall ABI：rax=系统调用号，rdi/rsi/rdx/r10/r8/r9=参数，
    // 返回值在 rax。`syscall` 指令使用 rcx 保存返回 RIP、r11 保存 RFLAGS，
    // 同时内核可能改写 EFLAGS 标志位 → 不能 preserves_flags。
    core::arch::asm!(
        "syscall",
        inlateout("rax") no => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r10") a3 => _,
        inlateout("r8") a4 => _,
        inlateout("r9") a5 => _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    ret
}

#[cfg(not(any(
    all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"),
    all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64"),
)))]
unsafe fn raw_syscall(_no: u64, _a0: u64, _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> u64 {
    // 非 Linux / 非 aarch64-x86_64：在加壳器进程内当作 noop（避免破坏 cargo test）。
    0
}
