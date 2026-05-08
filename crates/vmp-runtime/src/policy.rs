//! 威胁响应策略 —— vmp-protect 检测到威胁后由本模块决定怎么做。
//!
//! 4 种响应模式（通过 `QVMP_RESPONSE` env var 选择）：
//! - `silent`：仅 `log::warn!` 不影响执行（开发 / debug 推荐）
//! - `corrupt`：把 VM 状态毒化（写无意义 region_id），让攻击者 dump 也拿不到正确字节码（默认）
//! - `abort`：直接 `abort()`，进程立即退出
//! - `crash_random`：写入随机内存触发 SIGSEGV，进程像普通崩溃一样死掉，不留 abort 痕迹
//!
//! 多数加固框架使用 `crash_random` —— 攻击者从 crash dump 看不出是检测触发还是
//! 普通 bug。但对生产部署可能误伤，需要谨慎。

use vmp_protect::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    Silent,
    Corrupt,
    Abort,
    CrashRandom,
}

impl Response {
    pub fn from_env() -> Self {
        match std::env::var("QVMP_RESPONSE").ok().as_deref() {
            Some("silent") => Response::Silent,
            Some("abort") => Response::Abort,
            Some("crash") | Some("crash_random") => Response::CrashRandom,
            // 默认 corrupt
            _ => Response::Corrupt,
        }
    }
}

pub fn on_threat(verdict: &Verdict) {
    let r = Response::from_env();
    log::warn!(
        "vmp-protect threat: dbg={} dump={} hook={} ida={} vm={} inj={} hwbp={} integ={} → {:?}",
        verdict.debugger_attached,
        verdict.dump_in_progress,
        verdict.hooks_present,
        verdict.ida_attached,
        verdict.vm_or_emulator,
        verdict.injection_present,
        verdict.hwbp_count,
        verdict.integrity_failed,
        r,
    );
    match r {
        Response::Silent => {}
        Response::Corrupt => corrupt_vm_state(),
        Response::Abort => abort_process(),
        Response::CrashRandom => crash_random(),
    }
}

fn corrupt_vm_state() {
    // 多层毒化：
    // 1) 设置 THREAT_DETECTED → dispatch_region 直接返回 0xDEAD_C0DE 不进 VM
    // 2) 把全局 corrupt 模式打开 → 即使 caller 不通过 dispatch_region 而是直接调
    //    qvmp_dispatch（C ABI），也会被拦截
    // 3) 写一段 syscall noise（mmap/munmap 几个无害区域）—— 让攻击者的 syscall
    //    trace 多出几条假阳性，干扰静态分析路径标注
    crate::resolver::set_threat_flag();
    syscall_noise();
}

/// 通过几次 mmap/munmap 制造无害的 syscall 噪声。
/// Frida 的 syscall trace / strace 会看到额外几条 `mmap()` `munmap()` `getpid()`，
/// 干扰攻击者的"该函数有什么副作用"判断。
fn syscall_noise() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        extern "C" {
            fn mmap(
                addr: *mut core::ffi::c_void, len: usize, prot: i32, flags: i32,
                fd: i32, offset: i64,
            ) -> *mut core::ffi::c_void;
            fn munmap(addr: *mut core::ffi::c_void, len: usize) -> i32;
            fn getpid() -> i32;
        }
        const PROT_NONE: i32 = 0;
        const MAP_PRIVATE: i32 = 0x02;
        const MAP_ANONYMOUS: i32 = 0x20;
        for _ in 0..3 {
            let p = mmap(core::ptr::null_mut(), 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if !p.is_null() && p as i64 != -1 {
                let _ = munmap(p, 4096);
            }
        }
        let _ = getpid();
    }
}

fn abort_process() -> ! {
    // libc 的 abort()
    extern "C" {
        fn abort() -> !;
    }
    unsafe { abort() }
}

#[allow(clippy::diverging_sub_expression)]
fn crash_random() -> ! {
    // 写一个看起来像普通 bug 的 SIGSEGV：写入空指针偏移
    unsafe {
        let p = 0xDEAD_BEEFu64 as *mut u64;
        core::ptr::write_volatile(p, 0xCAFE_BABE);
    }
    // 不可达；防止编译器优化删掉 SIGSEGV 路径
    unreachable!()
}
