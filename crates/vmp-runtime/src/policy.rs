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
    // 通过修改 dispatcher 全局状态，让后续 dispatch_vm 落到错误 region。
    // 当前阶段：仅 log，留给后续的 dispatch 路径检查 `THREAT_DETECTED` flag。
    crate::resolver::set_threat_flag();
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
