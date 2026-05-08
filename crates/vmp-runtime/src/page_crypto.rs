//! 按页动态加解密（page-on-demand crypto）。
//!
//! 思想：
//! - rewriter 在打包阶段把目标代码段（每 4KB 一页）单独 XOR 加密 + 在 ELF 元数据
//!   里写一段「页表」（vaddr 起点 / 页数 / 每页 key）
//! - runtime 启动时（JNI_OnLoad）把所有这些页 mprotect 成 PROT_NONE，并安装
//!   `SIGSEGV` handler
//! - 第一次访问触发 SIGSEGV → handler 查页表找对应 key → 解密 → mprotect R+X →
//!   返回，CPU 重跑指令成功执行
//! - 一段时间后（或基于水位）通过 timer 把热度低的页重新加密 + mprotect PROT_NONE
//!
//! 这样静态 dump 拿到的永远是加密形态；只有命中过该页的代码才解密。
//!
//! **当前实现是模块骨架**：定义页表数据结构 + SIGSEGV handler + 解密路径，但**不
//! 默认启用**（启用需要 rewriter 端配套写页表 + 加密页字节，是 Phase 6 工作）。
//! 调用方通过 `enable_page_crypto(table)` 显式开启。

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy)]
pub struct PageEntry {
    /// 页起始虚拟地址（4KB 对齐）
    pub vaddr: u64,
    /// 该页的 8 字节 XOR key（重复使用 keystream）
    pub key: u64,
    /// 是否当前已解密。SIGSEGV handler 维护。
    pub decrypted: bool,
}

#[derive(Debug)]
pub struct PageTable {
    pub entries: Vec<PageEntry>,
}

static TABLE: OnceLock<std::sync::Mutex<PageTable>> = OnceLock::new();

/// 启用按页加解密。call once after `scan::scan_loaded_modules`。
pub fn enable_page_crypto(table: PageTable) -> bool {
    if TABLE.set(std::sync::Mutex::new(table)).is_err() {
        return false;
    }
    install_sigsegv_handler();
    mprotect_all_to_none();
    true
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn install_sigsegv_handler() {
    use core::mem::MaybeUninit;
    #[repr(C)]
    struct SigAction {
        sa_flags: i32,
        sa_handler: usize,
        sa_mask: [u64; 1],
        sa_restorer: usize,
    }
    // SA_SIGINFO + SA_NODEFER：handler 内部如果再触发 SIGSEGV，OS 不会自动屏蔽
    // → 由 thread-local IN_HANDLER 自己识别递归；NODEFER 比较稳健，避免 dead-lock。
    const SA_SIGINFO: i32 = 0x0000_0004;
    const SA_NODEFER: i32 = 0x4000_0000;
    const SIGSEGV: i32 = 11;
    extern "C" {
        fn sigaction(signum: i32, act: *const SigAction, oldact: *mut SigAction) -> i32;
    }
    let mut act: SigAction = unsafe { MaybeUninit::zeroed().assume_init() };
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    act.sa_handler = sigsegv_handler as *const () as usize;
    unsafe {
        sigaction(SIGSEGV, &act, core::ptr::null_mut());
    }
}

// 线程本地"我已经在 handler 里"计数器。recursion ≥ 2 即放弃处理（恢复 SIG_DFL）。
#[cfg(any(target_os = "linux", target_os = "android"))]
thread_local! {
    static IN_HANDLER: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn install_sigsegv_handler() {}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn mprotect_all_to_none() {
    use core::ffi::c_int;
    extern "C" {
        fn mprotect(addr: *mut core::ffi::c_void, len: usize, prot: c_int) -> c_int;
    }
    const PROT_NONE: c_int = 0;
    if let Some(t) = TABLE.get() {
        if let Ok(t) = t.lock() {
            for e in &t.entries {
                unsafe {
                    mprotect(e.vaddr as *mut _, 4096, PROT_NONE);
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn mprotect_all_to_none() {}

/// SIGSEGV handler：查页表，命中则解密 → mprotect R+X → 让 CPU 重跑触发指令。
/// 未命中（真实 segfault）/ 递归 fault → 恢复 SIG_DFL 让进程正常 crash。
#[cfg(any(target_os = "linux", target_os = "android"))]
extern "C" fn sigsegv_handler(
    sig: i32,
    info: *mut crate::sig::SiginfoT,
    _ctx: *mut core::ffi::c_void,
) {
    use core::ffi::c_int;
    extern "C" {
        fn mprotect(addr: *mut core::ffi::c_void, len: usize, prot: c_int) -> c_int;
        fn signal(signum: c_int, handler: usize) -> usize;
    }
    const PROT_R: c_int = 1;
    const PROT_X: c_int = 4;
    const SIGSEGV: c_int = 11;
    const SIG_DFL: usize = 0;

    // 递归保护：handler 内部如果再触发 SIGSEGV（页表 mutex 解锁失败 / mprotect 失败 /
    // 解密目标地址越界），不能再进 handler；恢复 SIG_DFL 让进程崩溃。
    let recursion_safe = IN_HANDLER.with(|c| {
        let v = c.get();
        c.set(v.saturating_add(1));
        v == 0
    });
    if !recursion_safe {
        unsafe {
            signal(SIGSEGV, SIG_DFL);
        }
        IN_HANDLER.with(|c| c.set(c.get().saturating_sub(1)));
        return;
    }

    unsafe {
        if info.is_null() {
            IN_HANDLER.with(|c| c.set(c.get().saturating_sub(1)));
            return;
        }
        let fault = (*info).si_addr as u64;
        let page = fault & !0xFFFu64;
        let mut handled = false;
        if let Some(t) = TABLE.get() {
            if let Ok(mut tbl) = t.lock() {
                for e in tbl.entries.iter_mut() {
                    if e.vaddr == page && !e.decrypted {
                        // 先临时设 R+W 解密，然后改 R+X
                        if mprotect(page as *mut _, 4096, PROT_R | 2) == 0 {
                            xor_page(page, e.key);
                            mprotect(page as *mut _, 4096, PROT_R | PROT_X);
                            e.decrypted = true;
                            handled = true;
                        }
                        break;
                    }
                }
            }
        }
        if !handled {
            // 未命中：恢复默认 handler，进程接受真实 SIGSEGV
            signal(SIGSEGV, SIG_DFL);
            let _ = sig;
        }
    }
    IN_HANDLER.with(|c| c.set(c.get().saturating_sub(1)));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn xor_page(page: u64, key: u64) {
    let buf = core::slice::from_raw_parts_mut(page as *mut u8, 4096);
    let key_bytes = key.to_le_bytes();
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= key_bytes[i & 7];
    }
}
