//! 运行时符号解析与 dispatch_vm 桥接。
//!
//! 两条职能：
//! 1. **import 解析**：scan 阶段如果识别到本进程 ELF 的 `.qimp` (imports.tbl) blob，
//!    就为每条 hash 项调 `dlsym` 找真实地址，缓存到 `HashMap<u64, u64>`（hash → addr）。
//!    VMP 字节码里的 `NativeCall` 不再用绝对地址，而是用 hash → 运行时查表 → 真实函数。
//! 2. **dispatch_region**：把 BRK 触发的 region_id 路由到对应模块的 StubBlob，调用
//!    `vmp_stub::dispatch_vm`。LinuxHost 复用 vmp-stub 提供的实现。

use crate::scan::discovered;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use vmp_core::Result;

static IMPORT_TABLE: OnceLock<HashMap<u64, u64>> = OnceLock::new();
static THREAT_DETECTED: AtomicBool = AtomicBool::new(false);

/// 多线程互斥：一次只允许一个线程进 dispatch_vm。
///
/// 原因：vmp-stub 的 `dispatch_vm` 创建本地 VmState（栈、寄存器）并把指针交给宿主
/// host bridge；如果两个线程同时调用，host_load/host_store 路径竞态；NestedDispatchHost
/// 内部也假设单线程。
///
/// 性能影响：单线程 VM 已经比 native 慢 ~50x，再加锁不影响绝对值（用户感知"VMP
/// 慢"已在预期内）。多线程并发性能差是 VMP 设计本身的代价。
///
/// 后续优化：把 VmState 池化，每线程拿一个；锁只保护池借出 / 归还。
static DISPATCH_LOCK: Mutex<()> = Mutex::new(());

/// 由 `policy::on_threat` 调用。设置后所有 `dispatch_region` 路径返回 corrupt 值。
pub fn set_threat_flag() {
    THREAT_DETECTED.store(true, Ordering::SeqCst);
}

pub fn threat_detected() -> bool {
    THREAT_DETECTED.load(Ordering::Relaxed)
}

/// scan 完成后调用：对每个发现模块的 imports 表（如有）做 dlsym 解析。
pub fn resolve_imports_for_all() {
    let _ = IMPORT_TABLE.set(resolve_impl());
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn resolve_impl() -> HashMap<u64, u64> {
    use byteorder::{ByteOrder, LittleEndian};
    use core::ffi::c_void;
    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const u8) -> *mut c_void;
    }
    const RTLD_DEFAULT: *mut c_void = core::ptr::null_mut();

    let mut out = HashMap::new();
    for d in discovered() {
        // 在模块所在内存里搜 QIMP magic。
        // discovered 不直接保存 imports.tbl 偏移；我们重新在该模块内存范围里扫描。
        let module_base = d.module_base as *const u8;
        // 启发式：模块内存窗口 cap 16 MB —— 商用 .so 极少超出该值；超出部分多半
        // 不是当前模块属地，避免 SIGSEGV / 巨慢扫描。
        const SCAN_LEN: usize = 16 * 1024 * 1024;
        let scan = unsafe { core::slice::from_raw_parts(module_base, SCAN_LEN) };
        for i in (0..scan.len().saturating_sub(10)).step_by(4) {
            if &scan[i..i + 4] == b"QIMP" {
                let count = LittleEndian::read_u32(&scan[i + 6..i + 10]) as usize;
                let mut p = i + 10;
                for _ in 0..count {
                    if p + 10 > scan.len() {
                        break;
                    }
                    let h = LittleEndian::read_u64(&scan[p..p + 8]);
                    p += 8;
                    let nlen = LittleEndian::read_u16(&scan[p..p + 2]) as usize;
                    p += 2;
                    if p + nlen > scan.len() {
                        break;
                    }
                    // 用 dlsym(RTLD_DEFAULT) 找原名
                    let mut name_buf: Vec<u8> = scan[p..p + nlen].to_vec();
                    name_buf.push(0);
                    let addr = unsafe { dlsym(RTLD_DEFAULT, name_buf.as_ptr()) };
                    if !addr.is_null() {
                        out.insert(h, addr as u64);
                    }
                    p += nlen;
                }
                break; // 一个模块只处理一个 QIMP
            }
        }
    }
    out
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn resolve_impl() -> HashMap<u64, u64> {
    HashMap::new()
}

/// hash → 真实 native 函数地址。VOp::NativeCall 路径调用：先用 hash 查表，
/// 找不到回退原 imm（兼容未启用 hash_imports 的 blob）。
pub fn lookup_import(hash: u64) -> Option<u64> {
    IMPORT_TABLE.get()?.get(&hash).copied()
}

/// 找 region_id 对应的 (StubBlob, region_index)。第一个发现的 blob 默认 region 0..N。
#[allow(dead_code)]
fn locate_region(region_id: usize) -> Option<(&'static vmp_stub::StubBlob, usize)> {
    for d in discovered() {
        if region_id < d.blob.regions.len() {
            return Some((&d.blob, region_id));
        }
    }
    None
}

/// 顶层 dispatch：BRK trap → 找 blob → vmp_stub::dispatch_vm。仅 Linux 上有 LinuxHost。
///
/// 多线程 caller 通过 `DISPATCH_LOCK` 串行化。Android JNI 在不同 java 线程调用同一
/// native 函数会触发并发，必须串行才能保证 VmState 不被踩。
///
/// **PIE 地址处理**：lifter 把"原 ELF vaddr"baked 进 blob（ADRP / LDR-literal /
/// 全局变量访问）。在 cdylib 模式下，本进程已经把 .so 映射到 dlpi_addr 起的位置，
/// 这些地址需要加 dlpi_addr 偏移才能命中真实数据。
///
/// 当前实现：用 `RebasedLinuxHost` 包一层 LinuxHost，把 `load`/`store`/`native_call`
/// 收到的"看起来是模块内"的地址加上发现的 dlpi_addr。判定标准：若地址 < 0x1_0000_0000
/// （4GB），认为是 .so 内 vaddr（PIE 相对低 32 位），需要加 base；否则视作绝对堆/栈
/// 地址（已经被 syscall / 调用方传入），不加 base。这是启发式，无法 100% 区分；对
/// 商用 SDK 的"读 .rodata 字符串"路径基本足够。完整方案需 lifter PIE-aware 标注。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn dispatch_region(region_id: usize, args: &[u64]) -> Result<u64> {
    if threat_detected() {
        // policy::corrupt：返回毒化值；攻击者拿到错的运行结果
        // 注：CodeGen 已经把字节码加密 → dump 出来也是密文；运行时再返回 corrupt
        // 数值让攻击者**进一步分不清是检测触发还是普通逻辑**。
        return Ok(0xDEAD_C0DE_DEAD_C0DEu64);
    }
    let _guard = DISPATCH_LOCK.lock().map_err(|_| vmp_core::Error::vm("E:lock"))?;
    let (blob, idx, module_base) = locate_region_with_base(region_id)
        .ok_or_else(|| vmp_core::Error::vm("E:no-region"))?;
    let inner = vmp_stub::linux::LinuxHost::new();
    let mut host = RebasedLinuxHost { base: module_base, inner };
    let v = vmp_stub::dispatch_vm(blob, idx, args, &mut host)
        .map_err(|_| vmp_core::Error::vm("E:vm"))?;
    Ok(v)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn locate_region_with_base(region_id: usize) -> Option<(&'static vmp_stub::StubBlob, usize, u64)> {
    for d in discovered() {
        if region_id < d.blob.regions.len() {
            return Some((&d.blob, region_id, d.module_base));
        }
    }
    None
}

/// PIE-aware HostBridge wrapper：把模块内相对地址（< 4GB 启发式）加上 `dlpi_addr`。
#[cfg(any(target_os = "linux", target_os = "android"))]
struct RebasedLinuxHost {
    base: u64,
    inner: vmp_stub::linux::LinuxHost,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl vmp_interpreter::HostBridge for RebasedLinuxHost {
    fn load(&mut self, addr: u64, w: vmp_isa::Width) -> vmp_core::Result<u64> {
        self.inner.load(rebase_if_relative(addr, self.base), w)
    }
    fn store(&mut self, addr: u64, value: u64, w: vmp_isa::Width) -> vmp_core::Result<()> {
        self.inner.store(rebase_if_relative(addr, self.base), value, w)
    }
    fn native_call(&mut self, target: u64, args: &[u64]) -> vmp_core::Result<u64> {
        self.inner.native_call(rebase_if_relative(target, self.base), args)
    }
    fn syscall(&mut self, no: u64, args: &[u64]) -> vmp_core::Result<u64> {
        self.inner.syscall(no, args)
    }
    fn map_data(&mut self, vaddr: u64, bytes: &[u8], prot: u8) -> vmp_core::Result<()> {
        // 在 cdylib 模式下，原 .so 数据段已被 dl_open 映射到 base+vaddr，无需再 mmap。
        // 走 inner.map_data 反而会失败（地址被占）。直接 noop。
        let _ = (vaddr, bytes, prot);
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
fn rebase_if_relative(addr: u64, base: u64) -> u64 {
    // 地址 < 4GB 视作模块内 PIE 相对（lifter 写出来的 ADRP 结果）；否则视作绝对值。
    // 对极少见的"模块加载到低 32 位空间"情况会误判，但商用 64-bit Linux ASLR 保证
    // 模块基址 ≥ 0x55_5555_5555 起，与"原 ELF vaddr ≤ ~10MB"区分清楚。
    if addr < 0x1_0000_0000u64 {
        base.wrapping_add(addr)
    } else {
        addr
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn dispatch_region(_region_id: usize, _args: &[u64]) -> Result<u64> {
    Err(vmp_core::Error::vm("E:platform"))
}

/// 给 SIGTRAP handler 用的便利包装：传 8 个 GPR 参数；返回 X0。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn dispatch_region_with_fp(region_id: usize, gpr: &[u64; 8]) -> Result<u64> {
    dispatch_region(region_id, gpr)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn dispatch_region_with_fp(_region_id: usize, _gpr: &[u64; 8]) -> Result<u64> {
    Err(vmp_core::Error::vm("E:platform"))
}
