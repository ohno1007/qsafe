//! Stub 运行时入口（host-side 模拟）。
//!
//! 真实嵌入到目标二进制中时，跳板会用对应架构的汇编写一个 thunk：
//!  - 保存调用者寄存器
//!  - 调用 `dispatch_vm(region_id, args...)`
//!  - 把返回值放回调用约定要求的寄存器
//!
//! 当前实现是 **加壳器内的功能性测试** 路径，用于验证 lift→encode→interpret 闭环。

use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use thiserror::Error;
use vmp_core::Result as CoreResult;
use vmp_interpreter::{HostBridge, Interpreter, VmState};
use vmp_isa::Width;

// =============================================================================
// signal-handler-safe scratch pool
// =============================================================================
//
// `dispatch_vm_fp` 在 SIGTRAP handler 里被调用. POSIX 明确说 malloc/free 是
// async-signal-unsafe —— bionic malloc 内部有 mutex, 主线程 malloc 中途被
// SIGTRAP 打断后再 malloc 会重入同一 mutex, 死锁或堆损坏. 触发足够多次后
// 整个进程的堆状态都乱了. 这是 v37/v38/v40 三套不同 region 子集都在大致相同
// 位置挂的根因.
//
// 改成: qvmp_init 时 mmap 一块匿名内存 (1MB), 用 atomic bump-down allocator
// 给每次 dispatch 切出 64KB 的 VM stack + 16KB 的 bytecode scratch. 递归
// dispatch (vm_call_region_fp) 再切下一片, 退出时归还. 完全不走 malloc.
//
// ImGui/C++ 容器算法 (std::vector::resize, std::sort, 字符串拼接) 嵌套调用
// 轻松 20-30 层. 1MB 池 / 80KB 每 frame 只够 12 层 → "frame pool exhausted"
// 错误 (Eb3) 是 v37-v44 全量挂的真正 root cause. 升 16MB → ~200 层够用.
const POOL_SIZE: usize = 16 * 1024 * 1024;
const VM_STACK_BYTES: usize = 64 * 1024;
const BC_SCRATCH_BYTES: usize = 16 * 1024;
const FRAME_BYTES: usize = VM_STACK_BYTES + BC_SCRATCH_BYTES;

static POOL_BASE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static POOL_USED: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(target_os = "linux", target_os = "android"))]
fn ensure_pool() -> *mut u8 {
    let cur = POOL_BASE.load(Ordering::Acquire);
    if !cur.is_null() {
        return cur;
    }
    unsafe {
        let p = libc::mmap(
            core::ptr::null_mut(),
            POOL_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            return core::ptr::null_mut();
        }
        // CAS so concurrent initializers don't leak. If another thread won,
        // unmap ours.
        let p_u8 = p as *mut u8;
        match POOL_BASE.compare_exchange(
            core::ptr::null_mut(),
            p_u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => p_u8,
            Err(existing) => {
                libc::munmap(p as *mut _, POOL_SIZE);
                existing
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn ensure_pool() -> *mut u8 {
    // Off-target builds (host CLI): fall back to a leaked Box. CLI doesn't
    // run inside a signal handler so the malloc concern doesn't apply.
    let cur = POOL_BASE.load(Ordering::Acquire);
    if !cur.is_null() {
        return cur;
    }
    let buf = vec![0u8; POOL_SIZE].into_boxed_slice();
    let p = Box::leak(buf).as_mut_ptr();
    match POOL_BASE.compare_exchange(
        core::ptr::null_mut(),
        p,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => p,
        Err(existing) => existing,
    }
}

/// Reserve a (vm_stack, bc_scratch) frame from the pool. Returns (stack_slice,
/// scratch_slice, prev_used) where `prev_used` must be restored on the way out.
unsafe fn alloc_frame() -> Option<(*mut u8, *mut u8, usize)> {
    let base = ensure_pool();
    if base.is_null() {
        return None;
    }
    let prev = POOL_USED.fetch_add(FRAME_BYTES, Ordering::AcqRel);
    if prev + FRAME_BYTES > POOL_SIZE {
        // Out of pool — undo and bail.
        POOL_USED.fetch_sub(FRAME_BYTES, Ordering::AcqRel);
        return None;
    }
    let frame = base.add(prev);
    Some((frame, frame.add(VM_STACK_BYTES), prev))
}

unsafe fn free_frame(prev: usize) {
    let now = POOL_USED.load(Ordering::Acquire);
    debug_assert_eq!(now, prev + FRAME_BYTES, "VM frame stack imbalance");
    POOL_USED.store(prev, Ordering::Release);
}

#[derive(Debug, Error)]
pub enum StubError {
    #[error("Eb1:{0}")]
    NoRegion(usize),
    #[error("Eb2:{0}")]
    Vm(#[from] vmp_core::Error),
    #[error("Eb3:{0}")]
    Blob(String),
}

/// FP-aware 入口：同时传 GPR + FP 参数，返回 (GPR V0, FREG D0 低 64 位)。
/// Pre-load the blob's data segments BEFORE entering signal context. Caller
/// (cdylib qvmp_init) must invoke this once on the main thread, outside any
/// SIGTRAP handler. Previously the same loop ran inside dispatch_vm_fp behind
/// a `std::sync::Once`, but `Once` uses a futex internally — if the main
/// thread is mid-Once-init when SIGTRAP fires and our handler hits the same
/// Once, we'd block on the futex forever (deadlock).
pub fn preload_data_segments(blob: &super::StubBlob, host: &mut dyn HostBridge) {
    for ds in &blob.data_segments {
        if let Err(e) = host.map_data(ds.vaddr, &ds.bytes, ds.prot) {
            log::warn!("map_data {:#x} 失败: {}", ds.vaddr, e);
        }
    }
}

/// 单顶层调用（vmp-runtime main）从 `dispatch_vm` 进入；递归（CallRegion）走此路径。
pub fn dispatch_vm_fp(
    blob: &super::StubBlob,
    region_id: usize,
    gpr_args: &[u64; 8],
    fpr_args: &[u64; 8],
    host: &mut dyn HostBridge,
) -> Result<(u64, u64), StubError> {
    let r = blob.regions.get(region_id).ok_or(StubError::NoRegion(region_id))?;
    let bc = &blob.bytecode_pool[r.bc_offset as usize..(r.bc_offset + r.bc_len) as usize];

    if bc.len() > BC_SCRATCH_BYTES {
        return Err(StubError::Blob(format!(
            "region {} bytecode {} bytes exceeds BC_SCRATCH_BYTES {}",
            region_id,
            bc.len(),
            BC_SCRATCH_BYTES
        )));
    }
    let (stack_ptr, scratch_ptr, prev_used) = unsafe {
        alloc_frame().ok_or_else(|| {
            StubError::Blob("VM frame pool exhausted (recursion too deep?)".into())
        })?
    };

    let stack_base = stack_ptr as u64;
    let stack_top = stack_base + VM_STACK_BYTES as u64;
    let initial_sp = stack_top & !0xFu64;

    let scratch =
        unsafe { core::slice::from_raw_parts_mut(scratch_ptr, BC_SCRATCH_BYTES) };

    let result = (|| {
        let mut nested = NestedDispatchHost { blob, inner: host };
        let spec = blob.spec_for_region(region_id);
        let mut interp = Interpreter::new(spec, bc)
            .with_host(&mut nested)
            .with_iv_salt(region_id as u64);
        interp.state.regs[31] = initial_sp;
        interp.state.regs[63] = 0;
        for (i, v) in gpr_args.iter().enumerate() {
            interp.state.regs[i] = *v;
        }
        for (i, v) in fpr_args.iter().enumerate() {
            interp.state.fregs[i] = *v as u128;
        }
        interp.run_with_scratch(scratch)?;
        let gpr_ret = interp.state.regs[0];
        let fpr_ret = interp.state.fregs[0] as u64;
        Ok::<_, StubError>((gpr_ret, fpr_ret))
    })();

    unsafe { free_frame(prev_used) };
    result
}

pub fn dispatch_vm(
    blob: &super::StubBlob,
    region_id: usize,
    args: &[u64],
    host: &mut dyn HostBridge,
) -> Result<u64, StubError> {
    // map_data was previously gated by std::sync::Once here -- moved to
    // preload_data_segments() invoked from cdylib qvmp_init so the futex
    // inside Once never gets touched from a signal handler.

    let r = blob.regions.get(region_id).ok_or(StubError::NoRegion(region_id))?;
    let bc = &blob.bytecode_pool[r.bc_offset as usize..(r.bc_offset + r.bc_len) as usize];

    if bc.len() > BC_SCRATCH_BYTES {
        return Err(StubError::Blob(format!(
            "region {} bytecode {} bytes exceeds BC_SCRATCH_BYTES {}",
            region_id,
            bc.len(),
            BC_SCRATCH_BYTES
        )));
    }
    let (stack_ptr, scratch_ptr, prev_used) = unsafe {
        alloc_frame().ok_or_else(|| {
            StubError::Blob("VM frame pool exhausted (recursion too deep?)".into())
        })?
    };

    let stack_base = stack_ptr as u64;
    let stack_top = stack_base + VM_STACK_BYTES as u64;
    let initial_sp = stack_top & !0xFu64;

    let scratch =
        unsafe { core::slice::from_raw_parts_mut(scratch_ptr, BC_SCRATCH_BYTES) };

    let result = (|| {
        let mut nested = NestedDispatchHost { blob, inner: host };
        let spec = blob.spec_for_region(region_id);
        let mut interp = Interpreter::new(spec, bc)
            .with_host(&mut nested)
            .with_iv_salt(region_id as u64);
        interp.state.regs[31] = initial_sp;
        interp.state.regs[63] = 0;
        for (i, v) in args.iter().take(8).enumerate() {
            interp.state.regs[i] = *v;
        }
        interp.run_with_scratch(scratch).map_err(StubError::Vm)
    })();

    unsafe { free_frame(prev_used) };
    result
}

/// 让 `VOp::CallRegion` 落到 `dispatch_vm` 的递归调用上。
/// 其它 host 接口透传给 inner（真正的宿主桥接，比如 LinuxHost）。
struct NestedDispatchHost<'a> {
    blob: &'a super::StubBlob,
    inner: &'a mut dyn HostBridge,
}

impl<'a> HostBridge for NestedDispatchHost<'a> {
    fn load(&mut self, addr: u64, w: vmp_isa::Width) -> vmp_core::Result<u64> {
        self.inner.load(addr, w)
    }
    fn store(&mut self, addr: u64, v: u64, w: vmp_isa::Width) -> vmp_core::Result<()> {
        self.inner.store(addr, v, w)
    }
    fn native_call(&mut self, target: u64, args: &[u64]) -> vmp_core::Result<u64> {
        // GPR-only 兼容入口 — interpreter 现在走 native_call_fp 不再调这里,
        // 但保留 fallback 防意外回退.
        let mut gpr = [0u64; 8];
        for (i, v) in args.iter().take(8).enumerate() {
            gpr[i] = *v;
        }
        let fpr = [0u64; 8];
        self.native_call_fp(target, &gpr, &fpr).map(|(g, _)| g)
    }

    fn native_call_fp(
        &mut self,
        target: u64,
        gpr_args: &[u64; 8],
        fpr_args: &[u64; 8],
    ) -> vmp_core::Result<(u64, u64)> {
        // BLR Rn 时 target 可能直接是另一个被保护函数的 trampoline 入口,
        // 或是 `B <trampoline>` 之类的单指令蹦床. 直接调 native 会撞嵌套
        // SIGTRAP; 即便靠 SA_NODEFER 撑住, 多两次信号上下文不便宜.
        // 改成: 第一层匹配 patch_addr; 第二层尝试 decode target 处的 B 指令
        // 看它跳哪 (单条 b xxx 蹦床很常见).
        let load_bias = vmp_interpreter::MAIN_EXEC_LOAD_BIAS
            .load(core::sync::atomic::Ordering::Relaxed);
        if load_bias != 0 {
            if let Some(region_id) = resolve_to_region(self.blob, load_bias, target) {
                return self.vm_call_region_fp(region_id as u64, gpr_args, fpr_args);
            }
        }
        self.inner.native_call_fp(target, gpr_args, fpr_args)
    }
    fn syscall(&mut self, no: u64, args: &[u64]) -> vmp_core::Result<u64> {
        self.inner.syscall(no, args)
    }
    fn vm_call_region(&mut self, region_id: u64, args: &[u64]) -> vmp_core::Result<u64> {
        match dispatch_vm(self.blob, region_id as usize, args, self.inner) {
            Ok(v) => Ok(v),
            Err(StubError::NoRegion(id)) => Err(vmp_core::Error::vm(format!("E1:{:x}", id))),
            Err(StubError::Vm(e)) => Err(e),
            Err(StubError::Blob(s)) => Err(vmp_core::Error::vm(s)),
        }
    }

    fn vm_call_region_fp(
        &mut self,
        region_id: u64,
        gpr: &[u64; 8],
        fpr: &[u64; 8],
    ) -> vmp_core::Result<(u64, u64)> {
        match dispatch_vm_fp(self.blob, region_id as usize, gpr, fpr, self.inner) {
            Ok(v) => Ok(v),
            Err(StubError::NoRegion(id)) => Err(vmp_core::Error::vm(format!("E1:{:x}", id))),
            Err(StubError::Vm(e)) => Err(e),
            Err(StubError::Blob(s)) => Err(vmp_core::Error::vm(s)),
        }
    }
}

/// 将 target 解析为某个 region_id，否则返回 None。
///
/// 两层匹配:
///   1. target == load_bias + region.patch_addr —— 直接是 trampoline 入口。
///   2. target 处是一条 ARM64 `B imm26` 指令 —— 单条蹦床, 解出真实目标后再
///      跟 patch_addr 比对 (rewriter 不会在 binary 里放 trampoline 的 thunk,
///      但被保护函数之间互相 `b region_entry` 这种 tail-call 蹦床很常见).
fn resolve_to_region(
    blob: &super::StubBlob,
    load_bias: u64,
    target: u64,
) -> Option<usize> {
    // Layer 1
    for (idx, region) in blob.regions.iter().enumerate() {
        if target == load_bias + region.patch_addr as u64 {
            return Some(idx);
        }
    }
    // Layer 2: decode single B at target
    if target & 0x3 != 0 || target < 0x1000 {
        return None;
    }
    // Read with the assumption target is mapped executable (caller already
    // gates by validation in LinuxHost.native_call). We're optimistic here;
    // a wrong read would SEGV which the parent handler would catch.
    let raw = unsafe { core::ptr::read_volatile(target as *const u32) };
    // B imm26: bits 31:26 = 0b000101
    if raw >> 26 != 0b000101 {
        return None;
    }
    let imm26 = (raw & 0x03FF_FFFF) as i64;
    let off = if imm26 & (1 << 25) != 0 {
        imm26 | !((1 << 26) - 1)
    } else {
        imm26
    } * 4;
    let branched = (target as i64).wrapping_add(off) as u64;
    for (idx, region) in blob.regions.iter().enumerate() {
        if branched == load_bias + region.patch_addr as u64 {
            return Some(idx);
        }
    }
    None
}

/// 默认 host bridge：禁用所有外部调用 / 内存访问，仅适合纯逻辑测试。
pub struct NullHost;

impl HostBridge for NullHost {
    fn load(&mut self, _addr: u64, _w: Width) -> CoreResult<u64> {
        Ok(0)
    }
    fn store(&mut self, _addr: u64, _v: u64, _w: Width) -> CoreResult<()> {
        Ok(())
    }
    fn native_call(&mut self, _t: u64, _args: &[u64]) -> CoreResult<u64> {
        Ok(0)
    }
    fn syscall(&mut self, _no: u64, _args: &[u64]) -> CoreResult<u64> {
        Ok(0)
    }
}

/// 内存沙盒 host：只允许访问预注册地址段。用于功能性单元测试。
pub struct SandboxHost {
    pub mem: Vec<(u64, Vec<u8>)>,
}

impl SandboxHost {
    fn find(&mut self, addr: u64) -> Option<(usize, usize)> {
        for (i, (base, m)) in self.mem.iter().enumerate() {
            if addr >= *base && addr < *base + m.len() as u64 {
                return Some((i, (addr - *base) as usize));
            }
        }
        None
    }
}

impl HostBridge for SandboxHost {
    fn load(&mut self, addr: u64, w: Width) -> CoreResult<u64> {
        let (i, off) = self.find(addr).ok_or_else(|| vmp_core::Error::vm("oob load"))?;
        let n = w.bytes();
        let s = &self.mem[i].1[off..off + n];
        let mut v = 0u64;
        for (k, b) in s.iter().enumerate() {
            v |= (*b as u64) << (k * 8);
        }
        Ok(v)
    }
    fn store(&mut self, addr: u64, val: u64, w: Width) -> CoreResult<()> {
        let (i, off) = self.find(addr).ok_or_else(|| vmp_core::Error::vm("oob store"))?;
        let n = w.bytes();
        for k in 0..n {
            self.mem[i].1[off + k] = ((val >> (k * 8)) & 0xFF) as u8;
        }
        Ok(())
    }
    fn native_call(&mut self, _t: u64, _args: &[u64]) -> CoreResult<u64> {
        Err(vmp_core::Error::vm("sandbox 不允许 native call"))
    }
    fn syscall(&mut self, _no: u64, _args: &[u64]) -> CoreResult<u64> {
        Err(vmp_core::Error::vm("sandbox 不允许 syscall"))
    }
}

#[allow(dead_code)]
fn _forces_use(_: VmState) {}
