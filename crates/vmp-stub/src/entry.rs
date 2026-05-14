//! Stub 运行时入口（host-side 模拟）。
//!
//! 真实嵌入到目标二进制中时，跳板会用对应架构的汇编写一个 thunk：
//!  - 保存调用者寄存器
//!  - 调用 `dispatch_vm(region_id, args...)`
//!  - 把返回值放回调用约定要求的寄存器
//!
//! 当前实现是 **加壳器内的功能性测试** 路径，用于验证 lift→encode→interpret 闭环。

use thiserror::Error;
use vmp_core::Result as CoreResult;
use vmp_interpreter::{HostBridge, Interpreter, VmState};
use vmp_isa::Width;

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
/// 单顶层调用（vmp-runtime main）从 `dispatch_vm` 进入；递归（CallRegion）走此路径。
pub fn dispatch_vm_fp(
    blob: &super::StubBlob,
    region_id: usize,
    gpr_args: &[u64; 8],
    fpr_args: &[u64; 8],
    host: &mut dyn HostBridge,
) -> Result<(u64, u64), StubError> {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        for ds in &blob.data_segments {
            if let Err(e) = host.map_data(ds.vaddr, &ds.bytes, ds.prot) {
                log::warn!("map_data {:#x} 失败: {}", ds.vaddr, e);
            }
        }
    });

    let r = blob.regions.get(region_id).ok_or(StubError::NoRegion(region_id))?;
    let bc = &blob.bytecode_pool[r.bc_offset as usize..(r.bc_offset + r.bc_len) as usize];

    const VM_STACK_BYTES: usize = 64 * 1024;
    let mut vm_stack: Vec<u64> = vec![0u64; VM_STACK_BYTES / 8];
    let stack_base = vm_stack.as_mut_ptr() as u64;
    let stack_top = stack_base + VM_STACK_BYTES as u64;
    let initial_sp = stack_top & !0xFu64;

    let mut nested = NestedDispatchHost { blob, inner: host };

    let mut interp = Interpreter::new(&blob.spec, bc)
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
    interp.run()?;
    let gpr_ret = interp.state.regs[0];
    let fpr_ret = interp.state.fregs[0] as u64;
    core::hint::black_box(vm_stack.as_ptr());
    Ok((gpr_ret, fpr_ret))
}

pub fn dispatch_vm(
    blob: &super::StubBlob,
    region_id: usize,
    args: &[u64],
    host: &mut dyn HostBridge,
) -> Result<u64, StubError> {
    // 第一次进入：把原 ELF 的 .rodata / .data / .bss 等加载到对应 vaddr，
    // 让 lifter 翻译的 ADR / LDR-literal / 全局访存在 vmp-runtime 进程里也能命中。
    // 用静态 OnceLock 防止重入时重复 map（递归 dispatch_vm 走 NestedDispatchHost 会触发）。
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        for ds in &blob.data_segments {
            if let Err(e) = host.map_data(ds.vaddr, &ds.bytes, ds.prot) {
                log::warn!("map_data {:#x} 失败: {}", ds.vaddr, e);
            }
        }
    });

    let r = blob.regions.get(region_id).ok_or(StubError::NoRegion(region_id))?;
    let bc = &blob.bytecode_pool[r.bc_offset as usize..(r.bc_offset + r.bc_len) as usize];

    // 给 VM 分配 64KB 真实栈：原 native 代码会做 `sub sp, sp, #N` 然后 `str/ldr [sp, #off]`，
    // 这些在解释器里走 HostBridge.store/load → 必须落到一块合法可读写的宿主内存上。
    const VM_STACK_BYTES: usize = 64 * 1024;
    let mut vm_stack: Vec<u64> = vec![0u64; VM_STACK_BYTES / 8];
    let stack_base = vm_stack.as_mut_ptr() as u64;
    let stack_top = stack_base + VM_STACK_BYTES as u64;
    let initial_sp = stack_top & !0xFu64;

    // 给 host 包一层 NestedDispatchHost：让 VOp::CallRegion 触发的 vm_call_region
    // 自动递归 dispatch_vm，从而支持「跨 region BL」。
    let mut nested = NestedDispatchHost { blob, inner: host };

    let mut interp = Interpreter::new(&blob.spec, bc)
        .with_host(&mut nested)
        .with_iv_salt(region_id as u64);
    interp.state.regs[31] = initial_sp;
    interp.state.regs[63] = 0;
    for (i, v) in args.iter().take(8).enumerate() {
        interp.state.regs[i] = *v;
    }
    let ret = interp.run()?;
    core::hint::black_box(vm_stack.as_ptr());
    Ok(ret)
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
        // BLR Rn 时 target 可能恰好指向另一个被保护函数的 trampoline 入口。
        // 直接调 native 会执行 trampoline 里的 BRK → 嵌套 SIGTRAP；若 handler
        // 没装 SA_NODEFER，信号被 mask，内核 SIGTRAP 默认动作 = 终止 (exit 133).
        // 改成识别 target == load_bias + region.patch_addr 时在 VM 里递归
        // 调度，绕开嵌套信号 + 省掉两次上下文切换。
        let load_bias = vmp_interpreter::MAIN_EXEC_LOAD_BIAS
            .load(core::sync::atomic::Ordering::Relaxed);
        if load_bias != 0 {
            for (idx, region) in self.blob.regions.iter().enumerate() {
                if target == load_bias + region.patch_addr as u64 {
                    let mut gpr = [0u64; 8];
                    let mut fpr = [0u64; 8];
                    for (i, v) in args.iter().take(8).enumerate() {
                        gpr[i] = *v;
                    }
                    return self
                        .vm_call_region_fp(idx as u64, &gpr, &fpr)
                        .map(|(g, _)| g);
                }
            }
        }
        self.inner.native_call(target, args)
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
