//! vmp-interpreter
//!
//! VM 解释器。设计为 **handler-table dispatch**，每条物理 opcode 经查表后调用对应 handler。
//!
//! 该 crate 同时被两个环境使用：
//! 1. **加壳器进程内**：用于功能性测试 / 模拟运行 lift 后的字节码（保证正确性）
//! 2. **被保护程序的 stub 内**：通过 [`vmp-stub`] 二次包装后嵌入目标二进制
//!
//! 因此不能依赖 std 之外的资源（这里仍然用 std；最终 stub crate 会做 no_std 适配）。

pub mod state;

use log::trace;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use vmp_core::{Error, Result};
use vmp_isa::{decode_instr, Cond, IsaSpec, VOp, Width};

pub use state::{HostBridge, VmState};

/// Diagnostic flag: when set (typically by the on-device cdylib's qvmp_init
/// when the rewrite-time `--log on` flag is baked into the QVMP header),
/// every VOp::NativeCall logs "BLR xN target=0x… x0..x7=…" to fd 2 before
/// crossing into the host. Silent on the protect-side CLI by default.
pub static TRACE_NATIVE_CALLS: AtomicBool = AtomicBool::new(false);

/// 主可执行 ELF 的 dlpi_addr。PIE 二进制 lifter 把 ADRP/ADR/LDR-literal 编成
/// `Add rd, V62, offset`，运行时需要 V62 = load_bias 才能算出真实地址。
/// 由 vmp-soruntime 的 qvmp_init 在 dl_iterate_phdr 找到 QVMP magic 那一瞬
/// 写入。CLI 模拟器场景保留 0（与 lift 时 pc 一致）。
pub static MAIN_EXEC_LOAD_BIAS: AtomicU64 = AtomicU64::new(0);

/// lifter / interpreter 约定：VM 寄存器 V62 在每次 run() 启动时被装载
/// MAIN_EXEC_LOAD_BIAS，用于 ADRP / ADR / LDR-literal 的运行时重定位。
pub const VM_REG_LOAD_BIAS: usize = 62;

/// Raw `SYS_write` via inline syscall — completely bypasses libc/bionic logger
/// machinery, which holds internal mutexes that deadlock if the SIGTRAP handler
/// re-enters them. POSIX `write(2)` is technically async-signal-safe, but
/// observed bionic interactions (errno TLS, sockets, etc) make the syscall
/// path the only truly safe option for tracing on the signal path.
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
#[inline]
unsafe fn syscall_write(fd: i32, buf: *const u8, len: usize) {
    let _r: i64;
    core::arch::asm!(
        "svc #0",
        in("x8") 64u64,
        inlateout("x0") fd as u64 => _r,
        inlateout("x1") buf as u64 => _,
        inlateout("x2") len as u64 => _,
        lateout("x3") _, lateout("x4") _, lateout("x5") _,
        lateout("x6") _, lateout("x7") _,
        options(nostack),
    );
}

#[cfg(not(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64")))]
unsafe fn syscall_write(fd: i32, buf: *const u8, len: usize) {
    extern "C" {
        fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    }
    let _ = write(fd, buf, len);
}

fn trace_native_call(rd: u8, target: u64, args: &[u64]) {
    if !TRACE_NATIVE_CALLS.load(Ordering::Relaxed) {
        return;
    }
    // Stack-only formatting, signal-safe: "[qvmp] vm: BLR xRD target=0xHEX
    // x0=… x1=… … x7=…\n"
    let mut buf = [0u8; 384];
    let mut pos = 0usize;
    fn push(buf: &mut [u8], pos: &mut usize, s: &[u8]) {
        for &b in s {
            if *pos < buf.len() {
                buf[*pos] = b;
                *pos += 1;
            }
        }
    }
    fn push_hex(buf: &mut [u8], pos: &mut usize, v: u64) {
        push(buf, pos, b"0x");
        let mut started = false;
        for i in (0..16).rev() {
            let nib = ((v >> (i * 4)) & 0xF) as u8;
            if nib != 0 || started || i == 0 {
                started = true;
                let c = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
                if *pos < buf.len() {
                    buf[*pos] = c;
                    *pos += 1;
                }
            }
        }
    }
    fn push_dec(buf: &mut [u8], pos: &mut usize, v: u64) {
        if v == 0 {
            push(buf, pos, b"0");
            return;
        }
        let mut digits = [0u8; 20];
        let mut n = 0;
        let mut v = v;
        while v > 0 {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        for i in (0..n).rev() {
            if *pos < buf.len() {
                buf[*pos] = digits[i];
                *pos += 1;
            }
        }
    }
    push(&mut buf, &mut pos, b"[qvmp] vm: BLR x");
    push_dec(&mut buf, &mut pos, rd as u64);
    push(&mut buf, &mut pos, b" target=");
    push_hex(&mut buf, &mut pos, target);
    for (i, v) in args.iter().take(8).enumerate() {
        push(&mut buf, &mut pos, b" x");
        push_dec(&mut buf, &mut pos, i as u64);
        push(&mut buf, &mut pos, b"=");
        push_hex(&mut buf, &mut pos, *v);
    }
    push(&mut buf, &mut pos, b"\n");
    unsafe {
        syscall_write(2, buf.as_ptr(), pos);
    }
}

fn trace_native_ret(target: u64, ret: u64) {
    if !TRACE_NATIVE_CALLS.load(Ordering::Relaxed) {
        return;
    }
    let mut buf = [0u8; 128];
    let mut pos = 0usize;
    fn push(buf: &mut [u8], pos: &mut usize, s: &[u8]) {
        for &b in s {
            if *pos < buf.len() {
                buf[*pos] = b;
                *pos += 1;
            }
        }
    }
    fn push_hex(buf: &mut [u8], pos: &mut usize, v: u64) {
        push(buf, pos, b"0x");
        let mut started = false;
        for i in (0..16).rev() {
            let nib = ((v >> (i * 4)) & 0xF) as u8;
            if nib != 0 || started || i == 0 {
                started = true;
                let c = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
                if *pos < buf.len() {
                    buf[*pos] = c;
                    *pos += 1;
                }
            }
        }
    }
    push(&mut buf, &mut pos, b"[qvmp] vm: <- ret=");
    push_hex(&mut buf, &mut pos, ret);
    push(&mut buf, &mut pos, b" (from target=");
    push_hex(&mut buf, &mut pos, target);
    push(&mut buf, &mut pos, b")\n");
    unsafe {
        syscall_write(2, buf.as_ptr(), pos);
    }
}

pub struct Interpreter<'a> {
    pub spec: &'a IsaSpec,
    pub bytecode: &'a [u8],
    pub state: VmState,
    /// 与宿主进程交互的桥接，可为 None（纯模拟）
    pub host: Option<&'a mut dyn HostBridge>,
    /// 字节码解密用的 IV salt；与 `CodeGen::iv_salt` 必须一致。
    pub iv_salt: u64,
}

impl<'a> Interpreter<'a> {
    pub fn new(spec: &'a IsaSpec, bytecode: &'a [u8]) -> Self {
        Self {
            spec,
            bytecode,
            state: VmState::new(),
            host: None,
            iv_salt: 0,
        }
    }

    pub fn with_host(mut self, host: &'a mut dyn HostBridge) -> Self {
        self.host = Some(host);
        self
    }

    pub fn with_iv_salt(mut self, salt: u64) -> Self {
        self.iv_salt = salt;
        self
    }

    /// 主循环；返回 VExit 时携带的值（约定放入 R0）。
    /// 旧入口 —— 通过堆分配字节码 scratch. 仅用于 host-side 模拟器/测试,
    /// 不要在 signal handler 路径上调用 (malloc 不可重入).
    pub fn run(&mut self) -> Result<u64> {
        let mut scratch = vec![0u8; self.bytecode.len()];
        self.run_with_scratch(&mut scratch)
    }

    /// signal-safe 入口：调用方提供 `bytecode.len()` 字节的 scratch buffer
    /// (栈数组 / mmap 池 / 等任何非 malloc 内存). 不再做堆分配.
    pub fn run_with_scratch(&mut self, bc_scratch: &mut [u8]) -> Result<u64> {
        if bc_scratch.len() < self.bytecode.len() {
            return Err(Error::vm("bc scratch 太小"));
        }
        // PIE 重定位：V62 = 运行时 load_bias。lifter 把 ADRP/ADR/LDR-literal
        // 都展开成 `Add rd, V62, vaddr_offset` 形式。
        self.state.regs[VM_REG_LOAD_BIAS] =
            MAIN_EXEC_LOAD_BIAS.load(Ordering::Relaxed);
        let bc_view = &mut bc_scratch[..self.bytecode.len()];
        bc_view.copy_from_slice(self.bytecode);
        if self.spec.encrypt {
            vmp_codegen::stream::decrypt_in_place_salted(
                bc_view,
                &self.spec.stream_key,
                &self.spec.stream_iv,
                self.iv_salt,
            );
        }
        let bc: &[u8] = bc_view;
        loop {
            // V63 = XZR：每周期重置为 0，保证它在 source 位置永远读 0、
            // 在 destination 位置充当"丢弃"槽位。
            self.state.regs[63] = 0;

            if self.state.pc as usize >= bc.len() {
                return Err(Error::vm("E6"));
            }
            let pc_before = self.state.pc as usize;
            let (instr, len) = decode_instr(self.spec, &bc[pc_before..])
                .map_err(|m| Error::vm(format!("decode: {m}")))?;
            self.state.pc += len as u64;
            trace!("[VM] pc={:#x} {:?}", pc_before, instr.op);

            match instr.op {
                VOp::Nop | VOp::Junk | VOp::Obfuscate => {}

                VOp::MovR => {
                    self.state.regs[instr.rd as usize] = self.state.regs[instr.rs as usize];
                }
                VOp::MovI => {
                    self.state.regs[instr.rd as usize] = instr.imm as u64;
                }
                VOp::Push => {
                    let v = self.state.regs[instr.rd as usize];
                    self.state.push(v)?;
                }
                VOp::Pop => {
                    let v = self.state.pop()?;
                    self.state.regs[instr.rd as usize] = v;
                }
                VOp::Load => {
                    let addr = self.state.regs[instr.rs as usize].wrapping_add(instr.imm as u64);
                    let v = self.host_load(addr, instr.width)?;
                    self.state.regs[instr.rd as usize] = v;
                }
                VOp::Store => {
                    let addr = self.state.regs[instr.rs as usize].wrapping_add(instr.imm as u64);
                    let v = self.state.regs[instr.rd as usize];
                    self.host_store(addr, v, instr.width)?;
                }

                VOp::Add => self.alu(instr, |a, b| a.wrapping_add(b)),
                VOp::Sub => self.alu(instr, |a, b| a.wrapping_sub(b)),
                VOp::Mul => self.alu(instr, |a, b| a.wrapping_mul(b)),
                VOp::UDiv => self.alu_checked(instr, |a, b| if b == 0 { 0 } else { a / b }),
                VOp::SDiv => self.alu_checked(instr, |a, b| {
                    let (sa, sb) = (a as i64, b as i64);
                    if sb == 0 {
                        0
                    } else {
                        (sa.wrapping_div(sb)) as u64
                    }
                }),
                VOp::And => self.alu(instr, |a, b| a & b),
                VOp::Or => self.alu(instr, |a, b| a | b),
                VOp::Xor => self.alu(instr, |a, b| a ^ b),
                VOp::Shl => self.alu(instr, |a, b| a.wrapping_shl((b & 63) as u32)),
                VOp::LShr => self.alu(instr, |a, b| a.wrapping_shr((b & 63) as u32)),
                VOp::AShr => self.alu(instr, |a, b| ((a as i64).wrapping_shr((b & 63) as u32)) as u64),
                VOp::Ror => self.alu(instr, |a, b| a.rotate_right((b & 63) as u32)),
                VOp::Neg => {
                    let v = (self.state.regs[instr.rs as usize] as i64).wrapping_neg() as u64;
                    self.state.regs[instr.rd as usize] = v & instr.width.mask();
                }
                VOp::Not => {
                    let v = !self.state.regs[instr.rs as usize];
                    self.state.regs[instr.rd as usize] = v & instr.width.mask();
                }
                VOp::CSel => {
                    let v = if self.state.flags.matches(instr.cond) {
                        self.state.regs[instr.rs as usize]
                    } else {
                        self.state.regs[instr.rt as usize]
                    };
                    self.state.regs[instr.rd as usize] = v;
                }

                VOp::Cmp => {
                    let a = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let b = self.state.regs[instr.rt as usize] & instr.width.mask();
                    let (res, carry) = a.overflowing_sub(b);
                    self.state.flags.update_arith(res, instr.width, !carry, signed_overflow_sub(a, b, res, instr.width));
                }
                VOp::Tst => {
                    let v = (self.state.regs[instr.rs as usize] & self.state.regs[instr.rt as usize])
                        & instr.width.mask();
                    self.state.flags.update_logical(v, instr.width);
                }

                VOp::Br => {
                    self.state.pc = pc_before as u64; // 相对当前指令起点
                    self.state.pc = (self.state.pc as i64 + instr.imm) as u64;
                }
                VOp::BCond => {
                    if self.state.flags.matches(instr.cond) {
                        self.state.pc = (pc_before as i64 + instr.imm) as u64;
                    }
                }
                VOp::Call => {
                    self.state.push(self.state.pc)?;
                    self.state.pc = (pc_before as i64 + instr.imm) as u64;
                }
                VOp::Ret => {
                    // 函数入口的 Ret：栈空 ⇒ 视作 VExit（返回 R0）。
                    // 嵌套调用情况下栈不空 ⇒ 弹出真实返回 PC。
                    if self.state.stack_is_empty() {
                        return Ok(self.state.regs[0]);
                    }
                    self.state.pc = self.state.pop()?;
                }
                VOp::NativeCall => {
                    // arm64 decode emits NativeCall { rd: Rn } for BLR/BR Rn —
                    // the target lives in the live VM register, not in imm.
                    let rd = instr.rd;
                    let target_ptr = self.state.regs[rd as usize];
                    trace_native_call(rd, target_ptr, &self.state.regs[..8]);
                    // AAPCS64 同时传 GPR (x0..x7) 和 FP/SIMD (v0..v7) 参数. 之前
                    // 只传 GPR, FP 路径完全丢: hardware V0..V7 仍是 SIGTRAP 触发
                    // 时 caller 的值 (stale). ImGui/Vulkan 大量 float / ImVec2 /
                    // ImVec4 经 V0..V7 传参, callee 拿到旧值 → 算出错误指针 /
                    // vtable → 跑一会必挂. 这是 v37 起 multi-region 全量挂的真因.
                    let mut gpr = [0u64; 8];
                    let mut fpr = [0u64; 8];
                    for i in 0..8 {
                        gpr[i] = self.state.regs[i];
                        fpr[i] = self.state.fregs[i] as u64;
                    }
                    let (gpr_ret, fpr_ret) = match self.host.as_deref_mut() {
                        Some(h) => h.native_call_fp(target_ptr, &gpr, &fpr)?,
                        None => return Err(Error::vm("E2")),
                    };
                    trace_native_ret(target_ptr, gpr_ret);
                    self.state.regs[0] = gpr_ret;
                    let hi = self.state.fregs[0] & !0xFFFF_FFFF_FFFF_FFFFu128;
                    self.state.fregs[0] = hi | (fpr_ret as u128);
                }
                VOp::CallRegion => {
                    let region_id = instr.imm as u64;
                    // GPR V0..V7 + FREG D0..D7 (低 64 位) 都传给 sub-dispatch
                    let mut gpr = [0u64; 8];
                    let mut fpr = [0u64; 8];
                    for i in 0..8 {
                        gpr[i] = self.state.regs[i];
                        fpr[i] = self.state.fregs[i] as u64;
                    }
                    let (ret_gpr, ret_fpr) = match self.host.as_deref_mut() {
                        Some(h) => h.vm_call_region_fp(region_id, &gpr, &fpr)?,
                        None => return Err(Error::vm("E3")),
                    };
                    self.state.regs[0] = ret_gpr;
                    // 写回 FREG D0 低 64 位（保留高 64 位，但通常调用约定不依赖高位）
                    let hi = self.state.fregs[0] & !0xFFFF_FFFF_FFFF_FFFFu128;
                    self.state.fregs[0] = hi | (ret_fpr as u128);
                }
                VOp::VExit => {
                    return Ok(self.state.regs[0]);
                }
                VOp::VEnter => {
                    return Err(Error::vm("E7"));
                }
                VOp::Syscall => {
                    let _raw_svc_imm = instr.imm as u64;
                    let no = self.state.regs[8];
                    let args = [
                        self.state.regs[0],
                        self.state.regs[1],
                        self.state.regs[2],
                        self.state.regs[3],
                        self.state.regs[4],
                        self.state.regs[5],
                    ];
                    log::debug!(
                        "SYSCALL no={} args=[{:#x},{:#x},{:#x}] D0={:#x} D1={:#x}",
                        no, args[0], args[1], args[2],
                        self.state.fregs[0] as u64, self.state.fregs[1] as u64
                    );
                    let ret = match self.host.as_deref_mut() {
                        Some(h) => h.syscall(no, &args)?,
                        None => 0,
                    };
                    self.state.regs[0] = ret;
                }
                VOp::Trap => return Err(Error::vm("E8")),

                // ==== FP / NEON ====
                VOp::FLoad => {
                    let addr = self.state.regs[instr.rs as usize].wrapping_add(instr.imm as u64);
                    match instr.width {
                        Width::W32 => {
                            let v = self.host_load(addr, Width::W32)? as u32;
                            self.state.fregs[instr.rd as usize & 31] =
                                (self.state.fregs[instr.rd as usize & 31] & !0xFFFF_FFFFu128)
                                    | (v as u128);
                        }
                        Width::W64 => {
                            let v = self.host_load(addr, Width::W64)?;
                            self.state.fregs[instr.rd as usize & 31] =
                                (self.state.fregs[instr.rd as usize & 31] & !0xFFFF_FFFF_FFFF_FFFFu128)
                                    | (v as u128);
                        }
                        _ => {
                            // 128-bit (Q) load：拆两次 u64
                            let lo = self.host_load(addr, Width::W64)?;
                            let hi = self.host_load(addr.wrapping_add(8), Width::W64)?;
                            self.state.fregs[instr.rd as usize & 31] =
                                (lo as u128) | ((hi as u128) << 64);
                        }
                    }
                }
                VOp::FStore => {
                    let addr = self.state.regs[instr.rs as usize].wrapping_add(instr.imm as u64);
                    let v = self.state.fregs[instr.rd as usize & 31];
                    match instr.width {
                        Width::W32 => self.host_store(addr, v as u64 & 0xFFFF_FFFF, Width::W32)?,
                        Width::W64 => self.host_store(addr, v as u64, Width::W64)?,
                        _ => {
                            let lo = v as u64;
                            let hi = (v >> 64) as u64;
                            self.host_store(addr, lo, Width::W64)?;
                            self.host_store(addr.wrapping_add(8), hi, Width::W64)?;
                        }
                    }
                }
                VOp::FMovR => {
                    self.state.fregs[instr.rd as usize & 31] =
                        self.state.fregs[instr.rs as usize & 31];
                }
                VOp::FMovFromGpr => {
                    let v = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let mask = instr.width.mask() as u128;
                    self.state.fregs[instr.rd as usize & 31] =
                        (self.state.fregs[instr.rd as usize & 31] & !mask) | (v as u128);
                }
                VOp::FMovToGpr => {
                    let v = self.state.fregs[instr.rs as usize & 31] as u64 & instr.width.mask();
                    self.state.regs[instr.rd as usize] = v;
                }
                VOp::FAdd => {
                    let r = fp_arith(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width,
                        |a, b| a + b,
                        |a, b| a + b,
                    );
                    self.state.fregs[instr.rd as usize & 31] = r;
                }
                VOp::FSub => {
                    let r = fp_arith(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width,
                        |a, b| a - b,
                        |a, b| a - b,
                    );
                    self.state.fregs[instr.rd as usize & 31] = r;
                }
                VOp::FMul => {
                    let r = fp_arith(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width,
                        |a, b| a * b,
                        |a, b| a * b,
                    );
                    self.state.fregs[instr.rd as usize & 31] = r;
                }
                VOp::FDiv => {
                    let r = fp_arith(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width,
                        |a, b| a / b,
                        |a, b| a / b,
                    );
                    self.state.fregs[instr.rd as usize & 31] = r;
                }
                VOp::FCmp => {
                    fp_cmp(
                        &mut self.state.flags,
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width,
                    );
                }
                VOp::FCvtZS => {
                    // float → signed int (truncate). width 应用到结果整数。
                    let f = self.state.fregs[instr.rs as usize & 31];
                    let v = match instr.width {
                        Width::W32 => f64::from(f32::from_bits(f as u32)) as i64 as u64
                            & Width::W32.mask(),
                        Width::W64 => f64::from_bits(f as u64) as i64 as u64,
                        _ => 0,
                    };
                    self.state.regs[instr.rd as usize] = v;
                }
                VOp::SCvtF => {
                    let i = self.state.regs[instr.rs as usize] as i64;
                    let bits = match instr.width {
                        Width::W32 => (i as f32).to_bits() as u128,
                        Width::W64 => (i as f64).to_bits() as u128,
                        _ => 0,
                    };
                    let mask = instr.width.mask() as u128;
                    self.state.fregs[instr.rd as usize & 31] =
                        (self.state.fregs[instr.rd as usize & 31] & !mask) | bits;
                }

                // ==== Atomics（VM 单线程：原子性来自解释器顺序执行）====
                VOp::AtomicAdd => {
                    let addr = self.state.regs[instr.rs as usize];
                    let old = self.host_load(addr, instr.width)?;
                    let val = self.state.regs[instr.rt as usize] & instr.width.mask();
                    let new = (old.wrapping_add(val)) & instr.width.mask();
                    self.host_store(addr, new, instr.width)?;
                    self.state.regs[instr.rd as usize] = old;
                }
                VOp::AtomicSwap => {
                    let addr = self.state.regs[instr.rs as usize];
                    let old = self.host_load(addr, instr.width)?;
                    let val = self.state.regs[instr.rt as usize] & instr.width.mask();
                    self.host_store(addr, val, instr.width)?;
                    self.state.regs[instr.rd as usize] = old;
                }
                VOp::AtomicCas => {
                    // CAS: rd 入参 = 期望值，rt = 新值；成功后 rd 返回旧 mem 值
                    let addr = self.state.regs[instr.rs as usize];
                    let expected = self.state.regs[instr.rd as usize] & instr.width.mask();
                    let new_val = self.state.regs[instr.rt as usize] & instr.width.mask();
                    let cur = self.host_load(addr, instr.width)?;
                    if cur == expected {
                        self.host_store(addr, new_val, instr.width)?;
                    }
                    self.state.regs[instr.rd as usize] = cur;
                }
                VOp::Barrier => {
                    // 单线程 VM：内存屏障 = noop
                }

                // ==== Bit-count / bit-reverse (dp-1src) ====
                VOp::Clz => {
                    let v = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let bits = (instr.width.bytes() * 8) as u32;
                    let r = if v == 0 { bits as u64 } else { v.leading_zeros() as u64 - (64 - bits as u64) };
                    self.state.regs[instr.rd as usize] = r;
                }
                VOp::Rbit => {
                    let v = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let r = if instr.width.bytes() == 4 {
                        (v as u32).reverse_bits() as u64
                    } else {
                        v.reverse_bits()
                    };
                    self.state.regs[instr.rd as usize] = r;
                }
                VOp::Rev => {
                    let v = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let r = if instr.width.bytes() == 4 {
                        (v as u32).swap_bytes() as u64
                    } else {
                        v.swap_bytes()
                    };
                    self.state.regs[instr.rd as usize] = r;
                }
                VOp::Rev16 => {
                    let v = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let r = if instr.width.bytes() == 4 {
                        let v = v as u32;
                        let lo = ((v & 0xFFFF) as u16).swap_bytes() as u32;
                        let hi = (((v >> 16) & 0xFFFF) as u16).swap_bytes() as u32;
                        ((hi << 16) | lo) as u64
                    } else {
                        let mut r: u64 = 0;
                        for i in 0..4 {
                            let h = ((v >> (i * 16)) & 0xFFFF) as u16;
                            r |= (h.swap_bytes() as u64) << (i * 16);
                        }
                        r
                    };
                    self.state.regs[instr.rd as usize] = r;
                }
                VOp::Rev32 => {
                    let v = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let r = if instr.width.bytes() == 4 {
                        (v as u32).swap_bytes() as u64
                    } else {
                        // 在 64-bit reg 内按 32-bit 字翻转字节
                        let lo = ((v & 0xFFFF_FFFF) as u32).swap_bytes() as u64;
                        let hi = ((v >> 32) as u32).swap_bytes() as u64;
                        (hi << 32) | lo
                    };
                    self.state.regs[instr.rd as usize] = r;
                }

                // ==== 128-bit NEON 位运算 ====
                VOp::VEor => {
                    self.state.fregs[instr.rd as usize & 31] =
                        self.state.fregs[instr.rs as usize & 31] ^ self.state.fregs[instr.rt as usize & 31];
                }
                VOp::VAnd => {
                    self.state.fregs[instr.rd as usize & 31] =
                        self.state.fregs[instr.rs as usize & 31] & self.state.fregs[instr.rt as usize & 31];
                }
                VOp::VOr => {
                    self.state.fregs[instr.rd as usize & 31] =
                        self.state.fregs[instr.rs as usize & 31] | self.state.fregs[instr.rt as usize & 31];
                }
                VOp::VNot => {
                    self.state.fregs[instr.rd as usize & 31] =
                        !self.state.fregs[instr.rs as usize & 31];
                }
                VOp::VBic => {
                    self.state.fregs[instr.rd as usize & 31] =
                        self.state.fregs[instr.rs as usize & 31] & !self.state.fregs[instr.rt as usize & 31];
                }

                // ==== 128-bit FREG 每-64-bit-lane 移位/旋转 ====
                VOp::VShlD => {
                    let v = self.state.fregs[instr.rs as usize & 31];
                    let amt = (instr.imm & 63) as u32;
                    let lo = (v as u64).wrapping_shl(amt);
                    let hi = ((v >> 64) as u64).wrapping_shl(amt);
                    self.state.fregs[instr.rd as usize & 31] = (lo as u128) | ((hi as u128) << 64);
                }
                VOp::VLShrD => {
                    let v = self.state.fregs[instr.rs as usize & 31];
                    let amt = (instr.imm & 63) as u32;
                    let lo = (v as u64).wrapping_shr(amt);
                    let hi = ((v >> 64) as u64).wrapping_shr(amt);
                    self.state.fregs[instr.rd as usize & 31] = (lo as u128) | ((hi as u128) << 64);
                }
                VOp::VRorD => {
                    let v = self.state.fregs[instr.rs as usize & 31];
                    let amt = (instr.imm & 63) as u32;
                    let lo = (v as u64).rotate_right(amt);
                    let hi = ((v >> 64) as u64).rotate_right(amt);
                    self.state.fregs[instr.rd as usize & 31] = (lo as u128) | ((hi as u128) << 64);
                }
            }
        }
    }

    fn alu(&mut self, instr: vmp_isa::Instr, f: impl Fn(u64, u64) -> u64) {
        let a = self.state.regs[instr.rs as usize] & instr.width.mask();
        let b = self.state.regs[instr.rt as usize] & instr.width.mask();
        let v = f(a, b) & instr.width.mask();
        self.state.regs[instr.rd as usize] = v;
    }

    fn alu_checked(&mut self, instr: vmp_isa::Instr, f: impl Fn(u64, u64) -> u64) {
        self.alu(instr, f);
    }

    fn host_load(&mut self, addr: u64, w: Width) -> Result<u64> {
        match self.host.as_deref_mut() {
            Some(h) => h.load(addr, w),
            None => Err(Error::vm("E9")),
        }
    }
    fn host_store(&mut self, addr: u64, v: u64, w: Width) -> Result<()> {
        match self.host.as_deref_mut() {
            Some(h) => h.store(addr, v, w),
            None => Err(Error::vm("E9")),
        }
    }
}

/// 双精度 / 单精度 FP 二元算术。
fn fp_arith(
    a: u128,
    b: u128,
    w: Width,
    op64: impl Fn(f64, f64) -> f64,
    op32: impl Fn(f32, f32) -> f32,
) -> u128 {
    match w {
        Width::W32 => {
            let af = f32::from_bits(a as u32);
            let bf = f32::from_bits(b as u32);
            let r = op32(af, bf);
            (a & !0xFFFF_FFFFu128) | (r.to_bits() as u128)
        }
        Width::W64 => {
            let af = f64::from_bits(a as u64);
            let bf = f64::from_bits(b as u64);
            let r = op64(af, bf);
            (a & !0xFFFF_FFFF_FFFF_FFFFu128) | (r.to_bits() as u128)
        }
        _ => a,
    }
}

/// FCMP：把比较结果写入 NZCV，遵循 ARM ARM 约定。NaN ⇒ N=0, Z=0, C=1, V=1。
fn fp_cmp(flags: &mut state::Flags, a: u128, b: u128, w: Width) {
    let (less, equal, unordered) = match w {
        Width::W32 => {
            let af = f32::from_bits(a as u32);
            let bf = f32::from_bits(b as u32);
            if af.is_nan() || bf.is_nan() {
                (false, false, true)
            } else {
                (af < bf, af == bf, false)
            }
        }
        _ => {
            let af = f64::from_bits(a as u64);
            let bf = f64::from_bits(b as u64);
            if af.is_nan() || bf.is_nan() {
                (false, false, true)
            } else {
                (af < bf, af == bf, false)
            }
        }
    };
    if unordered {
        flags.n = false;
        flags.z = false;
        flags.c = true;
        flags.v = true;
    } else if equal {
        flags.n = false;
        flags.z = true;
        flags.c = true;
        flags.v = false;
    } else if less {
        flags.n = true;
        flags.z = false;
        flags.c = false;
        flags.v = false;
    } else {
        // greater
        flags.n = false;
        flags.z = false;
        flags.c = true;
        flags.v = false;
    }
}

fn signed_overflow_sub(a: u64, b: u64, res: u64, w: Width) -> bool {
    let bits = (w.bytes() * 8) as u32;
    let sign_a = (a >> (bits - 1)) & 1;
    let sign_b = (b >> (bits - 1)) & 1;
    let sign_r = (res >> (bits - 1)) & 1;
    sign_a != sign_b && sign_a != sign_r
}

pub trait HostBridgeExt: HostBridge {}
impl<T: HostBridge> HostBridgeExt for T {}

// 重新导出条件码以便外部使用
pub use vmp_isa::Cond as VmCond;
#[allow(dead_code)]
fn _force_use(c: Cond) -> Cond {
    c
}
