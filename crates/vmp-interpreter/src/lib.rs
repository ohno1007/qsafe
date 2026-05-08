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
use vmp_core::{Error, Result};
use vmp_isa::{decode_instr, Cond, IsaSpec, VOp, Width};

pub use state::{HostBridge, VmState};

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
    pub fn run(&mut self) -> Result<u64> {
        let bc = if self.spec.encrypt {
            let mut tmp = self.bytecode.to_vec();
            vmp_codegen::stream::decrypt_in_place_salted(
                &mut tmp,
                &self.spec.stream_key,
                &self.spec.stream_iv,
                self.iv_salt,
            );
            tmp
        } else {
            self.bytecode.to_vec()
        };
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
                    let mut v = self.host_load(addr, instr.width)?;
                    // cond 字段在 Load 上被用作"符号扩展模式"：
                    //   Cond::Al (默认)  零扩展（LDR / LDRB / LDRH / LDRW）
                    //   Cond::Mi         符号扩展到 W64（LDRSB / LDRSH / LDRSW）
                    //   Cond::Pl         符号扩展到 W32（LDRSB / LDRSH 32-bit form）
                    if matches!(instr.cond, Cond::Mi | Cond::Pl) {
                        let bits = (instr.width.bytes() as u32) * 8;
                        let sign_bit = 1u64 << (bits - 1);
                        if v & sign_bit != 0 {
                            let mask = if matches!(instr.cond, Cond::Mi) {
                                !((1u64 << bits) - 1) // 扩到全 64 位
                            } else {
                                !((1u64 << bits) - 1) & 0xFFFF_FFFFu64 // 扩到 32 位再零扩
                            };
                            v |= mask;
                            if matches!(instr.cond, Cond::Pl) {
                                v &= 0xFFFF_FFFFu64;
                            }
                        }
                    }
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
                    if self.state.stack.is_empty() {
                        return Ok(self.state.regs[0]);
                    }
                    self.state.pc = self.state.pop()?;
                }
                VOp::NativeCall => {
                    let target_ptr = instr.imm as u64;
                    let ret = match self.host.as_deref_mut() {
                        Some(h) => h.native_call(target_ptr, &self.state.regs[..8])?,
                        None => return Err(Error::vm("E2")),
                    };
                    self.state.regs[0] = ret;
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

                // ==== NEON 向量算术 ====
                VOp::VAdd => {
                    self.state.fregs[instr.rd as usize & 31] = vec_op(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width,
                        instr.lane,
                        |a, b| a.wrapping_add(b),
                    );
                }
                VOp::VSub => {
                    self.state.fregs[instr.rd as usize & 31] = vec_op(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width,
                        instr.lane,
                        |a, b| a.wrapping_sub(b),
                    );
                }
                VOp::VMul => {
                    self.state.fregs[instr.rd as usize & 31] = vec_op(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width,
                        instr.lane,
                        |a, b| a.wrapping_mul(b),
                    );
                }

                // ==== 位运算扩展 ====
                VOp::Rbit => {
                    let v = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let r = match instr.width {
                        Width::W32 => (v as u32).reverse_bits() as u64,
                        Width::W64 => v.reverse_bits(),
                        _ => v,
                    };
                    self.state.regs[instr.rd as usize] = r & instr.width.mask();
                }
                VOp::Rev => {
                    let v = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let r = match instr.width {
                        Width::W16 => (v as u16).swap_bytes() as u64,
                        Width::W32 => (v as u32).swap_bytes() as u64,
                        Width::W64 => v.swap_bytes(),
                        _ => v,
                    };
                    self.state.regs[instr.rd as usize] = r & instr.width.mask();
                }
                VOp::Clz => {
                    let v = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let r = match instr.width {
                        Width::W32 => (v as u32).leading_zeros() as u64,
                        Width::W64 => v.leading_zeros() as u64,
                        _ => v.leading_zeros() as u64,
                    };
                    self.state.regs[instr.rd as usize] = r;
                }

                // ==== FP 单源 ====
                VOp::FNeg => {
                    let v = self.state.fregs[instr.rs as usize & 31];
                    let r = match instr.width {
                        Width::W32 => {
                            let f = -f32::from_bits(v as u32);
                            (v & !0xFFFF_FFFFu128) | (f.to_bits() as u128)
                        }
                        Width::W64 => {
                            let f = -f64::from_bits(v as u64);
                            (v & !0xFFFF_FFFF_FFFF_FFFFu128) | (f.to_bits() as u128)
                        }
                        _ => v,
                    };
                    self.state.fregs[instr.rd as usize & 31] = r;
                }
                VOp::FAbs => {
                    let v = self.state.fregs[instr.rs as usize & 31];
                    let r = match instr.width {
                        Width::W32 => {
                            let f = f32::from_bits(v as u32).abs();
                            (v & !0xFFFF_FFFFu128) | (f.to_bits() as u128)
                        }
                        Width::W64 => {
                            let f = f64::from_bits(v as u64).abs();
                            (v & !0xFFFF_FFFF_FFFF_FFFFu128) | (f.to_bits() as u128)
                        }
                        _ => v,
                    };
                    self.state.fregs[instr.rd as usize & 31] = r;
                }
                VOp::FSqrt => {
                    let v = self.state.fregs[instr.rs as usize & 31];
                    let r = match instr.width {
                        Width::W32 => {
                            let f = f32::from_bits(v as u32).sqrt();
                            (v & !0xFFFF_FFFFu128) | (f.to_bits() as u128)
                        }
                        Width::W64 => {
                            let f = f64::from_bits(v as u64).sqrt();
                            (v & !0xFFFF_FFFF_FFFF_FFFFu128) | (f.to_bits() as u128)
                        }
                        _ => v,
                    };
                    self.state.fregs[instr.rd as usize & 31] = r;
                }

                // ==== ADC / SBC ====
                VOp::Adc => {
                    let a = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let b = self.state.regs[instr.rt as usize] & instr.width.mask();
                    let c = if self.state.flags.c { 1u64 } else { 0 };
                    let r = a.wrapping_add(b).wrapping_add(c) & instr.width.mask();
                    self.state.regs[instr.rd as usize] = r;
                    if matches!(instr.cond, Cond::Ne) {
                        // ADCS：更新 NZCV（C/V 简化）
                        let (sum1, c1) = a.overflowing_add(b);
                        let (sum2, c2) = sum1.overflowing_add(c);
                        let _ = sum2;
                        self.state.flags.update_arith(
                            r, instr.width, c1 || c2,
                            signed_overflow_sub(a, b.wrapping_neg(), r, instr.width),
                        );
                    }
                }
                VOp::Sbc => {
                    // SBC: rd = rs - rt - !C
                    let a = self.state.regs[instr.rs as usize] & instr.width.mask();
                    let b = self.state.regs[instr.rt as usize] & instr.width.mask();
                    let c = if self.state.flags.c { 0u64 } else { 1 };
                    let r = a.wrapping_sub(b).wrapping_sub(c) & instr.width.mask();
                    self.state.regs[instr.rd as usize] = r;
                    if matches!(instr.cond, Cond::Ne) {
                        let (d1, b1) = a.overflowing_sub(b);
                        let (d2, b2) = d1.overflowing_sub(c);
                        let _ = d2;
                        self.state.flags.update_arith(
                            r, instr.width, !(b1 || b2),
                            signed_overflow_sub(a, b, r, instr.width),
                        );
                    }
                }

                // ==== MulH (SMULH / UMULH 真高 64) ====
                VOp::MulH => {
                    let a = self.state.regs[instr.rs as usize];
                    let b = self.state.regs[instr.rt as usize];
                    let r = if matches!(instr.cond, Cond::Eq) {
                        // SMULH：64×64 signed → high 64
                        ((a as i64 as i128).wrapping_mul(b as i64 as i128) >> 64) as u64
                    } else {
                        // UMULH：64×64 unsigned → high 64
                        ((a as u128).wrapping_mul(b as u128) >> 64) as u64
                    };
                    self.state.regs[instr.rd as usize] = r;
                }

                // ==== IndirectBr：通过 NativeCall 跳到寄存器目标 ====
                VOp::IndirectBr => {
                    let target = self.state.regs[instr.rd as usize];
                    let ret = match self.host.as_deref_mut() {
                        Some(h) => h.native_call(target, &self.state.regs[..8])?,
                        None => return Err(Error::vm("E2")),
                    };
                    self.state.regs[0] = ret;
                }

                // ==== NEON FP 向量 ====
                VOp::VFAdd => {
                    self.state.fregs[instr.rd as usize & 31] = vec_fp_op(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width, instr.lane,
                        |a, b| a + b, |a, b| a + b,
                    );
                }
                VOp::VFSub => {
                    self.state.fregs[instr.rd as usize & 31] = vec_fp_op(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width, instr.lane,
                        |a, b| a - b, |a, b| a - b,
                    );
                }
                VOp::VFMul => {
                    self.state.fregs[instr.rd as usize & 31] = vec_fp_op(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width, instr.lane,
                        |a, b| a * b, |a, b| a * b,
                    );
                }
                VOp::VFDiv => {
                    self.state.fregs[instr.rd as usize & 31] = vec_fp_op(
                        self.state.fregs[instr.rs as usize & 31],
                        self.state.fregs[instr.rt as usize & 31],
                        instr.width, instr.lane,
                        |a, b| a / b, |a, b| a / b,
                    );
                }

                // ==== CCMP ====
                VOp::Ccmp => {
                    if self.state.flags.matches(instr.cond) {
                        // 条件成立 → 真做 Cmp 设标志
                        let a = self.state.regs[instr.rs as usize] & instr.width.mask();
                        let b = self.state.regs[instr.rt as usize] & instr.width.mask();
                        let (res, carry) = a.overflowing_sub(b);
                        self.state.flags.update_arith(
                            res, instr.width, !carry,
                            signed_overflow_sub(a, b, res, instr.width),
                        );
                    } else {
                        // 不成立 → 把 imm 低 4 bit 当 nzcv 备份值写入
                        let nzcv = (instr.imm as u8) & 0xF;
                        self.state.flags.n = (nzcv >> 3) & 1 != 0;
                        self.state.flags.z = (nzcv >> 2) & 1 != 0;
                        self.state.flags.c = (nzcv >> 1) & 1 != 0;
                        self.state.flags.v = nzcv & 1 != 0;
                    }
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

/// 整数向量逐 lane 二元运算。lane size 由 `width` 决定（W8 / W16 / W32 / W64）；
/// `lane_count` 决定向量总长（lane_count * width.bytes()，必须 <= 16）。
/// 高位未占用部分保留 a 的高位字节。
fn vec_op(
    a: u128,
    b: u128,
    width: Width,
    lane_count: u8,
    op: impl Fn(u64, u64) -> u64,
) -> u128 {
    let lane_bytes = width.bytes();
    let lc = lane_count as usize;
    let total_bytes = lane_bytes * lc;
    if total_bytes == 0 || total_bytes > 16 {
        return a;
    }
    let mask = width.mask() as u128;
    let mut out: u128 = 0;
    for i in 0..lc {
        let shift = (i * lane_bytes * 8) as u32;
        let av = ((a >> shift) as u64) & width.mask();
        let bv = ((b >> shift) as u64) & width.mask();
        let r = op(av, bv) & width.mask();
        out |= (r as u128) << shift;
    }
    // 保留 a 的高位（向量总长 < 128 时）
    let used_mask = if total_bytes >= 16 {
        u128::MAX
    } else {
        let bits = (total_bytes * 8) as u32;
        (1u128 << bits) - 1
    };
    let _ = mask;
    (a & !used_mask) | (out & used_mask)
}

/// NEON 浮点向量逐 lane 运算。`width` = 单 lane 宽度（W32 单精度 / W64 双精度）；
/// `lane_count` ∈ {2, 4}。其它 lane 数视作 noop（保留高位）。
fn vec_fp_op(
    a: u128, b: u128, width: Width, lane_count: u8,
    op64: impl Fn(f64, f64) -> f64,
    op32: impl Fn(f32, f32) -> f32,
) -> u128 {
    let lc = lane_count as usize;
    if lc == 0 || lc > 4 {
        return a;
    }
    let lane_bytes = width.bytes();
    let total_bytes = lane_bytes * lc;
    if total_bytes == 0 || total_bytes > 16 {
        return a;
    }
    let mut out: u128 = 0;
    for i in 0..lc {
        let shift = (i * lane_bytes * 8) as u32;
        match width {
            Width::W32 => {
                let av = f32::from_bits((a >> shift) as u32);
                let bv = f32::from_bits((b >> shift) as u32);
                let r = op32(av, bv).to_bits() as u128;
                out |= r << shift;
            }
            Width::W64 => {
                let av = f64::from_bits((a >> shift) as u64);
                let bv = f64::from_bits((b >> shift) as u64);
                let r = op64(av, bv).to_bits() as u128;
                out |= r << shift;
            }
            _ => {}
        }
    }
    let used_mask = if total_bytes >= 16 {
        u128::MAX
    } else {
        let bits = (total_bytes * 8) as u32;
        (1u128 << bits) - 1
    };
    (a & !used_mask) | (out & used_mask)
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
