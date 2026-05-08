//! VM 指令字节级编解码。
//!
//! 通用变长格式：
//!
//! ```text
//!   +------+----------+----------+-----------+--------------+
//!   | OP   | (Rd|cond)| Rs       | Rt | Wid  | imm (0/4/8B) |
//!   +------+----------+----------+-----------+--------------+
//!     1B       1B         1B        1B            0/4/8B
//! ```
//!
//! 不同 VOp 占用不同的尾部字段，由 [`Instr::layout`] 决定。

use crate::opcode::{Cond, VOp, Width};
use crate::spec::IsaSpec;
use byteorder::{ByteOrder, LittleEndian};

pub const MAX_INSTR_LEN: usize = 16;

#[derive(Clone, Copy)]
pub struct Instr {
    pub op: VOp,
    pub rd: u8,
    pub rs: u8,
    pub rt: u8,
    pub width: Width,
    pub cond: Cond,
    pub imm: i64,
    /// 选择第几个 handler 变体（codegen 设置）
    pub variant: u8,
    /// NEON 向量 lane 数量（2 / 4 / 8 / 16）。仅 VAdd/VSub/VMul 等向量 VOp 使用，
    /// 配合 `width` 一起决定向量总位宽：lane * width.bytes()*8 ∈ {64, 128}。
    pub lane: u8,
}

impl core::fmt::Debug for Instr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(debug_assertions)]
        {
            f.debug_struct("Instr")
                .field("op", &self.op)
                .field("rd", &self.rd)
                .field("rs", &self.rs)
                .field("rt", &self.rt)
                .field("width", &self.width)
                .field("cond", &self.cond)
                .field("imm", &self.imm)
                .field("variant", &self.variant)
                .field("lane", &self.lane)
                .finish()
        }
        #[cfg(not(debug_assertions))]
        {
            write!(
                f,
                "I({:?},{},{},{},{:?},{:?},{},{},{})",
                self.op, self.rd, self.rs, self.rt, self.width, self.cond, self.imm, self.variant, self.lane
            )
        }
    }
}

impl Default for Instr {
    fn default() -> Self {
        Self {
            op: VOp::Nop,
            rd: 0,
            rs: 0,
            rt: 0,
            width: Width::W64,
            cond: Cond::Al,
            imm: 0,
            variant: 0,
            lane: 0,
        }
    }
}

/// 指令布局，用于决定哪些字段需要被编码。
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub has_rd: bool,
    pub has_rs: bool,
    pub has_rt: bool,
    pub has_width: bool,
    pub has_cond: bool,
    /// 0 / 4 / 8
    pub imm_bytes: u8,
    /// NEON 向量 lane 数量字段。设 true 时多出 1 字节存放 lane 数量。
    pub has_lane: bool,
}

impl Layout {
    pub const fn r0() -> Self {
        Layout { has_rd: false, has_rs: false, has_rt: false, has_width: false, has_cond: false, imm_bytes: 0, has_lane: false }
    }
    pub const fn r1() -> Self {
        Layout { has_rd: true, has_rs: false, has_rt: false, has_width: false, has_cond: false, imm_bytes: 0, has_lane: false }
    }
    pub const fn r2() -> Self {
        Layout { has_rd: true, has_rs: true, has_rt: false, has_width: false, has_cond: false, imm_bytes: 0, has_lane: false }
    }
    pub const fn r3w() -> Self {
        Layout { has_rd: true, has_rs: true, has_rt: true, has_width: true, has_cond: false, imm_bytes: 0, has_lane: false }
    }
    /// 向量 r3w + lane：rd, rs, rt, width(lane size), lane(lane count)
    pub const fn r3wl() -> Self {
        Layout { has_rd: true, has_rs: true, has_rt: true, has_width: true, has_cond: false, imm_bytes: 0, has_lane: true }
    }
    pub const fn r1i32() -> Self {
        Layout { has_rd: true, has_rs: false, has_rt: false, has_width: false, has_cond: false, imm_bytes: 4, has_lane: false }
    }
    pub const fn r1i64() -> Self {
        Layout { has_rd: true, has_rs: false, has_rt: false, has_width: false, has_cond: false, imm_bytes: 8, has_lane: false }
    }
    pub const fn r2i32w() -> Self {
        Layout { has_rd: true, has_rs: true, has_rt: false, has_width: true, has_cond: false, imm_bytes: 4, has_lane: false }
    }
    pub const fn i32_only() -> Self {
        Layout { has_rd: false, has_rs: false, has_rt: false, has_width: false, has_cond: false, imm_bytes: 4, has_lane: false }
    }
    pub const fn cond_i32() -> Self {
        Layout { has_rd: false, has_rs: false, has_rt: false, has_width: false, has_cond: true, imm_bytes: 4, has_lane: false }
    }
}

impl Instr {
    pub fn layout(&self) -> Layout {
        match self.op {
            VOp::Nop | VOp::Ret | VOp::VExit | VOp::Trap | VOp::Junk | VOp::Obfuscate => Layout::r0(),
            VOp::MovR | VOp::Neg | VOp::Not => Layout::r2(),
            VOp::CSel => Layout {
                has_rd: true,
                has_rs: true,
                has_rt: true,
                has_width: false,
                has_cond: true,
                imm_bytes: 0,
                has_lane: false,
            },
            VOp::Add
            | VOp::Sub
            | VOp::Mul
            | VOp::UDiv
            | VOp::SDiv
            | VOp::And
            | VOp::Or
            | VOp::Xor
            | VOp::Shl
            | VOp::LShr
            | VOp::AShr
            | VOp::Ror => Layout::r3w(),
            VOp::Cmp | VOp::Tst => Layout {
                has_rd: false,
                has_rs: true,
                has_rt: true,
                has_width: true,
                has_cond: false,
                imm_bytes: 0,
                has_lane: false,
            },
            VOp::Push => Layout::r1(),
            VOp::Pop => Layout::r1(),
            VOp::MovI => Layout::r1i64(),
            VOp::Load | VOp::Store => Layout::r2i32w(),
            VOp::Br => Layout::i32_only(),
            VOp::BCond => Layout::cond_i32(),
            VOp::Call => Layout::i32_only(),
            VOp::CallRegion => Layout::i32_only(),
            VOp::NativeCall => Layout::r1i64(),
            VOp::VEnter => Layout::r1i64(),
            VOp::Syscall => Layout::i32_only(),

            // FP load/store: rd(vreg) + rs(gpr) + width + imm32
            VOp::FLoad | VOp::FStore => Layout::r2i32w(),
            // FP move register: rd(vreg) + rs(vreg)
            VOp::FMovR => Layout::r2(),
            // FP <-> GPR: rd + rs + width
            VOp::FMovFromGpr | VOp::FMovToGpr => Layout {
                has_rd: true, has_rs: true, has_rt: false,
                has_width: true, has_cond: false, imm_bytes: 0, has_lane: false,
            },
            // FP arithmetic: rd + rs + rt + width
            VOp::FAdd | VOp::FSub | VOp::FMul | VOp::FDiv => Layout::r3w(),
            // FP compare: rs + rt + width (no rd)
            VOp::FCmp => Layout {
                has_rd: false, has_rs: true, has_rt: true,
                has_width: true, has_cond: false, imm_bytes: 0, has_lane: false,
            },
            // FP <-> Int 转换: rd + rs + width
            VOp::FCvtZS | VOp::SCvtF => Layout {
                has_rd: true, has_rs: true, has_rt: false,
                has_width: true, has_cond: false, imm_bytes: 0, has_lane: false,
            },

            // Atomic add/swap/cas：rd(返回) + rs(地址 GPR) + rt(值 GPR) + width
            VOp::AtomicAdd | VOp::AtomicSwap | VOp::AtomicCas => Layout::r3w(),
            // 内存屏障无操作数
            VOp::Barrier => Layout::r0(),

            // NEON 向量算术：r3w + lane 字段
            VOp::VAdd | VOp::VSub | VOp::VMul => Layout::r3wl(),

            // 位运算扩展（rd + rs + width，无 rt）
            VOp::Rbit | VOp::Rev | VOp::Clz => Layout {
                has_rd: true, has_rs: true, has_rt: false,
                has_width: true, has_cond: false, imm_bytes: 0, has_lane: false,
            },

            // FP 单源（rd + rs + width）
            VOp::FNeg | VOp::FAbs | VOp::FSqrt => Layout {
                has_rd: true, has_rs: true, has_rt: false,
                has_width: true, has_cond: false, imm_bytes: 0, has_lane: false,
            },

            // ADC / SBC：r3w + cond（cond 表示是否更新标志位）
            VOp::Adc | VOp::Sbc => Layout {
                has_rd: true, has_rs: true, has_rt: true,
                has_width: true, has_cond: true, imm_bytes: 0, has_lane: false,
            },

            // CCMP：rs + rt + width + cond + imm32（imm 字段低 4 bit 是 NZCV nzcv 备份值）
            VOp::Ccmp => Layout {
                has_rd: false, has_rs: true, has_rt: true,
                has_width: true, has_cond: true, imm_bytes: 4, has_lane: false,
            },

            // MulH: rd + rs + rt + width + cond（cond 选签名 / 无签名）
            VOp::MulH => Layout {
                has_rd: true, has_rs: true, has_rt: true,
                has_width: true, has_cond: true, imm_bytes: 0, has_lane: false,
            },

            // IndirectBr: rd 是寄存器号
            VOp::IndirectBr => Layout::r1(),

            // NEON FP 向量：r3w + lane（width=W32 单 / W64 双；lane=2/4）
            VOp::VFAdd | VOp::VFSub | VOp::VFMul | VOp::VFDiv => Layout::r3wl(),

            // VDupG: rd(vreg) + rs(gpr) + width + lane
            VOp::VDupG => Layout {
                has_rd: true, has_rs: true, has_rt: false,
                has_width: true, has_cond: false, imm_bytes: 0, has_lane: true,
            },
            // VDupE: rd(vreg) + rs(vreg) + width + lane + imm32(source lane index)
            VOp::VDupE => Layout {
                has_rd: true, has_rs: true, has_rt: false,
                has_width: true, has_cond: false, imm_bytes: 4, has_lane: true,
            },
            // VShlI: rd + rs + width + lane + cond(direction) + imm32(shift amount)
            VOp::VShlI => Layout {
                has_rd: true, has_rs: true, has_rt: false,
                has_width: true, has_cond: true, imm_bytes: 4, has_lane: true,
            },

            // NativeExec: imm32 = 4-byte 原 ARM 指令；不需要寄存器字段（VmState 由 host 直接读写）
            VOp::NativeExec => Layout::i32_only(),
        }
    }

    pub fn encoded_len(&self) -> usize {
        let lay = self.layout();
        1 // opcode
            + (lay.has_rd as usize)
            + (lay.has_rs as usize)
            + (lay.has_rt as usize)
            + (lay.has_width as usize)
            + (lay.has_cond as usize)
            + (lay.has_lane as usize)
            + lay.imm_bytes as usize
    }
}

pub fn encode_instr(spec: &IsaSpec, instr: &Instr, out: &mut Vec<u8>) -> Result<(), String> {
    let variant = spec
        .pick_variant(instr.op, instr.variant as usize)
        .ok_or_else(|| format!("无 ISA 编码: {:?}", instr.op))?;
    out.push(variant.opcode);

    let lay = instr.layout();
    if lay.has_rd {
        out.push(spec.enc_reg(instr.rd));
    }
    if lay.has_rs {
        out.push(spec.enc_reg(instr.rs));
    }
    if lay.has_rt {
        out.push(spec.enc_reg(instr.rt));
    }
    if lay.has_width {
        out.push(width_to_byte(instr.width));
    }
    if lay.has_cond {
        out.push(instr.cond as u8);
    }
    if lay.has_lane {
        out.push(instr.lane);
    }
    match lay.imm_bytes {
        0 => {}
        4 => {
            // 32 位 imm（用于跳转 / syscall 号 / 偏移）
            let v = if matches!(instr.op, VOp::Br | VOp::BCond | VOp::Call) {
                spec.enc_branch(instr.imm as i32) as u32
            } else {
                instr.imm as i32 as u32
            };
            let mut tmp = [0u8; 4];
            LittleEndian::write_u32(&mut tmp, v);
            out.extend_from_slice(&tmp);
        }
        8 => {
            let v = spec.enc_imm(instr.imm as u64);
            let mut tmp = [0u8; 8];
            LittleEndian::write_u64(&mut tmp, v);
            out.extend_from_slice(&tmp);
        }
        _ => return Err(format!("非法立即数宽度: {}", lay.imm_bytes)),
    }
    Ok(())
}

pub fn decode_instr(spec: &IsaSpec, bytes: &[u8]) -> Result<(Instr, usize), String> {
    if bytes.is_empty() {
        return Err("decode: 空字节".into());
    }
    let (op, _tweak) = spec
        .decode_opcode(bytes[0])
        .ok_or_else(|| format!("未知 opcode: 0x{:02x}", bytes[0]))?;
    let mut instr = Instr::default();
    instr.op = op;
    let mut pos = 1usize;
    let lay = instr.layout();

    if lay.has_rd {
        instr.rd = spec.dec_reg(*bytes.get(pos).ok_or("EOF rd")?);
        pos += 1;
    }
    if lay.has_rs {
        instr.rs = spec.dec_reg(*bytes.get(pos).ok_or("EOF rs")?);
        pos += 1;
    }
    if lay.has_rt {
        instr.rt = spec.dec_reg(*bytes.get(pos).ok_or("EOF rt")?);
        pos += 1;
    }
    if lay.has_width {
        instr.width = byte_to_width(*bytes.get(pos).ok_or("EOF width")?);
        pos += 1;
    }
    if lay.has_cond {
        instr.cond = Cond::from_u8(*bytes.get(pos).ok_or("EOF cond")?);
        pos += 1;
    }
    if lay.has_lane {
        instr.lane = *bytes.get(pos).ok_or("EOF lane")?;
        pos += 1;
    }
    match lay.imm_bytes {
        0 => {}
        4 => {
            if bytes.len() < pos + 4 {
                return Err("EOF imm32".into());
            }
            let raw = LittleEndian::read_u32(&bytes[pos..pos + 4]);
            instr.imm = if matches!(op, VOp::Br | VOp::BCond | VOp::Call) {
                spec.dec_branch(raw as i32) as i64
            } else {
                raw as i32 as i64
            };
            pos += 4;
        }
        8 => {
            if bytes.len() < pos + 8 {
                return Err("EOF imm64".into());
            }
            let raw = LittleEndian::read_u64(&bytes[pos..pos + 8]);
            instr.imm = spec.dec_imm(raw) as i64;
            pos += 8;
        }
        _ => unreachable!(),
    }
    Ok((instr, pos))
}

fn width_to_byte(w: Width) -> u8 {
    match w {
        Width::W8 => 0,
        Width::W16 => 1,
        Width::W32 => 2,
        Width::W64 => 3,
    }
}
fn byte_to_width(b: u8) -> Width {
    match b & 3 {
        0 => Width::W8,
        1 => Width::W16,
        2 => Width::W32,
        _ => Width::W64,
    }
}
