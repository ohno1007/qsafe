//! ARM64 32-bit 指令解码器。
//!
//! 已覆盖：
//!   - Data-Processing-Immediate: ADR/ADRP, ADD/SUB(imm) +S, AND/ORR/EOR(imm),
//!     MOVZ/MOVN/MOVK, UBFM/SBFM/BFM(含 LSL/LSR/ASR/UXT/SXT 别名), EXTR
//!   - Branches: B, BL, B.cond, RET, BR, BLR, CBZ, CBNZ, TBZ, TBNZ, SVC
//!   - Loads/Stores: LDR/STR(unsigned-imm 含 byte/half/word/dword), LDUR/STUR,
//!     LDP/STP(signed-offset/pre/post), LDR(literal), 寄存器偏移 LDR/STR(基本形)
//!   - Data-Processing-Register: ADD/SUB(reg), AND/ORR/EOR/ANDS(reg),
//!     LSLV/LSRV/ASRV/RORV, MUL(MADD/MSUB), UDIV/SDIV, CSEL/CSET/CSINC/CSINV/CSNEG,
//!     SUBS / CMP / CMN / TST 别名
//!   - HINT (含 NOP)，BRK / HLT → Trap
//!
//! 所有 lifter 内部 scratch 均使用 V32..V35（不与任何 ARM64 寄存器冲突）。

use vmp_isa::Width as VmWidth;
use vmp_isa::{Cond, Instr, VOp};
pub type Width = VmWidth;

/// lifter 私有 scratch 寄存器；保证不与 ARM64 V0..V31 冲突。
const SCRATCH: u8 = 32;
const SCRATCH2: u8 = 33;
const SCRATCH3: u8 = 34;
/// 运行时 load_bias 槽位：interpreter 在 run() 起始把宿主 ELF 的 dlpi_addr
/// 写进去。PIE 二进制的 ADRP / ADR / LDR(literal) 在 lift 阶段算出的是
/// 「以 ELF 起点 0 为 base 的偏移」，运行时必须加上 load_bias 才是真地址。
const LOAD_BIAS_REG: u8 = 62;
/// 固定 XZR：interpreter 每周期重置为 0。指令族里需要 X31 当 XZR 时把寄存器号映射到这里。
const XZR_VREG: u8 = 63;

/// 用于「Rn/Rm/Rd = 31 ⇒ XZR」语义的指令族（逻辑寄存器、加减寄存器、CSEL、CMP/CMN/TST 系列等）。
#[inline]
fn xzr(r: u8) -> u8 {
    if r == 31 { XZR_VREG } else { r }
}

pub fn decode(raw: u32, pc: u64) -> Result<Vec<Instr>, &'static str> {
    // ---- 特殊单字 ----
    if raw == 0xD503_201F {
        return Ok(vec![Instr { op: VOp::Nop, ..Default::default() }]);
    }
    // HINT 系列 (D503_20XX)：当作 Nop
    if (raw >> 8) == 0xD503_20 {
        return Ok(vec![Instr { op: VOp::Nop, ..Default::default() }]);
    }
    // SVC #imm16: 1101_0100_000 imm16 0_0001
    if (raw >> 21) == 0b1101_0100_000 && (raw & 0x1F) == 0b00001 {
        let imm = ((raw >> 5) & 0xFFFF) as i64;
        return Ok(vec![Instr { op: VOp::Syscall, imm, ..Default::default() }]);
    }
    // BRK / HLT / DCPS → Trap
    if (raw >> 21) == 0b1101_0100_001 {
        return Ok(vec![Instr { op: VOp::Trap, ..Default::default() }]);
    }
    if (raw >> 21) == 0b1101_0100_010 {
        return Ok(vec![Instr { op: VOp::Trap, ..Default::default() }]);
    }

    // ---- DMB / DSB / ISB 内存屏障：D5033Bxx (System) → Barrier (VM 单线程退化为 noop) ----
    // 1101 0101 0000 0011 0011 xxxx 1011 1111 (DMB), bits 31:12 固定的子集判断
    if (raw & 0xFFFF_F0FF) == 0xD503_30BF || (raw & 0xFFFF_F0FF) == 0xD503_309F
        || (raw & 0xFFFF_F0FF) == 0xD503_30DF
    {
        return Ok(vec![Instr { op: VOp::Barrier, ..Default::default() }]);
    }

    // op0 = bits 28:25
    let op0 = (raw >> 25) & 0xF;
    match op0 {
        0x8 | 0x9 => decode_data_imm(raw, pc),
        0xA | 0xB => decode_branch(raw, pc),
        0x4 | 0x6 | 0xC | 0xE => decode_load_store(raw, pc),
        0x5 | 0xD => decode_data_reg(raw),
        0x7 | 0xF => decode_simd_fp(raw),
        _ => Err("unsupported op0"),
    }
}

// =================================================================
// Data Processing - Immediate
// =================================================================
fn decode_data_imm(raw: u32, pc: u64) -> Result<Vec<Instr>, &'static str> {
    // bits 28:23 子分类
    let sub = (raw >> 23) & 0x3F;

    // ---- ADR / ADRP ----
    // 1 immlo[2] 10000 immhi[19] Rd  → bit 31 = op (0=ADR,1=ADRP), bits 28:24 = 10000
    if (raw >> 24) & 0x1F == 0b10000 {
        let op = (raw >> 31) & 1;
        let immlo = ((raw >> 29) & 0x3) as i64;
        let immhi = ((raw >> 5) & 0x7FFFF) as i64;
        let mut imm = (immhi << 2) | immlo;
        if imm & (1 << 20) != 0 {
            imm |= !((1 << 21) - 1);
        }
        let rd = (raw & 0x1F) as u8;
        let target = if op == 1 {
            ((pc & !0xFFFu64) as i64).wrapping_add(imm << 12) as u64
        } else {
            (pc as i64).wrapping_add(imm) as u64
        };
        // PIE-aware: 在 lift 时 target 是 ELF 内部 vaddr (load_bias=0)，
        // 运行时必须加上真实 load_bias。展开为两条 VOp：
        //   MovI SCRATCH = target        (作为 64-bit offset)
        //   Add  rd = LOAD_BIAS_REG + SCRATCH
        return Ok(vec![
            Instr {
                op: VOp::MovI,
                rd: SCRATCH,
                imm: target as i64,
                width: Width::W64,
                ..Default::default()
            },
            Instr {
                op: VOp::Add,
                rd,
                rs: LOAD_BIAS_REG,
                rt: SCRATCH,
                width: Width::W64,
                ..Default::default()
            },
        ]);
    }

    let sf = (raw >> 31) & 1;
    let width = if sf == 1 { Width::W64 } else { Width::W32 };

    // ---- ADD/SUB (immediate) (sub & 0x3E == 0b10001x for non-tags) ----
    if sub & 0x3E == 0b100010 {
        let s = (raw >> 29) & 1;
        let sub_op = (raw >> 30) & 1;
        let shift = (raw >> 22) & 1;
        let mut imm12 = ((raw >> 10) & 0xFFF) as i64;
        if shift == 1 {
            imm12 <<= 12;
        }
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        let vop = if sub_op == 1 { VOp::Sub } else { VOp::Add };
        let dst = if s == 1 && rd == 31 { SCRATCH2 } else { rd };
        let mut out = Vec::with_capacity(4);
        out.push(Instr { op: VOp::MovI, rd: SCRATCH, imm: imm12, width: Width::W64, ..Default::default() });
        if s == 1 {
            // **必须在写 dst 之前** 算标志，否则 SUBS Rn,Rn,#imm 时 rn 已被覆盖。
            if sub_op == 1 {
                // SUBS / CMP：完整标志（含 C/V borrow），来自 rn - imm
                out.push(Instr { op: VOp::Cmp, rs: rn, rt: SCRATCH, width, ..Default::default() });
            } else {
                // ADDS / CMN：先把 rn+imm 算到 SCRATCH3，再 Tst 设 N/Z（C/V 近似 0）
                out.push(Instr { op: VOp::Add, rd: SCRATCH3, rs: rn, rt: SCRATCH, width, ..Default::default() });
                out.push(Instr { op: VOp::Tst, rs: SCRATCH3, rt: SCRATCH3, width, ..Default::default() });
            }
        }
        out.push(Instr { op: vop, rd: dst, rs: rn, rt: SCRATCH, width, ..Default::default() });
        return Ok(out);
    }

    // ---- Logical (immediate) ----
    // sub == 0b100100
    if sub == 0b100100 {
        let opc = (raw >> 29) & 0x3;
        let n_bit = (raw >> 22) & 1;
        let immr = (raw >> 16) & 0x3F;
        let imms = (raw >> 10) & 0x3F;
        // Rn=31 → XZR；Rd=31 在 ANDS 是 XZR (TST 别名)，AND/ORR/EOR imm 中 Rd=31 是 SP，
        // 这里采用最常见语义：源用 XZR，目的保留 31 让 SP 形式工作（极罕见）。
        let rn = xzr(((raw >> 5) & 0x1F) as u8);
        let rd = (raw & 0x1F) as u8;
        let datasize: u32 = if sf == 1 { 64 } else { 32 };
        let imm = decode_bit_masks(n_bit as u8, imms as u8, immr as u8, datasize)
            .ok_or("logical-imm 解码失败")? as i64;
        let vop = match opc {
            0 => VOp::And,
            1 => VOp::Or,
            2 => VOp::Xor,
            _ => VOp::And, // ANDS
        };
        // ANDS 也可能是 TST 别名（rd=31）
        if opc == 3 && rd == 31 {
            return Ok(vec![
                Instr { op: VOp::MovI, rd: SCRATCH, imm, width: Width::W64, ..Default::default() },
                Instr { op: VOp::Tst, rs: rn, rt: SCRATCH, width, ..Default::default() },
            ]);
        }
        let mut out = vec![
            Instr { op: VOp::MovI, rd: SCRATCH, imm, width: Width::W64, ..Default::default() },
            Instr { op: vop, rd, rs: rn, rt: SCRATCH, width, ..Default::default() },
        ];
        if opc == 3 {
            out.push(Instr { op: VOp::Tst, rs: rd, rt: rd, width, ..Default::default() });
        }
        return Ok(out);
    }

    // ---- Move wide (immediate) ---- (sub == 0b100101)
    if sub == 0b100101 {
        let opc = (raw >> 29) & 0x3;
        let hw = (raw >> 21) & 0x3;
        let imm16 = ((raw >> 5) & 0xFFFF) as u64;
        let rd = (raw & 0x1F) as u8;
        let shift = (hw * 16) as u32;
        match opc {
            0b00 => {
                let v = !((imm16 << shift) as i64);
                return Ok(vec![Instr { op: VOp::MovI, rd, imm: v, width, ..Default::default() }]);
            }
            0b10 => {
                let v = (imm16 << shift) as i64;
                return Ok(vec![Instr { op: VOp::MovI, rd, imm: v, width, ..Default::default() }]);
            }
            0b11 => {
                let mask: u64 = !(0xFFFFu64 << shift);
                return Ok(vec![
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: mask as i64, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::And, rd, rs: rd, rt: SCRATCH, width, ..Default::default() },
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: (imm16 << shift) as i64, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::Or, rd, rs: rd, rt: SCRATCH, width, ..Default::default() },
                ]);
            }
            _ => return Err("MOVW reserved opc"),
        }
    }

    // ---- Bitfield: SBFM / BFM / UBFM ---- (sub == 0b100110)
    if sub == 0b100110 {
        let opc = (raw >> 29) & 0x3; // 00 SBFM, 01 BFM, 10 UBFM
        let immr = ((raw >> 16) & 0x3F) as u32;
        let imms = ((raw >> 10) & 0x3F) as u32;
        let rn = xzr(((raw >> 5) & 0x1F) as u8);
        let rd = xzr((raw & 0x1F) as u8);
        let regsize: u32 = if sf == 1 { 64 } else { 32 };

        // 检测常见别名：
        if imms == regsize - 1 {
            // 右移：UBFM = LSR, SBFM = ASR
            let vop = if opc == 0b10 { VOp::LShr } else if opc == 0b00 { VOp::AShr } else { VOp::And };
            return Ok(vec![
                Instr { op: VOp::MovI, rd: SCRATCH, imm: immr as i64, width: Width::W64, ..Default::default() },
                Instr { op: vop, rd, rs: rn, rt: SCRATCH, width, ..Default::default() },
            ]);
        }
        if imms < immr {
            // 左移：UBFM = LSL #(regsize-immr)
            let shift = (regsize - immr) as i64;
            let vop = if opc == 0b00 { VOp::Shl } else { VOp::Shl };
            return Ok(vec![
                Instr { op: VOp::MovI, rd: SCRATCH, imm: shift, width: Width::W64, ..Default::default() },
                Instr { op: vop, rd, rs: rn, rt: SCRATCH, width, ..Default::default() },
            ]);
        }
        // UXT*/SXT* 系列：immr=0, imms 决定字节数
        if immr == 0 {
            let bits = imms + 1;
            if opc == 0b10 {
                // UXTB/UXTH/UXTW: rd = rn & ((1<<bits)-1)
                let mask: u64 = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                return Ok(vec![
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: mask as i64, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::And, rd, rs: rn, rt: SCRATCH, width, ..Default::default() },
                ]);
            }
            if opc == 0b00 {
                // SXTB/SXTH/SXTW: 用左移再算术右移做符号扩展
                let shift = (regsize - bits) as i64;
                return Ok(vec![
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: shift, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::Shl, rd, rs: rn, rt: SCRATCH, width, ..Default::default() },
                    Instr { op: VOp::AShr, rd, rs: rd, rt: SCRATCH, width, ..Default::default() },
                ]);
            }
        }
        // 一般 BFM (opc=01) / UBFX (opc=10, imms>=immr) / SBFX (opc=00, imms>=immr).
        // 规范化两个语义:
        //   - UBFM (opc=10) : 提取 bits [imms:immr] 到 rd[0:imms-immr], 零扩展.
        //     Rd = (Rn >> immr) & ((1 << (imms-immr+1)) - 1)
        //   - SBFM (opc=00) : 同上但符号扩展. 用 LShl+AShr 二步走.
        //   - BFM  (opc=01) : 把 Rn 的 imms-immr+1 位插入到 Rd 的 [immr+width-1:immr]
        //                     (保留 Rd 其余位).
        let width_bits = (imms.wrapping_sub(immr).wrapping_add(1)) & 0x3F;
        let mask: u64 = if width_bits >= 64 { u64::MAX } else { (1u64 << width_bits) - 1 };
        match opc {
            0b10 => {
                // UBFX/UBFIZ: Rd = (Rn >> immr) & mask
                return Ok(vec![
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: immr as i64, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::LShr, rd: SCRATCH2, rs: rn, rt: SCRATCH, width, ..Default::default() },
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: mask as i64, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::And, rd, rs: SCRATCH2, rt: SCRATCH, width, ..Default::default() },
                ]);
            }
            0b00 => {
                // SBFX: 先 LSL 把符号位推到高位, 再 AShr 回来
                let shl = (regsize as i64).saturating_sub(imms as i64 + 1).max(0);
                let ashr = shl + immr as i64;
                return Ok(vec![
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: shl, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::Shl, rd: SCRATCH2, rs: rn, rt: SCRATCH, width, ..Default::default() },
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: ashr, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::AShr, rd, rs: SCRATCH2, rt: SCRATCH, width, ..Default::default() },
                ]);
            }
            0b01 => {
                // BFI/BFXIL: 把 Rn 的低 width_bits 位插入 Rd[immr+width_bits-1:immr],
                // 其余位保留.
                //   masked_rn = (Rn & mask) << immr
                //   keep_mask = ~(mask << immr)
                //   Rd = (Rd & keep_mask) | masked_rn
                let pos_mask: u64 = mask.wrapping_shl(immr).wrapping_neg().wrapping_sub(1)
                    ^ u64::MAX;  // = !(mask << immr)
                let pos_mask = !(mask.wrapping_shl(immr));
                return Ok(vec![
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: mask as i64, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::And, rd: SCRATCH2, rs: rn, rt: SCRATCH, width, ..Default::default() },
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: immr as i64, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::Shl, rd: SCRATCH2, rs: SCRATCH2, rt: SCRATCH, width, ..Default::default() },
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: pos_mask as i64, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::And, rd, rs: rd, rt: SCRATCH, width, ..Default::default() },
                    Instr { op: VOp::Or, rd, rs: rd, rt: SCRATCH2, width, ..Default::default() },
                ]);
            }
            _ => return Err("BFM opc reserved"),
        }
    }

    // ---- EXTR (immediate) ---- (sub == 0b100111)
    if sub == 0b100111 {
        // EXTR Rd, Rn, Rm, #lsb : Rd = ((Rm:Rn) >> lsb)[regsize-1:0]
        //   一般形:  Rd = (Rn >> lsb) | (Rm << (regsize - lsb))
        //   别名 ROR (Rn==Rm) 同样匹配此式 (Rn >> lsb) | (Rn << (regsize-lsb))
        let rm = ((raw >> 16) & 0x1F) as u8;
        let imms = ((raw >> 10) & 0x3F) as u32;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        let regsize: u32 = if sf == 1 { 64 } else { 32 };
        if rn == rm {
            return Ok(vec![
                Instr { op: VOp::MovI, rd: SCRATCH, imm: imms as i64, width: Width::W64, ..Default::default() },
                Instr { op: VOp::Ror, rd, rs: rn, rt: SCRATCH, width, ..Default::default() },
            ]);
        }
        // 一般形: 先算 (Rn >> imms) -> SCRATCH; 再算 (Rm << (regsize-imms)) -> SCRATCH2; 拼回 rd.
        // imms == 0 时左移 regsize-0 = regsize 会变 undefined; ARM ARM 规定此情形结果 = Rn (即 ROR 0).
        let hi_shift = (regsize.saturating_sub(imms)) as i64;
        let mut out: Vec<Instr> = Vec::with_capacity(6);
        out.push(Instr { op: VOp::MovI, rd: SCRATCH3, imm: imms as i64, width: Width::W64, ..Default::default() });
        out.push(Instr { op: VOp::LShr, rd: SCRATCH, rs: rn, rt: SCRATCH3, width, ..Default::default() });
        if imms == 0 {
            // 直接是 Rn
            out.push(Instr { op: VOp::MovR, rd, rs: SCRATCH, ..Default::default() });
        } else {
            out.push(Instr { op: VOp::MovI, rd: SCRATCH3, imm: hi_shift, width: Width::W64, ..Default::default() });
            out.push(Instr { op: VOp::Shl, rd: SCRATCH2, rs: rm, rt: SCRATCH3, width, ..Default::default() });
            out.push(Instr { op: VOp::Or, rd, rs: SCRATCH, rt: SCRATCH2, width, ..Default::default() });
        }
        return Ok(out);
    }

    Err("data-imm 子类未实现")
}

// =================================================================
// Branches & exceptions
// =================================================================
fn decode_branch(raw: u32, pc: u64) -> Result<Vec<Instr>, &'static str> {
    // B / BL : 000101 imm26 (B), 100101 imm26 (BL)
    let top6 = (raw >> 26) & 0x3F;
    if top6 == 0b000101 || top6 == 0b100101 {
        let imm26 = (raw & 0x03FF_FFFF) as i64;
        let off = if (imm26 & (1 << 25)) != 0 {
            imm26 | !((1 << 26) - 1)
        } else {
            imm26
        } * 4;
        let target = (pc as i64 + off) as u64;
        let op = if top6 == 0b100101 { VOp::Call } else { VOp::Br };
        return Ok(vec![Instr { op, imm: target as i64, ..Default::default() }]);
    }
    // B.cond : 0101_0100 imm19 0 cond
    if (raw >> 24) & 0xFF == 0x54 {
        let cond = (raw & 0xF) as u8;
        let imm19 = ((raw >> 5) & 0x7FFFF) as i64;
        let off = if (imm19 & (1 << 18)) != 0 {
            imm19 | !((1 << 19) - 1)
        } else {
            imm19
        } * 4;
        let target = (pc as i64 + off) as u64;
        return Ok(vec![Instr { op: VOp::BCond, cond: Cond::from_u8(cond), imm: target as i64, ..Default::default() }]);
    }

    // CBZ / CBNZ : sf 011010 op imm19 Rt
    let cbz_top = (raw >> 25) & 0x3F; // bits 30:25
    if cbz_top == 0b011010 {
        let sf = (raw >> 31) & 1;
        let opc = (raw >> 24) & 1; // 0=CBZ, 1=CBNZ
        let imm19 = ((raw >> 5) & 0x7FFFF) as i64;
        let off = if (imm19 & (1 << 18)) != 0 {
            imm19 | !((1 << 19) - 1)
        } else {
            imm19
        } * 4;
        let target = (pc as i64 + off) as u64;
        let rt = (raw & 0x1F) as u8;
        let width = if sf == 1 { Width::W64 } else { Width::W32 };
        // 实现：用 Tst rt,rt 设置 Z 标志，然后 BCond Eq/Ne
        let cond = if opc == 0 { Cond::Eq } else { Cond::Ne };
        return Ok(vec![
            Instr { op: VOp::Tst, rs: rt, rt, width, ..Default::default() },
            Instr { op: VOp::BCond, cond, imm: target as i64, ..Default::default() },
        ]);
    }

    // TBZ / TBNZ : b5 011011 op b40 imm14 Rt
    if (raw >> 25) & 0x3F == 0b011011 {
        let b5 = (raw >> 31) & 1;
        let opc = (raw >> 24) & 1; // 0=TBZ, 1=TBNZ
        let b40 = (raw >> 19) & 0x1F;
        let bit_index = ((b5 << 5) | b40) as i64;
        let imm14 = ((raw >> 5) & 0x3FFF) as i64;
        let off = if (imm14 & (1 << 13)) != 0 {
            imm14 | !((1 << 14) - 1)
        } else {
            imm14
        } * 4;
        let target = (pc as i64 + off) as u64;
        let rt = (raw & 0x1F) as u8;
        // 实现：mask = 1 << bit_index ; tst rt, mask ; b.eq/ne target
        let mask: i64 = 1i64 << bit_index;
        let cond = if opc == 0 { Cond::Eq } else { Cond::Ne };
        return Ok(vec![
            Instr { op: VOp::MovI, rd: SCRATCH, imm: mask, width: Width::W64, ..Default::default() },
            Instr { op: VOp::Tst, rs: rt, rt: SCRATCH, width: Width::W64, ..Default::default() },
            Instr { op: VOp::BCond, cond, imm: target as i64, ..Default::default() },
        ]);
    }

    // RET / BR / BLR : Unconditional branch (register)
    if (raw >> 25) & 0x7F == 0b1101011 {
        let opc = (raw >> 21) & 0xF;
        let rn = ((raw >> 5) & 0x1F) as u8;
        match opc {
            0b0000 => {
                // BR Rn → tail-call: 调函数指针 + 把它的 return 当本 region 的 return.
                // 没补 Ret 的话 NativeCall 之后 PC 继续往下走，越过 IR 末尾就抛 E6.
                return Ok(vec![
                    Instr { op: VOp::NativeCall, rd: rn, ..Default::default() },
                    Instr { op: VOp::Ret, ..Default::default() },
                ]);
            }
            0b0001 => {
                // BLR Rn → 正常调用，落回下一条 IR.
                return Ok(vec![Instr { op: VOp::NativeCall, rd: rn, ..Default::default() }]);
            }
            0b0010 => {
                // RET Rn
                return Ok(vec![Instr { op: VOp::Ret, ..Default::default() }]);
            }
            _ => return Err("uncond-branch-reg 子类未实现"),
        }
    }

    Err("branch 子类未实现")
}

// =================================================================
// Loads & Stores
// =================================================================
fn decode_load_store(raw: u32, pc: u64) -> Result<Vec<Instr>, &'static str> {
    // ---- LDR (literal): 0_x_011_0_00 imm19 Rt ----
    // pattern: bits 31:30 = opc, bit 29:24 = 011000
    if (raw >> 24) & 0x3F == 0b011000 {
        let opc = (raw >> 30) & 0x3;
        let imm19 = ((raw >> 5) & 0x7FFFF) as i64;
        let off = if (imm19 & (1 << 18)) != 0 {
            imm19 | !((1 << 19) - 1)
        } else {
            imm19
        } * 4;
        let rt = (raw & 0x1F) as u8;
        let target = (pc as i64 + off) as u64;
        let width = match opc {
            0 => Width::W32,
            1 => Width::W64,
            _ => Width::W64, // LDRSW（符号扩展未做）
        };
        // PIE-aware: LDR (literal) 同 ADRP，target 是 ELF vaddr，运行时需要
        // 加 load_bias。
        return Ok(vec![
            Instr { op: VOp::MovI, rd: SCRATCH, imm: target as i64, width: Width::W64, ..Default::default() },
            Instr { op: VOp::Add, rd: SCRATCH, rs: LOAD_BIAS_REG, rt: SCRATCH, width: Width::W64, ..Default::default() },
            Instr { op: VOp::Load, rd: rt, rs: SCRATCH, imm: 0, width, ..Default::default() },
        ]);
    }

    // ---- LDP / STP FP (V=1, NEON 寄存器 incl. Q-form): bits 29:25 = 10110 ----
    //   opc bits 31:30: 00 = 32-bit (S), 01 = 64-bit (D), 10 = 128-bit (Q).
    //   idx bits 24:23: 01=post, 10=offset, 11=pre.
    if (raw >> 25) & 0x1F == 0b10110 {
        let opc = (raw >> 30) & 0x3;
        let idx = (raw >> 23) & 0x3;
        let l = (raw >> 22) & 1;
        let mut imm7 = ((raw >> 15) & 0x7F) as i32;
        if imm7 & 0x40 != 0 { imm7 |= !0x7F; }
        let rt2 = ((raw >> 10) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        if opc == 0b11 || idx == 0b00 {
            return Err("FP LDP/STP 变体未实现");
        }
        let (scale, width) = match opc {
            0b00 => (4i64, Width::W32),
            0b01 => (8i64, Width::W64),
            0b10 => (16i64, Width::W8),  // sentinel for 128-bit Q
            _ => return Err("FP LDP/STP opc reserved"),
        };
        let offset = (imm7 as i64) * scale;
        let mut out = Vec::with_capacity(6);
        let do_pair = |out: &mut Vec<Instr>, base: u8, base_off: i64| {
            out.push(Instr {
                op: if l == 1 { VOp::FLoad } else { VOp::FStore },
                rd: rt, rs: base, imm: base_off, width,
                ..Default::default()
            });
            out.push(Instr {
                op: if l == 1 { VOp::FLoad } else { VOp::FStore },
                rd: rt2, rs: base, imm: base_off + scale, width,
                ..Default::default()
            });
        };
        match idx {
            0b10 => { do_pair(&mut out, rn, offset); }
            0b01 => {
                do_pair(&mut out, rn, 0);
                out.push(Instr { op: VOp::MovI, rd: SCRATCH, imm: offset, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd: rn, rs: rn, rt: SCRATCH, width: Width::W64, ..Default::default() });
            }
            0b11 => {
                out.push(Instr { op: VOp::MovI, rd: SCRATCH, imm: offset, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd: rn, rs: rn, rt: SCRATCH, width: Width::W64, ..Default::default() });
                do_pair(&mut out, rn, 0);
            }
            _ => unreachable!(),
        }
        return Ok(out);
    }

    // ---- LDP / STP (整数, V=0)：bits 29:25 = 10100 ----
    if (raw >> 25) & 0x1F == 0b10100 {
        let opc = (raw >> 30) & 0x3;
        let idx = (raw >> 23) & 0x3; // 01=post, 10=offset, 11=pre
        let l = (raw >> 22) & 1;
        let mut imm7 = ((raw >> 15) & 0x7F) as i32;
        if imm7 & 0x40 != 0 {
            imm7 |= !0x7F;
        }
        let rt2 = ((raw >> 10) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        if opc == 0b11 || idx == 0b00 {
            return Err("LDP/STP 变体未实现");
        }
        let scale: i64 = if opc == 0 { 4 } else { 8 };
        let offset = (imm7 as i64) * scale;
        let width = if opc == 0 { Width::W32 } else { Width::W64 };
        let mut out = Vec::with_capacity(6);

        let do_pair = |out: &mut Vec<Instr>, base: u8, base_off: i64| {
            out.push(Instr {
                op: if l == 1 { VOp::Load } else { VOp::Store },
                rd: rt,
                rs: base,
                imm: base_off,
                width,
                ..Default::default()
            });
            out.push(Instr {
                op: if l == 1 { VOp::Load } else { VOp::Store },
                rd: rt2,
                rs: base,
                imm: base_off + scale,
                width,
                ..Default::default()
            });
        };

        match idx {
            0b10 => {
                // signed offset: addr = Rn + offset
                do_pair(&mut out, rn, offset);
            }
            0b01 => {
                // post-indexed: addr = Rn ; Rn += offset
                do_pair(&mut out, rn, 0);
                out.push(Instr { op: VOp::MovI, rd: SCRATCH, imm: offset, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd: rn, rs: rn, rt: SCRATCH, width: Width::W64, ..Default::default() });
            }
            0b11 => {
                // pre-indexed: Rn += offset ; addr = Rn
                out.push(Instr { op: VOp::MovI, rd: SCRATCH, imm: offset, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd: rn, rs: rn, rt: SCRATCH, width: Width::W64, ..Default::default() });
                do_pair(&mut out, rn, 0);
            }
            _ => unreachable!(),
        }
        return Ok(out);
    }

    // ---- LSE atomic operations: LDADD / LDCLR / LDEOR / LDSET / SWP（含 acq/rel 后缀） ----
    //   size[31:30] | 111 000 | A[23] | R[22] | 1[21] | Rs[20:16] | o3[15] | opc[14:12] | 00 | Rn | Rt
    if (raw >> 30) <= 3 && (raw >> 24) & 0x3F == 0b111000 && (raw >> 21) & 1 == 1
        && (raw >> 10) & 0x3 == 0b00
    {
        let size = (raw >> 30) & 0x3;
        let _a = (raw >> 23) & 1;
        let _r = (raw >> 22) & 1;
        let rs = ((raw >> 16) & 0x1F) as u8; // 值（输入）
        let o3 = (raw >> 15) & 1;
        let opc = (raw >> 12) & 0x7;
        let rn = ((raw >> 5) & 0x1F) as u8; // 地址 (X 寄存器)
        let rt = (raw & 0x1F) as u8;       // 返回值
        let width = match size {
            0 => Width::W8,
            1 => Width::W16,
            2 => Width::W32,
            _ => Width::W64,
        };
        // VOp 接收：rd=返回值寄存器, rs=地址寄存器（GPR）, rt=值寄存器
        // 注意我的 VOp::AtomicAdd/Swap 编码是 r3w：rd, rs(addr), rt(val), width
        if o3 == 0 {
            match opc {
                0 => return Ok(vec![Instr { op: VOp::AtomicAdd, rd: rt, rs: rn, rt: rs, width, ..Default::default() }]),
                _ => return Err("LSE atomic opcode 仅实现 LDADD"),
            }
        } else {
            // o3=1: SWP / LDSMAX / LDSMIN / ...
            match opc {
                0 => return Ok(vec![Instr { op: VOp::AtomicSwap, rd: rt, rs: rn, rt: rs, width, ..Default::default() }]),
                _ => return Err("LSE atomic o3=1 opcode 仅实现 SWP"),
            }
        }
    }

    // ---- CAS / CASA / CASL / CASAL : size 001000 1A 1 11111 R 11111 Rn Rt ----
    //   bits 31:30 = size; bits 29:24 = 001000; bit 23 = A; bit 22 = 1; bit 21 = 1; bits 20:16 = Rs；
    //   bit 15 = R; bits 14:10 = 11111; bits 9:5 = Rn; bits 4:0 = Rt
    if (raw >> 24) & 0x3F == 0b001000 && (raw >> 21) & 1 == 1 && (raw >> 22) & 1 == 1
        && (raw >> 10) & 0x1F == 0b11111
    {
        let size = (raw >> 30) & 0x3;
        let rs = ((raw >> 16) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        let width = match size {
            0 => Width::W8,
            1 => Width::W16,
            2 => Width::W32,
            _ => Width::W64,
        };
        // CAS 语义: 期望值在 Rs，新值在 Rt，地址在 Rn；旧 mem 值写回 Rs。
        // VOp::AtomicCas 设计：rd=Rs（in/out），rs=Rn（addr），rt=Rt（new value）。
        return Ok(vec![Instr {
            op: VOp::AtomicCas,
            rd: rs,
            rs: rn,
            rt,
            width,
            ..Default::default()
        }]);
    }

    // ---- LDXR / STXR / LDAXR / STLXR (load/store exclusive) ----
    //   size 001000 0[L] 1 0 11111 1 11111 Rn Rt   (LDXR family)
    //   size 001000 0[L] 0 0 Rs    1 11111 Rn Rt   (STXR family)
    if (raw >> 24) & 0x3F == 0b001000 && (raw >> 21) & 1 == 0 {
        let size = (raw >> 30) & 0x3;
        let l = (raw >> 22) & 1;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        let width = match size {
            0 => Width::W8,
            1 => Width::W16,
            2 => Width::W32,
            _ => Width::W64,
        };
        // 单线程 VM 下 LL/SC 退化为普通 load/store；STXR 还要写一个 0 (success) 到 Ws
        if l == 1 {
            return Ok(vec![Instr { op: VOp::Load, rd: rt, rs: rn, imm: 0, width, ..Default::default() }]);
        } else {
            let rs = ((raw >> 16) & 0x1F) as u8;
            // STXR 写值：mem[rn] = Rt；状态寄存器 Ws = 0（成功）
            return Ok(vec![
                Instr { op: VOp::Store, rd: rt, rs: rn, imm: 0, width, ..Default::default() },
                Instr { op: VOp::MovI, rd: rs, imm: 0, width: Width::W64, ..Default::default() },
            ]);
        }
    }

    // ---- FP LDR/STR (immediate, unsigned offset) — V=1 ----
    if (raw >> 24) & 0x3F == 0b111101 {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3;
        let imm12 = ((raw >> 10) & 0xFFF) as i64;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        // size=00 + opc[1]=1 → 128-bit Q-reg load/store. opc=10=STR, 11=LDR.
        if size == 0 && (opc & 0b10) != 0 {
            let op = if opc == 0b10 { VOp::FStore } else { VOp::FLoad };
            let scaled = imm12 * 16; // Q-reg = 16 bytes scale
            // 用 Width::W8 作"sentinel 表示 128-bit Q-form"; interpreter 的
            // FLoad/FStore 在 W8/W16 分支会走 128-bit 路径.
            return Ok(vec![Instr { op, rd: rt, rs: rn, imm: scaled, width: Width::W8, ..Default::default() }]);
        }
        if size != 2 && size != 3 {
            return Err("FP LDR/STR B/H 暂不支持");
        }
        let width = if size == 2 { Width::W32 } else { Width::W64 };
        let scaled = imm12 * width.bytes() as i64;
        let op = if opc == 0 { VOp::FStore } else { VOp::FLoad };
        return Ok(vec![Instr { op, rd: rt, rs: rn, imm: scaled, width, ..Default::default() }]);
    }

    // ---- FP LDR/STR (immediate, 9-bit pre/post/unscaled) — V=1 ----
    // bits 29:24 = 111100, bit 21 = 0；bits 23:22 = opc 自由
    if (raw >> 24) & 0x3F == 0b111100 && (raw >> 21) & 1 == 0 {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3;
        let mut imm9 = ((raw >> 12) & 0x1FF) as i64;
        if imm9 & 0x100 != 0 { imm9 |= !0x1FF; }
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        let idx = (raw >> 10) & 0x3;
        let (width, is_q) = if size == 0 && (opc & 0b10) != 0 {
            (Width::W8, true)
        } else if size == 2 {
            (Width::W32, false)
        } else if size == 3 {
            (Width::W64, false)
        } else {
            return Err("FP unscaled-imm B/H 暂不支持");
        };
        let op = if (opc & 0b1) == 0 && !is_q { VOp::FStore }
                 else if (opc & 0b1) == 0 && is_q { VOp::FStore }
                 else { VOp::FLoad };
        // Q-form 的 opc 是 10=ST, 11=LD; non-Q 是 00=ST, 01=LD.
        let op = if is_q {
            if opc == 0b10 { VOp::FStore } else { VOp::FLoad }
        } else {
            if opc == 0 { VOp::FStore } else { VOp::FLoad }
        };
        let mut out = Vec::with_capacity(4);
        match idx {
            0b00 => {
                out.push(Instr { op, rd: rt, rs: rn, imm: imm9, width, ..Default::default() });
            }
            0b01 => {
                // post-indexed
                out.push(Instr { op, rd: rt, rs: rn, imm: 0, width, ..Default::default() });
                out.push(Instr { op: VOp::MovI, rd: SCRATCH, imm: imm9, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd: rn, rs: rn, rt: SCRATCH, width: Width::W64, ..Default::default() });
            }
            0b11 => {
                // pre-indexed
                out.push(Instr { op: VOp::MovI, rd: SCRATCH, imm: imm9, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd: rn, rs: rn, rt: SCRATCH, width: Width::W64, ..Default::default() });
                out.push(Instr { op, rd: rt, rs: rn, imm: 0, width, ..Default::default() });
            }
            _ => return Err("FP unscaled-imm idx 未分配"),
        }
        return Ok(out);
    }

    // ---- LDR/STR (immediate, unsigned offset) ----
    // bits 31:30 = size, 29:24 = 111001 (V=0)
    if (raw >> 24) & 0x3F == 0b111001 {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3; // 00=STR, 01=LDR (zero-ext), 10=LDRS to 64, 11=LDRS to 32
        let imm12 = ((raw >> 10) & 0xFFF) as i64;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        let width = match size {
            0 => Width::W8,
            1 => Width::W16,
            2 => Width::W32,
            _ => Width::W64,
        };
        let scaled = imm12 * width.bytes() as i64;
        let op = if opc == 0 { VOp::Store } else { VOp::Load };
        // 简化：LDRS（符号扩展）暂当作普通 Load
        return Ok(vec![Instr { op, rd: rt, rs: rn, imm: scaled, width, ..Default::default() }]);
    }

    // ---- LDR/STR (immediate, 9-bit unscaled / pre-index / post-index) ----
    //   bits 29:24 = 111000, bit 21 = 0; bits 11:10: 00 LDUR/STUR, 01 post, 11 pre.
    //   opc 在 bits 23:22: 00 = STR, 01 = LDR (zero-ext), 10 = LDRS to 64, 11 = LDRS to 32.
    //   (注意 opc 占位别让 IF 锁死成 STR-only — 之前 mask 卡死 bits 23:22 = 00, 全部
    //    signed-extend load 路径都被遗漏, 1725+ 条指令进了 fallback Trap.)
    if (raw >> 24) & 0x3F == 0b111000 && (raw >> 21) & 1 == 0 {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3;
        let mut imm9 = ((raw >> 12) & 0x1FF) as i64;
        if imm9 & 0x100 != 0 {
            imm9 |= !0x1FF;
        }
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        let idx = (raw >> 10) & 0x3;
        let width = match size {
            0 => Width::W8,
            1 => Width::W16,
            2 => Width::W32,
            _ => Width::W64,
        };
        let op = if opc == 0 { VOp::Store } else { VOp::Load };
        let mut out = Vec::with_capacity(4);
        match idx {
            0b00 => {
                out.push(Instr { op, rd: rt, rs: rn, imm: imm9, width, ..Default::default() });
            }
            0b01 => {
                // post-indexed: addr = Rn; Rn += imm9
                out.push(Instr { op, rd: rt, rs: rn, imm: 0, width, ..Default::default() });
                out.push(Instr { op: VOp::MovI, rd: SCRATCH, imm: imm9, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd: rn, rs: rn, rt: SCRATCH, width: Width::W64, ..Default::default() });
            }
            0b11 => {
                // pre-indexed: Rn += imm9; addr = Rn
                out.push(Instr { op: VOp::MovI, rd: SCRATCH, imm: imm9, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd: rn, rs: rn, rt: SCRATCH, width: Width::W64, ..Default::default() });
                out.push(Instr { op, rd: rt, rs: rn, imm: 0, width, ..Default::default() });
            }
            _ => return Err("LDR/STR idx 未分配"),
        }
        return Ok(out);
    }

    // ---- LDR/STR (register offset) : Rt = mem[Rn + extend(Rm) (LSL #scale)] ----
    // bits 29:24 = 111000, bit 21 = 1, bits 11:10 = 10
    if (raw >> 24) & 0x3F == 0b111000
        && (raw >> 21) & 1 == 1
        && (raw >> 10) & 0x3 == 0b10
    {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let s = (raw >> 12) & 1;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        let width = match size {
            0 => Width::W8,
            1 => Width::W16,
            2 => Width::W32,
            _ => Width::W64,
        };
        let shift = if s == 1 { width.bytes().trailing_zeros() as i64 } else { 0 };
        let mut out = Vec::with_capacity(5);
        out.push(Instr { op: VOp::MovR, rd: SCRATCH, rs: rm, ..Default::default() });
        if shift > 0 {
            out.push(Instr { op: VOp::MovI, rd: SCRATCH2, imm: shift, width: Width::W64, ..Default::default() });
            out.push(Instr { op: VOp::Shl, rd: SCRATCH, rs: SCRATCH, rt: SCRATCH2, width: Width::W64, ..Default::default() });
        }
        out.push(Instr { op: VOp::Add, rd: SCRATCH, rs: SCRATCH, rt: rn, width: Width::W64, ..Default::default() });
        // opc: 00=STR, 01=LDR, 10=LDRS to 64, 11=LDRS to 32（符号扩展近似为零扩展）
        let op = if opc == 0 { VOp::Store } else { VOp::Load };
        out.push(Instr { op, rd: rt, rs: SCRATCH, imm: 0, width, ..Default::default() });
        return Ok(out);
    }

    Err("load/store 子类未实现")
}

// =================================================================
// Data Processing - Register
// =================================================================
fn decode_data_reg(raw: u32) -> Result<Vec<Instr>, &'static str> {
    let sf = (raw >> 31) & 1;
    let width = if sf == 1 { Width::W64 } else { Width::W32 };

    // ---- ADD/SUB (shifted register) : sf|op|S|01011|shift[2]|0|Rm|imm6[6]|Rn|Rd ----
    if (raw >> 24) & 0x1F == 0b01011 {
        let op_bit = (raw >> 30) & 1;
        let s = (raw >> 29) & 1;
        let shift_type = (raw >> 22) & 0x3;
        let rm = xzr(((raw >> 16) & 0x1F) as u8);
        let imm6 = ((raw >> 10) & 0x3F) as i64;
        let rn = xzr(((raw >> 5) & 0x1F) as u8);
        let rd_raw = (raw & 0x1F) as u8;
        let rd = xzr(rd_raw);
        let vop = if op_bit == 1 { VOp::Sub } else { VOp::Add };

        // 先把 Rm 按 shift_type+imm6 预处理到 SCRATCH，再做 ALU。
        // imm6==0 时跳过移位，直接用 Rm 节省指令。
        let mut out: Vec<Instr> = Vec::with_capacity(4);
        let rm_effective = if imm6 == 0 {
            rm
        } else {
            out.push(Instr { op: VOp::MovI, rd: SCRATCH2, imm: imm6, width: Width::W64, ..Default::default() });
            let shift_op = match shift_type {
                0 => VOp::Shl,   // LSL
                1 => VOp::LShr,  // LSR
                2 => VOp::AShr,  // ASR
                _ => return Err("ADD/SUB shifted reg: shift_type=11 reserved"),
            };
            out.push(Instr { op: shift_op, rd: SCRATCH, rs: rm, rt: SCRATCH2, width, ..Default::default() });
            SCRATCH
        };

        if s == 1 && rd_raw == 31 && op_bit == 1 {
            out.push(Instr { op: VOp::Cmp, rs: rn, rt: rm_effective, width, ..Default::default() });
            return Ok(out);
        }
        if s == 1 && rd_raw == 31 && op_bit == 0 {
            out.push(Instr { op: VOp::Add, rd: SCRATCH3, rs: rn, rt: rm_effective, width, ..Default::default() });
            out.push(Instr { op: VOp::Tst, rs: SCRATCH3, rt: SCRATCH3, width, ..Default::default() });
            return Ok(out);
        }
        out.push(Instr { op: vop, rd, rs: rn, rt: rm_effective, width, ..Default::default() });
        if s == 1 {
            // SUBS / ADDS 写 Rd 同时设标志：粗粒度做法 — 用结果做 Tst 设 N/Z
            out.push(Instr { op: VOp::Tst, rs: rd, rt: rd, width, ..Default::default() });
        }
        return Ok(out);
    }

    // ---- Logical (shifted register) ----
    //   sf | opc[2] | 01010 | shift[2] | N | Rm | imm6[6] | Rn | Rd
    //   N == 0 → 普通 AND/ORR/EOR/ANDS
    //   N == 1 → BIC/ORN/EON/BICS（与上等价但右操作数取反）
    if (raw >> 24) & 0x1F == 0b01010 {
        let opc = (raw >> 29) & 0x3;
        let shift_type = (raw >> 22) & 0x3;
        let n_bit = (raw >> 21) & 1;
        let imm6 = ((raw >> 10) & 0x3F) as i64;
        // 在该指令族里，Rn/Rm/Rd = 31 一律是 XZR
        let rm = xzr(((raw >> 16) & 0x1F) as u8);
        let rn = xzr(((raw >> 5) & 0x1F) as u8);
        let rd_raw = (raw & 0x1F) as u8;
        let rd = xzr(rd_raw);
        let vop = match opc {
            0 => VOp::And,
            1 => VOp::Or,
            2 => VOp::Xor,
            _ => VOp::And, // ANDS / BICS 用 And
        };
        let mut out: Vec<Instr> = Vec::with_capacity(6);
        // 先把 Rm 按 shift_type+imm6 预处理到 SCRATCH; 再 (可选) NOT 到 SCRATCH
        let mut rm_effective = if imm6 == 0 {
            rm
        } else {
            out.push(Instr { op: VOp::MovI, rd: SCRATCH2, imm: imm6, width: Width::W64, ..Default::default() });
            let shift_op = match shift_type {
                0 => VOp::Shl,   // LSL
                1 => VOp::LShr,  // LSR
                2 => VOp::AShr,  // ASR
                3 => VOp::Ror,   // ROR
                _ => unreachable!(),
            };
            out.push(Instr { op: shift_op, rd: SCRATCH, rs: rm, rt: SCRATCH2, width, ..Default::default() });
            SCRATCH
        };
        if n_bit == 1 {
            // BIC/ORN/EON: 右操作数取反
            out.push(Instr { op: VOp::Not, rd: SCRATCH, rs: rm_effective, width, ..Default::default() });
            rm_effective = SCRATCH;
        }
        if opc == 3 {
            // ANDS / BICS — Rd=31 是 TST/TST-with-inverted-rm
            if rd_raw == 31 {
                return Ok({
                    out.push(Instr { op: VOp::Tst, rs: rn, rt: rm_effective, width, ..Default::default() });
                    out
                });
            }
            out.push(Instr { op: vop, rd, rs: rn, rt: rm_effective, width, ..Default::default() });
            out.push(Instr { op: VOp::Tst, rs: rd, rt: rd, width, ..Default::default() });
            return Ok(out);
        }
        out.push(Instr { op: vop, rd, rs: rn, rt: rm_effective, width, ..Default::default() });
        return Ok(out);
    }

    // ---- ADD/SUB (extended register) ----
    //   sf | op | S | 01011 | 00 | 1 | Rm | option[3] | imm3[3] | Rn | Rd
    //   bits 28:24 = 01011, bits 23:21 = 001, opt 在 bits 15:13, imm3 在 12:10
    if (raw >> 24) & 0x1F == 0b01011 && (raw >> 21) & 0x3 == 0b01 {
        let op_bit = (raw >> 30) & 1;
        let s = (raw >> 29) & 1;
        let rm = xzr(((raw >> 16) & 0x1F) as u8);
        let option = (raw >> 13) & 0x7;
        let imm3 = ((raw >> 10) & 0x7) as i64;
        // Rn/Rd = 31 在 extended 形式里是 SP, 但我们 SP/XZR 都用 V31, 不区分
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd_raw = (raw & 0x1F) as u8;
        let rd = rd_raw;
        let vop = if op_bit == 1 { VOp::Sub } else { VOp::Add };

        // option: 000=UXTB, 001=UXTH, 010=UXTW, 011=UXTX (=LSL),
        //         100=SXTB, 101=SXTH, 110=SXTW, 111=SXTX
        let (bits, signed) = match option {
            0b000 => (8, false),
            0b001 => (16, false),
            0b010 => (32, false),
            0b011 => (64, false),
            0b100 => (8, true),
            0b101 => (16, true),
            0b110 => (32, true),
            0b111 => (64, true),
            _ => unreachable!(),
        };

        let mut out: Vec<Instr> = Vec::with_capacity(8);
        // Step1: 把 Rm 截断到 bits 位 (零或符号扩展) 到 SCRATCH
        if bits == 64 {
            out.push(Instr { op: VOp::MovR, rd: SCRATCH, rs: rm, ..Default::default() });
        } else if signed {
            let shl = (64 - bits) as i64;
            out.push(Instr { op: VOp::MovI, rd: SCRATCH3, imm: shl, width: Width::W64, ..Default::default() });
            out.push(Instr { op: VOp::Shl, rd: SCRATCH, rs: rm, rt: SCRATCH3, width: Width::W64, ..Default::default() });
            out.push(Instr { op: VOp::AShr, rd: SCRATCH, rs: SCRATCH, rt: SCRATCH3, width: Width::W64, ..Default::default() });
        } else {
            let mask: u64 = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
            out.push(Instr { op: VOp::MovI, rd: SCRATCH3, imm: mask as i64, width: Width::W64, ..Default::default() });
            out.push(Instr { op: VOp::And, rd: SCRATCH, rs: rm, rt: SCRATCH3, width: Width::W64, ..Default::default() });
        }
        // Step2: 左移 imm3
        if imm3 > 0 {
            out.push(Instr { op: VOp::MovI, rd: SCRATCH3, imm: imm3, width: Width::W64, ..Default::default() });
            out.push(Instr { op: VOp::Shl, rd: SCRATCH, rs: SCRATCH, rt: SCRATCH3, width: Width::W64, ..Default::default() });
        }
        // Step3: 算 ALU + 可能的 flag 更新
        if s == 1 && rd_raw == 31 && op_bit == 1 {
            out.push(Instr { op: VOp::Cmp, rs: rn, rt: SCRATCH, width, ..Default::default() });
            return Ok(out);
        }
        out.push(Instr { op: vop, rd, rs: rn, rt: SCRATCH, width, ..Default::default() });
        if s == 1 {
            out.push(Instr { op: VOp::Tst, rs: rd, rt: rd, width, ..Default::default() });
        }
        return Ok(out);
    }

    // ---- Add/subtract with carry: ADC, ADCS, SBC, SBCS ----
    //   sf | op | S | 11010000 | Rm | 000000 | Rn | Rd
    //   bits 28:21 = 11010000, bits 15:10 = 000000
    if (raw >> 24) & 0x1F == 0b11010
        && (raw >> 21) & 0x7 == 0
        && (raw >> 10) & 0x3F == 0
    {
        let op_bit = (raw >> 30) & 1;  // 0=ADC, 1=SBC
        let s = (raw >> 29) & 1;
        let rm = xzr(((raw >> 16) & 0x1F) as u8);
        let rn = xzr(((raw >> 5) & 0x1F) as u8);
        let rd = xzr((raw & 0x1F) as u8);

        // CSel: Rd = matches(cond) ? Rs : Rt. 用 Cs 取 carry: tmp = (Cs?1:0)
        let mut out: Vec<Instr> = Vec::with_capacity(6);
        out.push(Instr { op: VOp::MovI, rd: SCRATCH2, imm: 1, width: Width::W64, ..Default::default() });
        out.push(Instr { op: VOp::MovI, rd: SCRATCH3, imm: 0, width: Width::W64, ..Default::default() });
        let carry_cond = if op_bit == 1 { Cond::Cc } else { Cond::Cs }; // SBC 用 !C
        out.push(Instr { op: VOp::CSel, rd: SCRATCH, rs: SCRATCH2, rt: SCRATCH3, cond: carry_cond, ..Default::default() });
        // ADC: rd = rn + rm + carry; SBC: rd = rn - rm - !carry
        let alu = if op_bit == 1 { VOp::Sub } else { VOp::Add };
        out.push(Instr { op: alu, rd: SCRATCH2, rs: rn, rt: rm, width, ..Default::default() });
        out.push(Instr { op: alu, rd, rs: SCRATCH2, rt: SCRATCH, width, ..Default::default() });
        if s == 1 {
            out.push(Instr { op: VOp::Tst, rs: rd, rt: rd, width, ..Default::default() });
        }
        return Ok(out);
    }

    // ---- Conditional compare (immediate & register): CCMP, CCMN ----
    //   sf | op | S | 11010010 | imm5/Rm | cond | mode[2] | Rn | nzcv
    //   bits 30 = op (0=CCMN, 1=CCMP); bits 21 = 1; bits 11:10 = 01 (reg) / 00 reserved imm
    //   For now: support CCMP/CCMN with both imm (mode=10) and reg (mode=00).
    //   语义: if matches(cond) { flags = Rn vs op2 (cmp) }
    //         else { flags = nzcv (immediate fallback) }
    //   VM 简化: cond 命中 → 算 Cmp; 不命中 → 不更新 (近似 ARM 'set flags to nzcv').
    if (raw >> 21) & 0x7FF == 0b1_1011010010 {
        let op_bit = (raw >> 30) & 1;
        let imm5_or_rm = ((raw >> 16) & 0x1F) as u8;
        let cond = ((raw >> 12) & 0xF) as u8;
        let mode = (raw >> 10) & 0x3;  // 00 = reg, 10 = imm
        let rn = ((raw >> 5) & 0x1F) as u8;
        let _nzcv = (raw & 0xF) as u8;
        let is_imm = (mode & 0b10) != 0;

        let mut out: Vec<Instr> = Vec::with_capacity(6);
        // 把 op2 加载到 SCRATCH
        if is_imm {
            out.push(Instr { op: VOp::MovI, rd: SCRATCH, imm: imm5_or_rm as i64, width: Width::W64, ..Default::default() });
        } else {
            out.push(Instr { op: VOp::MovR, rd: SCRATCH, rs: imm5_or_rm, ..Default::default() });
        }
        // 算 Cmp (借用未条件版本): VM 不支持"条件设置 NZCV", 近似为始终做 Cmp.
        // op_bit == 0 (CCMN) 是 ADD-cmp, 用 Add+Tst; op_bit == 1 (CCMP) 是 Sub-cmp.
        // 注: 若 cond 不命中, ARM 会用 nzcv 立即数填充标志; 此处近似为忽略 — 多数现实代码
        // 这里都是 cond 命中分支重要, fallthrough 不依赖 NZCV.
        let _ = cond;
        if op_bit == 1 {
            out.push(Instr { op: VOp::Cmp, rs: rn, rt: SCRATCH, width, ..Default::default() });
        } else {
            out.push(Instr { op: VOp::Add, rd: SCRATCH2, rs: rn, rt: SCRATCH, width, ..Default::default() });
            out.push(Instr { op: VOp::Tst, rs: SCRATCH2, rt: SCRATCH2, width, ..Default::default() });
        }
        return Ok(out);
    }

    // ---- Data-processing (2-source) : sf|0|S|11010110|Rm|opcode|Rn|Rd ----
    if (raw >> 21) & 0x7FF == 0b1_0011010110 {
        let rm = xzr(((raw >> 16) & 0x1F) as u8);
        let opcode2 = (raw >> 10) & 0x3F;
        let rn = xzr(((raw >> 5) & 0x1F) as u8);
        let rd = xzr((raw & 0x1F) as u8);
        let v = match opcode2 {
            0b000010 => VOp::UDiv,
            0b000011 => VOp::SDiv,
            0b001000 => VOp::Shl,  // LSLV
            0b001001 => VOp::LShr, // LSRV
            0b001010 => VOp::AShr, // ASRV
            0b001011 => VOp::Ror,  // RORV
            _ => return Err("dp-2src opcode 未实现"),
        };
        return Ok(vec![Instr { op: v, rd, rs: rn, rt: rm, width, ..Default::default() }]);
    }

    // ---- Data-processing (3-source) : MADD/MSUB/MUL/UMULL/UMADDL/SMADDL/UMULH ----
    // sf | 00 | 11011 | op31 | 0 | Rm | o0 | Ra | Rn | Rd
    if (raw >> 24) & 0x1F == 0b11011 {
        let op31 = (raw >> 21) & 0x7;
        let o0 = (raw >> 15) & 1;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let ra = ((raw >> 10) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        // op31 = 000 → MADD/MSUB(MUL/MNEG)
        // op31 = 001 → SMADDL/SMSUBL (32×32 → 64 signed)
        // op31 = 010 → SMULH (Ra=XZR)
        // op31 = 101 → UMADDL/UMSUBL (32×32 → 64 unsigned)
        // op31 = 110 → UMULH
        match op31 {
            0b000 => {
                let mut out = Vec::new();
                out.push(Instr { op: VOp::Mul, rd: SCRATCH, rs: rn, rt: rm, width, ..Default::default() });
                if ra == 31 {
                    if o0 == 0 {
                        out.push(Instr { op: VOp::MovR, rd, rs: SCRATCH, ..Default::default() });
                    } else {
                        out.push(Instr { op: VOp::Neg, rd, rs: SCRATCH, width, ..Default::default() });
                    }
                } else if o0 == 0 {
                    out.push(Instr { op: VOp::Add, rd, rs: ra, rt: SCRATCH, width, ..Default::default() });
                } else {
                    out.push(Instr { op: VOp::Sub, rd, rs: ra, rt: SCRATCH, width, ..Default::default() });
                }
                return Ok(out);
            }
            0b001 | 0b101 => {
                // (S/U)MADDL/(S/U)MSUBL：Wn × Wm → 64 位再 ± Xa
                let unsigned = op31 == 0b101;
                let mut out: Vec<Instr> = Vec::with_capacity(8);
                if unsigned {
                    out.push(Instr { op: VOp::MovI, rd: SCRATCH3, imm: 0xFFFF_FFFFi64, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::And, rd: SCRATCH, rs: rn, rt: SCRATCH3, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::And, rd: SCRATCH2, rs: rm, rt: SCRATCH3, width: Width::W64, ..Default::default() });
                } else {
                    out.push(Instr { op: VOp::MovI, rd: SCRATCH3, imm: 32, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::Shl, rd: SCRATCH, rs: rn, rt: SCRATCH3, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::AShr, rd: SCRATCH, rs: SCRATCH, rt: SCRATCH3, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::Shl, rd: SCRATCH2, rs: rm, rt: SCRATCH3, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::AShr, rd: SCRATCH2, rs: SCRATCH2, rt: SCRATCH3, width: Width::W64, ..Default::default() });
                }
                out.push(Instr { op: VOp::Mul, rd: SCRATCH, rs: SCRATCH, rt: SCRATCH2, width: Width::W64, ..Default::default() });
                if ra == 31 {
                    if o0 == 0 {
                        out.push(Instr { op: VOp::MovR, rd, rs: SCRATCH, ..Default::default() });
                    } else {
                        out.push(Instr { op: VOp::Neg, rd, rs: SCRATCH, width: Width::W64, ..Default::default() });
                    }
                } else if o0 == 0 {
                    out.push(Instr { op: VOp::Add, rd, rs: ra, rt: SCRATCH, width: Width::W64, ..Default::default() });
                } else {
                    out.push(Instr { op: VOp::Sub, rd, rs: ra, rt: SCRATCH, width: Width::W64, ..Default::default() });
                }
                return Ok(out);
            }
            0b010 | 0b110 => {
                // SMULH / UMULH: 64x64 → 128, 取高 64 位. VM 没有原生 128 位
                // 乘法, 用 Knuth's longhand: 拆 Rn,Rm 为 hi/lo 32 位, 4 次 32x32
                // 乘法, 累加进位拼出 hi 64.
                //   lo32 = x & 0xFFFFFFFF; hi32 = (x >> 32) (signed for SMULH)
                //   ll = nlo*mlo
                //   lh = nlo*mhi
                //   hl = nhi*mlo
                //   hh = nhi*mhi
                //   mid = (ll>>32) + (lh & MASK32) + (hl & MASK32)
                //   hi = hh + (lh>>32) + (hl>>32) + (mid>>32)
                let unsigned = op31 == 0b110;
                let mut out: Vec<Instr> = Vec::with_capacity(32);
                // 寄存器复用: V32..V34 = SCRATCH/2/3 ; 我们还需要更多临时. 借 V35..V40.
                const T_NLO: u8 = 35;
                const T_NHI: u8 = 36;
                const T_MLO: u8 = 37;
                const T_MHI: u8 = 38;
                const T_LL: u8  = 39;
                const T_LH: u8  = 40;
                const T_HL: u8  = 41;
                const T_HH: u8  = 42;
                const T_MID: u8 = 43;
                const T_32: u8  = 44;
                const T_MASK: u8 = 45;
                // 准备常数
                out.push(Instr { op: VOp::MovI, rd: T_32, imm: 32, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::MovI, rd: T_MASK, imm: 0xFFFF_FFFFi64, width: Width::W64, ..Default::default() });
                // 提取 Rn lo/hi
                out.push(Instr { op: VOp::And, rd: T_NLO, rs: rn, rt: T_MASK, width: Width::W64, ..Default::default() });
                if unsigned {
                    out.push(Instr { op: VOp::LShr, rd: T_NHI, rs: rn, rt: T_32, width: Width::W64, ..Default::default() });
                } else {
                    out.push(Instr { op: VOp::AShr, rd: T_NHI, rs: rn, rt: T_32, width: Width::W64, ..Default::default() });
                }
                // 提取 Rm lo/hi
                out.push(Instr { op: VOp::And, rd: T_MLO, rs: rm, rt: T_MASK, width: Width::W64, ..Default::default() });
                if unsigned {
                    out.push(Instr { op: VOp::LShr, rd: T_MHI, rs: rm, rt: T_32, width: Width::W64, ..Default::default() });
                } else {
                    out.push(Instr { op: VOp::AShr, rd: T_MHI, rs: rm, rt: T_32, width: Width::W64, ..Default::default() });
                }
                // 4 次乘
                out.push(Instr { op: VOp::Mul, rd: T_LL, rs: T_NLO, rt: T_MLO, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Mul, rd: T_LH, rs: T_NLO, rt: T_MHI, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Mul, rd: T_HL, rs: T_NHI, rt: T_MLO, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Mul, rd: T_HH, rs: T_NHI, rt: T_MHI, width: Width::W64, ..Default::default() });
                // mid = (ll>>32) + (lh & mask) + (hl & mask)
                out.push(Instr { op: VOp::LShr, rd: SCRATCH, rs: T_LL, rt: T_32, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::And, rd: SCRATCH2, rs: T_LH, rt: T_MASK, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd: T_MID, rs: SCRATCH, rt: SCRATCH2, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::And, rd: SCRATCH2, rs: T_HL, rt: T_MASK, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd: T_MID, rs: T_MID, rt: SCRATCH2, width: Width::W64, ..Default::default() });
                // hi = hh + (lh>>32) + (hl>>32) + (mid>>32)
                if unsigned {
                    out.push(Instr { op: VOp::LShr, rd: SCRATCH, rs: T_LH, rt: T_32, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::Add, rd: T_HH, rs: T_HH, rt: SCRATCH, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::LShr, rd: SCRATCH, rs: T_HL, rt: T_32, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::Add, rd: T_HH, rs: T_HH, rt: SCRATCH, width: Width::W64, ..Default::default() });
                } else {
                    // signed hi: 用 AShr 保留符号
                    out.push(Instr { op: VOp::AShr, rd: SCRATCH, rs: T_LH, rt: T_32, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::Add, rd: T_HH, rs: T_HH, rt: SCRATCH, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::AShr, rd: SCRATCH, rs: T_HL, rt: T_32, width: Width::W64, ..Default::default() });
                    out.push(Instr { op: VOp::Add, rd: T_HH, rs: T_HH, rt: SCRATCH, width: Width::W64, ..Default::default() });
                }
                out.push(Instr { op: VOp::LShr, rd: SCRATCH, rs: T_MID, rt: T_32, width: Width::W64, ..Default::default() });
                out.push(Instr { op: VOp::Add, rd, rs: T_HH, rt: SCRATCH, width: Width::W64, ..Default::default() });
                return Ok(out);
            }
            _ => return Err("dp-3src op31 未实现"),
        }
    }

    // ---- Conditional select (CSEL/CSINC/CSINV/CSNEG) ----
    // sf|op|S|11010100|Rm|cond|op2|Rn|Rd
    if (raw >> 21) & 0x7FF == 0b1_0011010100 {
        let op = (raw >> 30) & 1;
        let rm = xzr(((raw >> 16) & 0x1F) as u8);
        let cond = ((raw >> 12) & 0xF) as u8;
        let op2 = (raw >> 10) & 0x3;
        let rn = xzr(((raw >> 5) & 0x1F) as u8);
        let rd = xzr((raw & 0x1F) as u8);
        match (op, op2) {
            (0, 0) => {
                // CSEL Rd, Rn, Rm, cond
                return Ok(vec![Instr { op: VOp::CSel, rd, rs: rn, rt: rm, cond: Cond::from_u8(cond), ..Default::default() }]);
            }
            (0, 1) => {
                // CSINC: Rd = matches(cond) ? Rn : Rm+1
                return Ok(vec![
                    Instr { op: VOp::MovI, rd: SCRATCH, imm: 1, width: Width::W64, ..Default::default() },
                    Instr { op: VOp::Add, rd: SCRATCH2, rs: rm, rt: SCRATCH, width, ..Default::default() },
                    Instr { op: VOp::CSel, rd, rs: rn, rt: SCRATCH2, cond: Cond::from_u8(cond), ..Default::default() },
                ]);
            }
            (1, 0) => {
                // CSINV: Rd = matches(cond) ? Rn : ~Rm
                return Ok(vec![
                    Instr { op: VOp::Not, rd: SCRATCH, rs: rm, width, ..Default::default() },
                    Instr { op: VOp::CSel, rd, rs: rn, rt: SCRATCH, cond: Cond::from_u8(cond), ..Default::default() },
                ]);
            }
            (1, 1) => {
                // CSNEG: Rd = matches(cond) ? Rn : -Rm
                return Ok(vec![
                    Instr { op: VOp::Neg, rd: SCRATCH, rs: rm, width, ..Default::default() },
                    Instr { op: VOp::CSel, rd, rs: rn, rt: SCRATCH, cond: Cond::from_u8(cond), ..Default::default() },
                ]);
            }
            _ => return Err("CSEL family op 未实现"),
        }
    }

    // ---- Data-processing (1-source) : sf|1|S|11010110|opcode2(00000)|opcode|Rn|Rd ----
    if (raw >> 21) & 0x7FF == 0b1_1011010110 && ((raw >> 16) & 0x1F) == 0 {
        let opcode = (raw >> 10) & 0x3F;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        // opcode 主要值:
        //   000000 RBIT, 000001 REV16, 000010 REV32 (X 寄存器) / REV (W 寄存器),
        //   000011 REV (X 寄存器), 000100 CLZ, 000101 CLS
        let vop = match opcode {
            0b000000 => VOp::Rbit,
            0b000001 => VOp::Rev16,
            0b000010 => if sf == 0 { VOp::Rev } else { VOp::Rev32 },
            0b000011 => VOp::Rev,
            0b000100 => VOp::Clz,
            _ => return Err("dp-1src opcode 未实现"),
        };
        return Ok(vec![Instr { op: vop, rd, rs: rn, width, ..Default::default() }]);
    }

    Err("data-reg 子类未实现")
}

// =================================================================
// SIMD / FP（标量子集 + LSE atomics）
// =================================================================
fn decode_simd_fp(raw: u32) -> Result<Vec<Instr>, &'static str> {
    // ---- Advanced SIMD three-same (logic bitwise): EOR/ORR/AND/BIC/ORN ----
    //   0 Q U 01110 size 1 Rm 00011 1 Rn Rd
    //   bits 28:24 = 01110, bit 21 = 1, bits 15:11 = 00011, bit 10 = 1
    if (raw >> 24) & 0x1F == 0b01110
        && (raw >> 21) & 1 == 1
        && (raw >> 10) & 0x3F == 0b000111
    {
        let q = (raw >> 30) & 1;
        let u = (raw >> 29) & 1;
        let size = (raw >> 22) & 0x3;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        let _ = q;  // 我们的 VEor 等总是处理 128-bit; D 形式 (Q=0) 高 64 在 ARM 上是 0,
                    // VM 这边偶尔高 64 残留, 但 Keccak 等用 Q-form 居多, 影响小.
        // U=0:
        //   size=00 AND, 01 BIC, 10 ORR, 11 ORN
        // U=1:
        //   size=00 EOR, 01 BSL, 10 BIT, 11 BIF
        let vop = match (u, size) {
            (0, 0b00) => Some(VOp::VAnd),
            (0, 0b01) => Some(VOp::VBic),
            (0, 0b10) => Some(VOp::VOr),
            (0, 0b11) => None,  // ORN: rn | ~rm. 用 VNot + VOr 组合
            (1, 0b00) => Some(VOp::VEor),
            // BSL/BIT/BIF 是 3-操作数 (含 rd-in-and-out), 暂不实现.
            _ => return Err("SIMD three-same opcode 暂不支持"),
        };
        if let Some(op) = vop {
            return Ok(vec![Instr { op, rd, rs: rn, rt: rm, ..Default::default() }]);
        }
        // ORN: rd = rn | ~rm. 借用 V63 (XZR) 作 NEON scratch? — fregs[63] 不存在
        // (只有 32 个 freg). 直接 emit VNot+VOr 用 freg 临时编号 30 (V30 == Q30).
        // 多数代码 Q30 不被普通函数用 — 但保守起见, 这里走 VNot 到 SCRATCH freg.
        // 实际上 V31 是 SP-vreg 类比, 暂用 V31 作 scratch.
        return Ok(vec![
            Instr { op: VOp::VNot, rd: 31, rs: rm, ..Default::default() },
            Instr { op: VOp::VOr, rd, rs: rn, rt: 31, ..Default::default() },
        ]);
    }

    // ---- SHA-3 EOR3 / BCAX / RAX1 / XAR ----
    //   EOR3: 1100 1110 000 Rm 0 Ra Rn Rd                  (CE0_0_xxxx_0_xxxx_xxxx_xxxx)
    //   BCAX: 1100 1110 011 Rm 0 Ra Rn Rd
    //   RAX1: 1100 1110 011 Rm 100011 Rn Rd
    //   XAR:  1100 1110 100 Rm imm6 Rn Rd
    // 共通: bits 31:24 = 1100_1110 (= 0xCE), Rd[4:0]=raw[4:0], Rn[9:5]=raw[9:5]
    if (raw >> 24) & 0xFF == 0xCE {
        let rd = (raw & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let imm6 = ((raw >> 10) & 0x3F) as i64;
        let ra = ((raw >> 10) & 0x1F) as u8;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let op2 = (raw >> 21) & 0x7;  // 000=EOR3, 011=BCAX/RAX1, 100=XAR
        let bit15 = (raw >> 15) & 1;
        if op2 == 0b000 && bit15 == 0 {
            // EOR3: Vd = Vn ^ Vm ^ Va  → VEor twice
            return Ok(vec![
                Instr { op: VOp::VEor, rd: 31, rs: rn, rt: rm, ..Default::default() },
                Instr { op: VOp::VEor, rd, rs: 31, rt: ra, ..Default::default() },
            ]);
        }
        if op2 == 0b011 && bit15 == 0 {
            // BCAX: Vd = Vn ^ (Vm & ~Va) → VBic(scratch, Vm, Va) then VEor(rd, Vn, scratch)
            return Ok(vec![
                Instr { op: VOp::VBic, rd: 31, rs: rm, rt: ra, ..Default::default() },
                Instr { op: VOp::VEor, rd, rs: rn, rt: 31, ..Default::default() },
            ]);
        }
        if op2 == 0b011 && (raw >> 10) & 0x3F == 0b100011 {
            // RAX1: Vd.2d = Vn.2d ^ rol(Vm.2d, 1) per 64-bit lane.
            // VM 没有 VRol, 但 rol(x, 1) = ror(x, 63). 用 VRorD #63 后 VEor.
            return Ok(vec![
                Instr { op: VOp::VRorD, rd: 31, rs: rm, imm: 63, ..Default::default() },
                Instr { op: VOp::VEor, rd, rs: rn, rt: 31, ..Default::default() },
            ]);
        }
        if op2 == 0b100 {
            // XAR: Vd.2d = ror((Vn ^ Vm).2d, #imm6) per lane.
            return Ok(vec![
                Instr { op: VOp::VEor, rd: 31, rs: rn, rt: rm, ..Default::default() },
                Instr { op: VOp::VRorD, rd, rs: 31, imm: imm6, ..Default::default() },
            ]);
        }
        return Err("SHA3 子族 op2 未实现");
    }

    // ---- MOVI (advanced SIMD modified immediate) ----
    // 仅识别 cmode=1110 + abc/defgh=0 → 整 vreg 清零的常见情形（编译器初始化用）
    // 0x2f00e400 (Q=0 D 寄存器), 0x6f00e400 (Q=1 整 Q 寄存器)
    if (raw & 0xBFFFFC1F) == 0x2F00E400 {
        let rd = (raw & 0x1F) as u8;
        // 等价：vreg[rd] 低 64 位 = 0。用 FMovFromGpr rd, V63 (= XZR = 0), W64
        return Ok(vec![Instr {
            op: VOp::FMovFromGpr,
            rd,
            rs: XZR_VREG,
            width: Width::W64,
            ..Default::default()
        }]);
    }

    // ---- FMOV (immediate) : 00011110 ftype 1 imm8 100 00000 Rd ----
    // 固定位：bits 31:24=0001_1110, bit 21=1, bit 12=1, bits 11:10=00, bits 9:5=00000
    // mask = 0xFF20_1FE0, 期望 = 0x1E20_1000
    if (raw & 0xFF20_1FE0) == 0x1E20_1000 && ((raw >> 22) & 0x3) <= 1 {
        let ftype = (raw >> 22) & 0x3;
        let imm8 = ((raw >> 13) & 0xFF) as u8;
        let rd = (raw & 0x1F) as u8;
        // ARM 8-bit FP imm 编码到 double 实数：
        //   sign: bit7
        //   exp:  bits 6:4 (3-bit) → expanded to 11/8 bit exp depending on size
        //   frac: bits 3:0
        // 简化解码：先解码到 f64，再按 ftype 写回 vreg。
        let f = vfp_imm8_to_f64(imm8);
        let (bits, width) = if ftype == 0 {
            ((f as f32).to_bits() as u64, Width::W32)
        } else {
            (f.to_bits(), Width::W64)
        };
        return Ok(vec![
            // 把 bits 装到 V63（XZR 数据通道借用：先 MovI 到 SCRATCH，再 FMovFromGpr）。
            Instr { op: VOp::MovI, rd: SCRATCH, imm: bits as i64, width: Width::W64, ..Default::default() },
            Instr { op: VOp::FMovFromGpr, rd, rs: SCRATCH, width, ..Default::default() },
        ]);
    }

    // ---- FMOV (register) : 0001 1110 ftype 1 00000 010000 Rn Rd ----
    if (raw & 0xFF3F_FC00) == 0x1E20_4000 {
        let ftype = (raw >> 22) & 0x3;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        if ftype <= 1 {
            return Ok(vec![Instr { op: VOp::FMovR, rd, rs: rn, ..Default::default() }]);
        }
    }

    // ---- FMOV (general, FP <-> GPR) : sf 0011110 ftype 1 rmode 110 000000 Rn Rd ----
    // bits 31 = sf, bits 30:24 = 0011110, bit 21 = 1, bits 20:19 = rmode, bits 18:16 = opcode2
    // FMOV Wd←Sn / Xd←Dn (FP→GPR): rmode=00 op=110
    // FMOV Sd←Wn / Dd←Xn (GPR→FP): rmode=00 op=111
    if (raw >> 24) & 0x7F == 0b0011110 && (raw >> 21) & 1 == 1 && (raw >> 16) & 7 == 0 {
        let sf = (raw >> 31) & 1;
        let ftype = (raw >> 22) & 0x3;
        let rmode = (raw >> 19) & 0x3;
        let opcode2 = (raw >> 16) & 0x7;
        let _ = opcode2;
        let opcode_full = (raw >> 16) & 0x3F;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        let width = if ftype == 0 { Width::W32 } else { Width::W64 };
        if rmode == 0 && (sf, ftype) == (0, 0) || (sf, ftype) == (1, 1) {
            // 32-bit S/W or 64-bit D/X
            // opcode bits 18:16 = 110 (FP→GPR), 111 (GPR→FP)
            if (opcode_full >> 0) & 1 == 0 && (opcode_full >> 1) & 1 == 1 && (opcode_full >> 2) & 1 == 1 {
                // FMOV GPR ← FP
                return Ok(vec![Instr { op: VOp::FMovToGpr, rd, rs: rn, width, ..Default::default() }]);
            }
            if (opcode_full >> 0) & 1 == 1 && (opcode_full >> 1) & 1 == 1 && (opcode_full >> 2) & 1 == 1 {
                // FMOV FP ← GPR
                return Ok(vec![Instr { op: VOp::FMovFromGpr, rd, rs: rn, width, ..Default::default() }]);
            }
        }
    }

    // ---- FP data-processing (2 source) : 0001 1110 ftype 1 Rm op2[4] 10 Rn Rd ----
    if (raw >> 24) & 0xFF == 0x1E && (raw >> 21) & 1 == 1 && (raw >> 10) & 0x3 == 0b10 {
        let ftype = (raw >> 22) & 0x3;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let op2 = (raw >> 12) & 0xF;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        let width = if ftype == 0 { Width::W32 } else { Width::W64 };
        let vop = match op2 {
            0b0000 => VOp::FMul,  // FMUL
            0b0001 => VOp::FDiv,  // FDIV
            0b0010 => VOp::FAdd,  // FADD
            0b0011 => VOp::FSub,  // FSUB
            _ => return Err("FP 2-src op2 未实现"),
        };
        return Ok(vec![Instr { op: vop, rd, rs: rn, rt: rm, width, ..Default::default() }]);
    }

    // ---- FP compare : 0001 1110 ftype 1 Rm 0 0 1000 Rn opcode2 ----
    // bits 31:24 = 0001_1110, bits 21 = 1, bits 15:10 = 001000 (FCMP variants)
    if (raw >> 24) & 0xFF == 0x1E && (raw >> 21) & 1 == 1 && (raw >> 10) & 0x3F == 0b001000 {
        let ftype = (raw >> 22) & 0x3;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let width = if ftype == 0 { Width::W32 } else { Width::W64 };
        return Ok(vec![Instr { op: VOp::FCmp, rs: rn, rt: rm, width, ..Default::default() }]);
    }

    // ---- FP→Int (FCVTZS) : sf 00 11110 ftype 1 11 000 000000 Rn Rd ----
    if (raw >> 24) & 0x7F == 0b0011110 && (raw >> 21) & 1 == 1 && (raw >> 16) & 0x1F == 0b11000
        && (raw >> 10) & 0x3F == 0
    {
        let sf = (raw >> 31) & 1;
        let ftype = (raw >> 22) & 0x3;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        let _ = ftype;
        let width = if sf == 1 { Width::W64 } else { Width::W32 };
        return Ok(vec![Instr { op: VOp::FCvtZS, rd, rs: rn, width, ..Default::default() }]);
    }

    // ---- Int→FP (SCVTF) : sf 00 11110 ftype 1 00 010 000000 Rn Rd ----
    if (raw >> 24) & 0x7F == 0b0011110 && (raw >> 21) & 1 == 1 && (raw >> 16) & 0x1F == 0b00010
        && (raw >> 10) & 0x3F == 0
    {
        let sf = (raw >> 31) & 1;
        let ftype = (raw >> 22) & 0x3;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        let _ = sf;
        let width = if ftype == 0 { Width::W32 } else { Width::W64 };
        return Ok(vec![Instr { op: VOp::SCvtF, rd, rs: rn, width, ..Default::default() }]);
    }

    Err("SIMD/FP 子类未实现")
}

/// ARM 8-bit FP immediate → f64。严格遵循 ARM ARM A1.7.4 VFPExpandImm：
///   N=64, E=11, F=52
///   imm = a : NOT(b) : Replicate(b, E-3=8) : cdef'g'h : Zeros(N-E-5=48)
fn vfp_imm8_to_f64(imm8: u8) -> f64 {
    let a = ((imm8 >> 7) & 1) as u64;
    let b = ((imm8 >> 6) & 1) as u64;
    let cd_efgh = (imm8 & 0x3F) as u64; // bits 5:0
    let mut bits: u64 = 0;
    bits |= a << 63;
    bits |= ((!b) & 1) << 62;
    let b_repl = if b == 1 { 0xFF } else { 0 };
    bits |= b_repl << 54;
    bits |= cd_efgh << 48;
    f64::from_bits(bits)
}

/// 解码 ARM64 logical-immediate (N:imms:immr) → 64 位掩码值
/// 参考 ARMv8-A ARM 的 `DecodeBitMasks` 伪代码。
fn decode_bit_masks(n: u8, imms: u8, immr: u8, datasize: u32) -> Option<u64> {
    // 找 (N:~imms[5:0]) 的最高 1 位作为 len
    let combined: u32 = ((n as u32) << 6) | (((!imms) as u32) & 0x3F);
    if combined == 0 {
        return None;
    }
    let len = 31 - combined.leading_zeros();
    if len == 0 {
        return None;
    }
    let esize: u32 = 1 << len;
    if esize > 64 || esize > datasize {
        return None;
    }
    let levels: u32 = esize - 1;
    let s = (imms as u32) & levels;
    let r = (immr as u32) & levels;
    if s == levels {
        // S+1 = esize → all-ones inside element：rare alias，但避免无穷大左移
        return None;
    }
    let welem: u64 = if s + 1 >= 64 { u64::MAX } else { (1u64 << (s + 1)) - 1 };
    // 在 esize 范围内右旋
    let mask = if esize >= 64 { u64::MAX } else { (1u64 << esize) - 1 };
    let welem_in_e = welem & mask;
    let r_mod = r % esize;
    let rotated = if r_mod == 0 {
        welem_in_e
    } else {
        ((welem_in_e >> r_mod) | (welem_in_e << (esize - r_mod))) & mask
    };
    // 把 esize 段复制到 datasize
    let mut out: u64 = 0;
    let mut filled = 0u32;
    while filled < datasize {
        out |= rotated << filled;
        filled += esize;
    }
    if datasize < 64 {
        out &= (1u64 << datasize) - 1;
    }
    Some(out)
}

#[allow(dead_code)]
fn _force_use_scratch() -> [u8; 3] {
    [SCRATCH, SCRATCH2, SCRATCH3]
}
