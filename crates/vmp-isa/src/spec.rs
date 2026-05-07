//! 物理 ISA 规范。
//!
//! `IsaSpec` 把语义 [`VOp`] 映射到运行时使用的 1～N 字节物理 opcode。
//! 同一语义可有多份变体（多态 handler），由 codegen 随机选取。
//!
//! 同时还包含：
//! - 寄存器编号置换表（虚拟寄存器 ↔ 编码寄存器）
//! - 字节码 XOR / ROL 流加密 key 与 IV
//! - 跳转偏移 ROL bits

use crate::opcode::VOp;
use std::collections::HashMap;

/// 一个语义指令对应的物理变体。
#[derive(Debug, Clone, Copy)]
pub struct HandlerVariant {
    /// 物理 opcode 值（1 字节）
    pub opcode: u8,
    /// 该变体的额外 tweak（解释器在 dispatch 后异或/旋转结果以制造差异）
    pub tweak: u8,
}

#[derive(Debug, Clone)]
pub struct OpEncoding {
    pub variants: Vec<HandlerVariant>,
}

#[derive(Debug, Clone)]
pub struct IsaSpec {
    /// VOp -> 编码（含若干变体）
    pub op_table: HashMap<u16, OpEncoding>,
    /// 反查：opcode byte -> (VOp, tweak)
    pub op_reverse: [Option<(u16, u8)>; 256],
    /// 虚拟寄存器编号 -> 编码寄存器编号 (64 项；V0..V31 = 用户寄存器 / V32..V63 = lifter scratch)
    pub reg_perm: [u8; 64],
    pub reg_unperm: [u8; 64],
    /// 字节码 XOR 流密钥
    pub stream_key: [u8; 32],
    /// 立即数旋转位 (0..63)，用于 Imm 编码混淆
    pub imm_rol: u32,
    /// 跳转偏移 XOR mask
    pub branch_xor: u32,
    /// 用于流加密的 IV / nonce
    pub stream_iv: [u8; 16],
    /// 是否启用流加密
    pub encrypt: bool,
    /// 该 ISA 的指纹哈希（diagnostics 用）
    pub fingerprint: [u8; 8],
}

impl IsaSpec {
    /// 从语义 VOp 取一个随机变体（codegen 使用；解释器使用反查）
    pub fn pick_variant(&self, op: VOp, idx: usize) -> Option<HandlerVariant> {
        let enc = self.op_table.get(&(op as u16))?;
        let i = idx % enc.variants.len();
        Some(enc.variants[i])
    }

    pub fn opcode_for(&self, op: VOp) -> Option<u8> {
        self.op_table
            .get(&(op as u16))
            .and_then(|e| e.variants.first())
            .map(|v| v.opcode)
    }

    pub fn decode_opcode(&self, b: u8) -> Option<(VOp, u8)> {
        self.op_reverse[b as usize].and_then(|(v, t)| VOp::from_u16(v).map(|op| (op, t)))
    }

    pub fn enc_reg(&self, virt: u8) -> u8 {
        self.reg_perm[(virt as usize) & 63]
    }
    pub fn dec_reg(&self, phys: u8) -> u8 {
        self.reg_unperm[(phys as usize) & 63]
    }

    /// 立即数加密：左旋 + XOR 一个由 stream_key 派生的常量
    pub fn enc_imm(&self, v: u64) -> u64 {
        let key = u64::from_le_bytes(self.stream_key[0..8].try_into().unwrap());
        v.rotate_left(self.imm_rol) ^ key
    }
    pub fn dec_imm(&self, v: u64) -> u64 {
        let key = u64::from_le_bytes(self.stream_key[0..8].try_into().unwrap());
        (v ^ key).rotate_right(self.imm_rol)
    }

    pub fn enc_branch(&self, off: i32) -> i32 {
        (off ^ (self.branch_xor as i32)).rotate_left(3)
    }
    pub fn dec_branch(&self, v: i32) -> i32 {
        v.rotate_right(3) ^ (self.branch_xor as i32)
    }
}
