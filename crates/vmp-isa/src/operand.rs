//! 操作数描述：寄存器编号、立即数、内存引用。
//!
//! 编码层不直接使用这里的结构；这是 IR 层 → 编码层的中间表示。

use crate::opcode::Width;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandKind {
    None,
    Reg,
    Imm,
    /// 用于条件分支等的额外 4-bit 字段
    Extra4,
}

#[derive(Debug, Clone, Copy)]
pub enum Operand {
    None,
    Reg(u8),
    Imm(i64),
    Extra(u8),
}

impl Operand {
    pub fn kind(&self) -> OperandKind {
        match self {
            Operand::None => OperandKind::None,
            Operand::Reg(_) => OperandKind::Reg,
            Operand::Imm(_) => OperandKind::Imm,
            Operand::Extra(_) => OperandKind::Extra4,
        }
    }

    pub fn as_reg(&self) -> Option<u8> {
        if let Operand::Reg(r) = self { Some(*r) } else { None }
    }
    pub fn as_imm(&self) -> Option<i64> {
        if let Operand::Imm(v) = self { Some(*v) } else { None }
    }
    pub fn as_extra(&self) -> Option<u8> {
        if let Operand::Extra(v) = self { Some(*v) } else { None }
    }
}

/// 部分 VOp 携带 width 信息（如 Load/Store/算术），统一放在指令编码的尾部 1 字节。
#[derive(Debug, Clone, Copy)]
pub struct WidthSlot(pub Width);
