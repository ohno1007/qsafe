//! vmp-isa
//!
//! 虚拟机指令集定义。
//!
//! 设计要点：
//! - **语义指令** `VOp` 与 **物理编码** `IsaSpec` 解耦。
//!   语义指令保持稳定，物理编码每次构建按 `seed` 随机化：
//!     - opcode 编号随机
//!     - 寄存器编号置换
//!     - 立即数可选 XOR / ROL 混淆
//!     - 同一语义可有多个 handler 变体（多态 handler）
//! - 解释器构造时与 codegen 共享同一份 `IsaSpec`，因此运行时与编译期完全对称。
//! - `IsaSpec` 可以序列化嵌入到 stub 二进制中，stub 在运行时读取后还原解释器。

pub mod opcode;
pub mod operand;
pub mod spec;
pub mod encoding;
pub mod random;

pub use opcode::{Cond, VOp, Width, VOP_COUNT};
pub use operand::{Operand, OperandKind};
pub use spec::{HandlerVariant, IsaSpec, OpEncoding};
pub use encoding::{decode_instr, encode_instr, Instr, MAX_INSTR_LEN};
pub use random::IsaRandomizer;
