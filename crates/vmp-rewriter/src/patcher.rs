//! 跳板（trampoline）字节级生成。
//!
//! 一个跳板对应**一个被保护的函数 region**，长度 16 字节（4 条 ARM64 指令）：
//!
//! ```asm
//!     mov  x16, #region_id      ; 把 region_id 写到 X16（caller-saved）
//!     brk  #0xQVMP_BASE+region_id_low_byte ; 触发 SIGTRAP，由 runtime 接管
//!     nop
//!     b    .                    ; 防 fallthrough 兜底
//! ```
//!
//! 选择 BRK 的原因：
//! - 单条指令即可触发 OS 信号，不需要预先链接 runtime 符号
//! - `brk #imm16` 的 imm16 字段可以直接编码 region_id 的低 16 位，runtime 在
//!   SIGTRAP handler 里读 `siginfo->si_imm` / 重构指令即可拿到。
//! - 不依赖 PLT / GOT，在 .so 里也能用。
//!
//! 注：原函数入口的 4 字节会被覆盖成 `B <trampoline>` —— 因此只能保护**入口
//! 字节确实不再被执行**（即 lifter 已经把整段函数 lift 完）的情形。

use byteorder::{ByteOrder, LittleEndian};

/// BRK imm16 的高 8 位预留为 magic "QV"，低 8 位放 region_id（最多 256 个 region）；
/// 超过 256 时 runtime 必须从 X16 寄存器读完整 region_id。
pub const ARM64_BRK_QVMP_BASE: u16 = 0x5156; // 'Q' 'V'

#[derive(Debug, Clone, Copy)]
pub enum TrampolineKind {
    /// 用 BRK 触发外部 dispatcher（默认）
    Brk,
    /// 用 BL 直接跳到嵌入的 dispatch 函数（要求新 segment 内有 dispatch 入口）
    BlDirect,
}

/// 编码一条 `mov x16, #imm16` (MOVZ Xd=16, hw=0)。
fn encode_movz_x16(imm16: u32) -> u32 {
    // sf=1, opc=10, 100101, hw=00, imm16, Rd=16
    0xD2_80_00_00 | ((imm16 & 0xFFFF) << 5) | 16
}

/// 编码 `brk #imm16` : 1101_0100_001 imm16 0_0000
fn encode_brk(imm16: u16) -> u32 {
    0xD420_0000 | ((imm16 as u32) << 5)
}

/// 编码 `nop`
fn encode_nop() -> u32 {
    0xD503_201F
}

/// 编码 `bti jc`（HINT #0x26 = 100110）—— Branch Target Identification 接收
/// indirect branch (j) + indirect call (c) 两种入口。Android 14 启用 PAC+BTI
/// 后函数入口必须有 BTI 指令，否则间接跳转触发 SIGILL。
///
/// 编码：`HINT #imm7`，imm7=0x26 即 BTI jc
fn encode_bti_jc() -> u32 {
    0xD503_24DF
}

/// 编码 `b imm26` (相对当前 PC 的字节偏移；必须 4 字节对齐)
pub fn encode_b(rel_bytes: i32) -> Result<u32, super::RewriteError> {
    if rel_bytes & 3 != 0 {
        return Err(super::RewriteError::Internal(format!("B 偏移非 4 字节对齐: {}", rel_bytes)));
    }
    let imm26 = rel_bytes >> 2;
    if imm26 < -(1 << 25) || imm26 >= (1 << 25) {
        return Err(super::RewriteError::BranchTooFar);
    }
    let imm26_u = (imm26 as u32) & 0x03FF_FFFF;
    Ok(0x14000000 | imm26_u)
}

/// 生成一个 16-byte x86 / x86_64 trampoline：INT3 + region_id + filler。
///
/// 布局（16 字节）：
/// ```
///   CC                 ; INT3 — Linux SIGTRAP / Windows EXCEPTION_BREAKPOINT
///   00 00 00 <region_id_le_u32>     ; runtime VEH/handler 读 region_id
///   90 90 90 ... 90    ; NOP 填到 16 字节
/// ```
///
/// runtime 在 SIGTRAP handler / Windows VEH 里：
/// - 读 fault PC → 找跳板表项偏移 → 拿 region_id
/// - 调 `qvmp_dispatch(region_id, args, nargs)`
/// - 把 PC 推进到原函数的 caller LR 位置，等价 ret
pub fn build_x86_int3_trampoline(region_id: u32) -> [u8; 16] {
    let mut out = [0x90u8; 16]; // NOP 填充
    out[0] = 0xCC; // INT3
    // 1..5 留 region_id（little-endian u32），handler 从 fault PC + 1 读
    let bytes = region_id.to_le_bytes();
    out[1..5].copy_from_slice(&bytes);
    out
}

/// 生成一个 16-byte BRK 跳板：mov x16,#region_id ; brk #(QVMP_BASE|region_id_low) ; nop ; b .
///
/// **不带 BTI** 形式：用于不启用 BTI 的设备 / 二进制。
pub fn build_brk_trampoline(region_id: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mov = encode_movz_x16(region_id);
    let brk = encode_brk(ARM64_BRK_QVMP_BASE | ((region_id as u16) & 0xFF));
    let nop = encode_nop();
    let bself = 0x14000000u32; // b . （imm26=0，自跳）
    LittleEndian::write_u32(&mut out[0..4], mov);
    LittleEndian::write_u32(&mut out[4..8], brk);
    LittleEndian::write_u32(&mut out[8..12], nop);
    LittleEndian::write_u32(&mut out[12..16], bself);
    out
}

/// 生成一个 20-byte BTI 兼容跳板：bti jc ; mov x16,#region_id ; brk ; nop ; b .
///
/// 用于 Android 14 / 启用 GP（Guard Page）的 ARM64 二进制。当原函数入口使用
/// `BLR Xn` 跳转过来（非 B 指令），CPU 需要落地点首条指令是 BTI 否则 SIGILL。
/// 由于跳板长度变 20 字节而不是 16，调用方写入 e_text 时也要按 20 偏移。
pub fn build_brk_trampoline_bti(region_id: u32) -> [u8; 20] {
    let mut out = [0u8; 20];
    let bti = encode_bti_jc();
    let mov = encode_movz_x16(region_id);
    let brk = encode_brk(ARM64_BRK_QVMP_BASE | ((region_id as u16) & 0xFF));
    let nop = encode_nop();
    let bself = 0x14000000u32;
    LittleEndian::write_u32(&mut out[0..4], bti);
    LittleEndian::write_u32(&mut out[4..8], mov);
    LittleEndian::write_u32(&mut out[8..12], brk);
    LittleEndian::write_u32(&mut out[12..16], nop);
    LittleEndian::write_u32(&mut out[16..20], bself);
    out
}
