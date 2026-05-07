//! vmp-codegen
//!
//! 把一段 IR ([`vmp_isa::Instr`] 列表)编码为字节流，并应用：
//! - 随机选择 handler 变体
//! - 可选流加密（位置敏感的密钥派生 XOR）
//! - 垃圾指令插入
//!
//! 输出由 [`vmp-interpreter`] 在运行时反向解码并执行。

pub mod junk;
pub mod resolve;
pub mod stream;

pub use resolve::{resolve_program, FunctionRegion, ResolveReport};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use vmp_core::{Error, Result};
use vmp_isa::{encode_instr, Instr, IsaSpec, VOp};

pub struct CodeGen<'a> {
    pub spec: &'a IsaSpec,
    pub rng: ChaCha20Rng,
    pub junk_density: u8,
    pub variants_per_op: u8,
    /// 字节码流加密的 IV salt：interpreter 解密时也要使用同一 salt（dispatch_vm 传入）。
    /// 不同 region 用不同 salt → keystream 不共享 → 静态分析单个 region 的字节码无法迁移到别的 region。
    pub iv_salt: u64,
}

impl<'a> CodeGen<'a> {
    pub fn new(spec: &'a IsaSpec, seed: u64, junk_density: u8, variants_per_op: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        Self {
            spec,
            rng: ChaCha20Rng::from_seed(bytes),
            junk_density,
            variants_per_op: variants_per_op.max(1),
            iv_salt: 0,
        }
    }

    pub fn with_iv_salt(mut self, salt: u64) -> Self {
        self.iv_salt = salt;
        self
    }

    /// 把 IR 序列编码成字节流。
    ///
    /// IR 中的分支指令（Br / BCond / Call）的 `imm` 字段被 lifter 设置为
    /// **目标 IR 索引**（不是字节偏移）。codegen 在真正编码完所有 IR（含按需插入的 junk）
    /// 之后，再做第二遍 fixup —— 把每条分支的 imm 字段重写成 enc_branch(实际字节 delta)。
    /// 这样 junk insertion 不会让分支错位。
    pub fn encode(&mut self, ir: &[Instr]) -> Result<Vec<u8>> {
        use byteorder::{ByteOrder, LittleEndian};

        let mut out = Vec::with_capacity(ir.len() * 6);
        let mut ir_byte_offsets = Vec::with_capacity(ir.len());
        // (imm 字段的字节偏移, 该分支 IR 的索引, 目标 IR 索引)
        let mut branch_fixups: Vec<(usize, usize, usize)> = Vec::new();

        for (idx, instr) in ir.iter().enumerate() {
            // junk 在 IR 编码之前插（不影响 IR 间的语义；分支偏移由后面 fixup 处理）
            if self.junk_density > 0 && self.rng.gen_range(0..100) < self.junk_density {
                self.emit_junk(&mut out)?;
            }

            let ir_start = out.len();
            ir_byte_offsets.push(ir_start);

            let mut concrete = *instr;
            concrete.variant = self.rng.gen_range(0..self.variants_per_op);

            let is_branch = matches!(concrete.op, VOp::Br | VOp::BCond | VOp::Call);
            if is_branch {
                // 暂存目标索引，imm 占位为 0；记录稍后 fixup 的 byte 位置。
                let target_idx = concrete.imm as usize;
                concrete.imm = 0;
                let lay = concrete.layout();
                let imm_field_offset = ir_start
                    + 1 // opcode
                    + lay.has_rd as usize
                    + lay.has_rs as usize
                    + lay.has_rt as usize
                    + lay.has_width as usize
                    + lay.has_cond as usize;
                encode_instr(self.spec, &concrete, &mut out)
                    .map_err(|m| Error::internal(format!("encode: {m}")))?;
                branch_fixups.push((imm_field_offset, idx, target_idx));
            } else {
                encode_instr(self.spec, &concrete, &mut out)
                    .map_err(|m| Error::internal(format!("encode: {m}")))?;
            }
        }

        // 第二遍：根据真实 byte 偏移回填每条 branch 的 imm 字段
        for (imm_pos, branch_idx, target_idx) in branch_fixups {
            if target_idx >= ir_byte_offsets.len() {
                return Err(Error::internal(format!(
                    "branch target IR 索引越界: {} (共 {})",
                    target_idx,
                    ir_byte_offsets.len()
                )));
            }
            let cur = ir_byte_offsets[branch_idx] as i64;
            let tgt = ir_byte_offsets[target_idx] as i64;
            let delta = (tgt - cur) as i32;
            let encoded = self.spec.enc_branch(delta) as u32;
            let mut buf = [0u8; 4];
            LittleEndian::write_u32(&mut buf, encoded);
            out[imm_pos..imm_pos + 4].copy_from_slice(&buf);
        }

        if self.spec.encrypt {
            stream::encrypt_in_place_salted(
                &mut out,
                &self.spec.stream_key,
                &self.spec.stream_iv,
                self.iv_salt,
            );
        }
        Ok(out)
    }

    fn emit_junk(&mut self, out: &mut Vec<u8>) -> Result<()> {
        // 升级版 junk：可能产出 1~3 条 IR 的"哑指令序列"，更难被静态分析识别为统一 noop slot
        let mut decoy_buf: Vec<Instr> = Vec::with_capacity(4);
        crate::junk::emit_decoy_seq(&mut decoy_buf, &mut self.rng);
        for ins in &decoy_buf {
            let mut concrete = *ins;
            concrete.variant = self.rng.gen_range(0..self.variants_per_op);
            encode_instr(self.spec, &concrete, out)
                .map_err(|m| Error::internal(format!("junk: {m}")))?;
        }
        Ok(())
    }
}
