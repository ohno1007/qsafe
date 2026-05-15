//! StubBlob 二进制格式
//!
//! v2 layout:
//! ```text
//!   magic[4]    = "QVMP"
//!   version: u16 = 2
//!   spec_count: u32
//!   for each spec: isa_len: u32, isa_bytes: ... (IsaSpec 序列化)
//!   region_count: u32
//!   region[0..n]:
//!      patch_addr: u64
//!      patch_len:  u32
//!      bc_offset:  u32
//!      bc_len:     u32
//!      spec_idx:   u32        ← v2 加: 每个 region 指向自己的 IsaSpec
//!   bytecode_pool_len: u32
//!   bytecode_pool: ...
//!   entry_region: u32
//!   data_segments: ...
//! ```
//!
//! v2 与 v1 不兼容：v2 把"一个全局 IsaSpec"换成"每个 region 一个独立 IsaSpec"，
//! 静态分析 region A 拿到的 opcode→VOp 表完全不能套用到 region B。每个被保护
//! 函数有自己的 opcode 排列、寄存器置换、加密 key、立即数旋转, 等于每个函数
//! 跑在一台**不同的虚拟机**上。

use vmp_core::{Error, Result};
use vmp_isa::{HandlerVariant, IsaSpec, OpEncoding};
use std::collections::HashMap;

pub const MAGIC: &[u8; 4] = b"QVMP";
pub const VERSION: u16 = 2;

#[derive(Debug, Clone)]
pub struct StubRegion {
    pub patch_addr: u64,
    pub patch_len: u32,
    pub bc_offset: u32,
    pub bc_len: u32,
    /// 指向 `StubBlob.specs` 中的 IsaSpec 索引。同一进程内, 每个 region 可独立选
    /// 自己的 ISA — 一段 bytecode 必须用自己 region 的 spec 解才能跑.
    pub spec_idx: u32,
}

/// 原 ELF 加载段的拷贝，dispatch_vm 启动时通过 host.map_data 映射到对应 vaddr。
/// 这让 lifter 翻译的 `ADR` / `LDR literal` / 全局变量访问在 vmp-runtime 进程里也能生效。
#[derive(Debug, Clone)]
pub struct DataSegment {
    pub vaddr: u64,
    pub bytes: Vec<u8>,
    /// MAP 权限位：0x1=R, 0x2=W, 0x4=X。.rodata=R, .data=RW, .bss=RW。
    pub prot: u8,
}

#[derive(Debug, Clone)]
pub struct StubBlob {
    /// 每个 region 拿自己 spec_idx 对应的 spec. `specs[0]` 同时作为 v1
    /// 兼容入口 — 旧测试代码读 `blob.spec` 时拿到第一个.
    pub specs: Vec<IsaSpec>,
    pub regions: Vec<StubRegion>,
    pub bytecode_pool: Vec<u8>,
    /// 程序入口 region 索引（通常是 `_start` / `main` 所在 region）。
    /// vmp-runtime 默认从此 region 进入；可被 CLI `--region` 覆盖。
    pub entry_region: u32,
    /// 原 ELF 加载段拷贝（.rodata / .data / .bss 等）。dispatch_vm 启动时按原 vaddr 映射。
    pub data_segments: Vec<DataSegment>,
}

impl StubBlob {
    /// 拿 region_idx 对应 region 的 IsaSpec.
    pub fn spec_for_region(&self, region_idx: usize) -> &IsaSpec {
        let r = &self.regions[region_idx];
        &self.specs[r.spec_idx as usize]
    }

    /// v1 兼容入口: 默认 spec (第一个). 老测试代码直接读 `blob.spec`.
    pub fn spec(&self) -> &IsaSpec {
        &self.specs[0]
    }
}

pub fn pack_blob(blob: &StubBlob) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024 + blob.bytecode_pool.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());

    out.extend_from_slice(&(blob.specs.len() as u32).to_le_bytes());
    for spec in &blob.specs {
        let isa = pack_isa(spec);
        out.extend_from_slice(&(isa.len() as u32).to_le_bytes());
        out.extend_from_slice(&isa);
    }

    out.extend_from_slice(&(blob.regions.len() as u32).to_le_bytes());
    for r in &blob.regions {
        out.extend_from_slice(&r.patch_addr.to_le_bytes());
        out.extend_from_slice(&r.patch_len.to_le_bytes());
        out.extend_from_slice(&r.bc_offset.to_le_bytes());
        out.extend_from_slice(&r.bc_len.to_le_bytes());
        out.extend_from_slice(&r.spec_idx.to_le_bytes());
    }
    out.extend_from_slice(&(blob.bytecode_pool.len() as u32).to_le_bytes());
    out.extend_from_slice(&blob.bytecode_pool);
    out.extend_from_slice(&blob.entry_region.to_le_bytes());
    // data segments
    out.extend_from_slice(&(blob.data_segments.len() as u32).to_le_bytes());
    for ds in &blob.data_segments {
        out.extend_from_slice(&ds.vaddr.to_le_bytes());
        out.extend_from_slice(&(ds.bytes.len() as u32).to_le_bytes());
        out.push(ds.prot);
        out.extend_from_slice(&ds.bytes);
    }
    out
}

pub fn unpack_blob(data: &[u8]) -> Result<StubBlob> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8]> {
        if *p + n > data.len() {
            return Err(Error::parse("stub blob 截断"));
        }
        let r = &data[*p..*p + n];
        *p += n;
        Ok(r)
    };
    if take(&mut p, 4)? != MAGIC {
        return Err(Error::parse("stub blob magic 不匹配"));
    }
    let ver = u16::from_le_bytes(take(&mut p, 2)?.try_into().unwrap());
    if ver != VERSION {
        return Err(Error::parse(format!(
            "stub blob 版本不支持: {} (需 {})",
            ver, VERSION
        )));
    }

    let spec_count = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    let mut specs = Vec::with_capacity(spec_count);
    for _ in 0..spec_count {
        let isa_len = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        let isa_bytes = take(&mut p, isa_len)?.to_vec();
        specs.push(unpack_isa(&isa_bytes)?);
    }

    let region_count = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    let mut regions = Vec::with_capacity(region_count);
    for _ in 0..region_count {
        let patch_addr = u64::from_le_bytes(take(&mut p, 8)?.try_into().unwrap());
        let patch_len = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap());
        let bc_offset = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap());
        let bc_len = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap());
        let spec_idx = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap());
        regions.push(StubRegion {
            patch_addr,
            patch_len,
            bc_offset,
            bc_len,
            spec_idx,
        });
    }
    let pool_len = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    let bytecode_pool = take(&mut p, pool_len)?.to_vec();
    let entry_region = if data.len() >= p + 4 {
        u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap())
    } else {
        0
    };
    let mut data_segments = Vec::new();
    if data.len() >= p + 4 {
        let n = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        for _ in 0..n {
            let vaddr = u64::from_le_bytes(take(&mut p, 8)?.try_into().unwrap());
            let len = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
            let prot = take(&mut p, 1)?[0];
            let bytes = take(&mut p, len)?.to_vec();
            data_segments.push(DataSegment { vaddr, bytes, prot });
        }
    }

    Ok(StubBlob {
        specs,
        regions,
        bytecode_pool,
        entry_region,
        data_segments,
    })
}

// --- IsaSpec 自定义打包 ---
fn pack_isa(s: &IsaSpec) -> Vec<u8> {
    let mut out = Vec::new();
    // op_table
    out.extend_from_slice(&(s.op_table.len() as u32).to_le_bytes());
    let mut entries: Vec<_> = s.op_table.iter().collect();
    entries.sort_by_key(|(k, _)| **k);
    for (k, enc) in entries {
        out.extend_from_slice(&k.to_le_bytes());
        out.extend_from_slice(&(enc.variants.len() as u16).to_le_bytes());
        for v in &enc.variants {
            out.push(v.opcode);
            out.push(v.tweak);
        }
    }
    // op_reverse 通过 op_table 还原，这里不写
    out.extend_from_slice(&s.reg_perm);
    out.extend_from_slice(&s.reg_unperm);
    out.extend_from_slice(&s.stream_key);
    out.extend_from_slice(&s.stream_iv);
    out.extend_from_slice(&s.imm_rol.to_le_bytes());
    out.extend_from_slice(&s.branch_xor.to_le_bytes());
    out.push(if s.encrypt { 1 } else { 0 });
    out.extend_from_slice(&s.fingerprint);
    out
}

fn unpack_isa(data: &[u8]) -> Result<IsaSpec> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8]> {
        if *p + n > data.len() {
            return Err(Error::parse("isa blob 截断"));
        }
        let r = &data[*p..*p + n];
        *p += n;
        Ok(r)
    };
    let n = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    let mut op_table: HashMap<u16, OpEncoding> = HashMap::with_capacity(n);
    let mut op_reverse: [Option<(u16, u8)>; 256] = [None; 256];
    for _ in 0..n {
        let k = u16::from_le_bytes(take(&mut p, 2)?.try_into().unwrap());
        let vc = u16::from_le_bytes(take(&mut p, 2)?.try_into().unwrap()) as usize;
        let mut variants = Vec::with_capacity(vc);
        for _ in 0..vc {
            let opcode = take(&mut p, 1)?[0];
            let tweak = take(&mut p, 1)?[0];
            variants.push(HandlerVariant { opcode, tweak });
            op_reverse[opcode as usize] = Some((k, tweak));
        }
        op_table.insert(k, OpEncoding { variants });
    }
    let mut reg_perm = [0u8; 64];
    reg_perm.copy_from_slice(take(&mut p, 64)?);
    let mut reg_unperm = [0u8; 64];
    reg_unperm.copy_from_slice(take(&mut p, 64)?);
    let mut stream_key = [0u8; 32];
    stream_key.copy_from_slice(take(&mut p, 32)?);
    let mut stream_iv = [0u8; 16];
    stream_iv.copy_from_slice(take(&mut p, 16)?);
    let imm_rol = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap());
    let branch_xor = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap());
    let encrypt = take(&mut p, 1)?[0] != 0;
    let mut fingerprint = [0u8; 8];
    fingerprint.copy_from_slice(take(&mut p, 8)?);

    Ok(IsaSpec {
        op_table,
        op_reverse,
        reg_perm,
        reg_unperm,
        stream_key,
        imm_rol,
        branch_xor,
        stream_iv,
        encrypt,
        fingerprint,
    })
}
