//! Windows PE / PE32+ 加壳重写。
//!
//! 与 ELF 路径思想对称：
//! - 在 PE 末尾追加新 section（`.qvmp`）承载 stub blob + 跳板表
//! - 修改 IMAGE_FILE_HEADER.NumberOfSections + IMAGE_OPTIONAL_HEADER.SizeOfImage
//! - 在每个被保护函数入口写一条 ARM64 / x86_64 跳板
//!
//! ARM64 Windows ABI 与 Linux 不同：
//! - X18 是平台保留寄存器（TEB pointer）—— lifter 不能把它当通用寄存器用，
//!   否则原 native 代码读 X18 时会拿到 VM scratch 而非 TEB。
//! - 调用约定相同（X0..X7 参数 / X0 返回），栈对齐 16
//! - PAC（指针签名）在 ARM64EC 启用，BRK 跳板需要 ret 时用 RETAB；本 MVP 不动 PAC
//!
//! 当前实现：MVP — 只追加新 section + 跳板，不改 import table，不动 .pdata。
//! ARM64 PE 的 .pdata 表项基于函数 RVA 描述展开信息；如果跳板覆盖第一条指令，
//! 异常展开仍能正确处理（unwind code 通常从 prologue 开始解析，覆盖第 1 条 ≤ 4 字节
//! 不破坏 unwind 语义）。完整 PE 路径会在 Phase 5 补完。

use crate::patcher::{build_brk_trampoline, build_x86_int3_trampoline};
use crate::Result;
use byteorder::{ByteOrder, LittleEndian};
use vmp_loader::{BinaryKind, LoadedObject};
use vmp_stub::{pack_blob, StubBlob};

#[derive(Debug, Clone, Default)]
pub struct PeRewriteOptions {
    pub write_entry_trampolines: bool,
    /// X18 平台保留寄存器路由：ARM64 Windows 必开启（Linux 关闭）。
    /// lifter 可读此 flag 把 X18 映射到独立 vreg 隔离 Windows TEB。
    pub arm64_windows_x18_isolation: bool,
}

#[derive(Debug, Default)]
pub struct PeRewriteReport {
    pub patched_entries: usize,
    pub new_section_rva: u32,
    pub new_section_size: u32,
    pub blob_offset: u64,
}

/// 把 stub blob 嵌入 PE，输出新二进制。MVP：仅追加 section，不写跳板。
pub fn rewrite_pe(
    loaded: &LoadedObject,
    blob: &StubBlob,
    opts: &PeRewriteOptions,
) -> Result<(Vec<u8>, PeRewriteReport)> {
    if !matches!(loaded.kind, BinaryKind::Executable | BinaryKind::SharedObject) {
        return Err(crate::RewriteError::Unsupported);
    }
    if loaded.format != vmp_core::ObjectFormat::Pe {
        return Err(crate::RewriteError::Unsupported);
    }

    let mut out = loaded.raw.clone();
    let _ = opts.write_entry_trampolines; // MVP 暂未写跳板
    let _ = opts.arm64_windows_x18_isolation;

    // 找 PE header (e_lfanew @ 0x3C)
    if out.len() < 0x40 {
        return Err(crate::RewriteError::Parse("PE 太短".into()));
    }
    let pe_off = LittleEndian::read_u32(&out[0x3C..0x40]) as usize;
    if pe_off + 24 > out.len() || &out[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err(crate::RewriteError::Parse("PE signature 缺失".into()));
    }
    // COFF File Header
    let coff_off = pe_off + 4;
    let num_sections = LittleEndian::read_u16(&out[coff_off + 2..coff_off + 4]);
    let opt_size = LittleEndian::read_u16(&out[coff_off + 16..coff_off + 18]);
    let opt_off = coff_off + 20;

    // 判断 PE32 vs PE32+
    if opt_off + 2 > out.len() {
        return Err(crate::RewriteError::Parse("optional header 越界".into()));
    }
    let magic = LittleEndian::read_u16(&out[opt_off..opt_off + 2]);
    let is_pe32_plus = magic == 0x20B;

    // PE32 vs PE32+ optional header 字段偏移（IMAGE_OPTIONAL_HEADER vs ..._64）：
    //   字段                 PE32     PE32+
    //   SectionAlignment     +32      +32
    //   FileAlignment        +36      +36
    //   SizeOfImage          +56      +56     ← 两者相同（在 ImageBase 之前）
    //   ImageBase            +28(u32) +24(u64) ← 这里两者位置都不一样
    // SizeOfImage 在 PE32 里是 +56，在 PE32+ 里仍是 +56（"NumberOfHeaders 之后"），
    // 所以下面统一处理；ImageBase 我们没用，跳过。
    let sec_align_off = opt_off + 32;
    let file_align_off = opt_off + 36;
    let size_of_image_off = opt_off + 56;
    let sec_align = LittleEndian::read_u32(&out[sec_align_off..sec_align_off + 4]);
    let file_align = LittleEndian::read_u32(&out[file_align_off..file_align_off + 4]);
    if sec_align == 0 || file_align == 0 {
        return Err(crate::RewriteError::Parse("alignment 字段为 0".into()));
    }
    let _ = is_pe32_plus;

    // section table 紧跟 optional header
    let section_table_off = opt_off + opt_size as usize;
    let section_size = 40usize;
    let new_section_off = section_table_off + (num_sections as usize) * section_size;
    if new_section_off + section_size > out.len() {
        return Err(crate::RewriteError::Internal(
            "section table 后没有空间放新 section header（PE 路径需要重排，MVP 拒绝）".into(),
        ));
    }

    // 计算追加 section 的字节。
    //
    // 跳板形式由架构决定：
    // - ARM64 / ARM64EC：BRK + MOV X16,#region_id（[`build_brk_trampoline`]）
    // - x86 / x86_64：INT3 (0xCC) + 一段裸 region_id 字节（runtime 在 SIGTRAP / VEH
    //   handler 里读 region_id 并继续）
    //
    // 当前 MVP：所有架构统一用 ARM64 形式 16 字节跳板（仅 ARM64 上能正确触发；x86
    // 上会被 CPU 当作非法指令，调用方需要在 cdylib 内特化处理）。后续按 `loaded.arch`
    // 分发到各自跳板生成器。
    let mut payload: Vec<u8> = Vec::new();
    for (idx, _r) in blob.regions.iter().enumerate() {
        let tramp = match loaded.arch {
            vmp_core::Arch::X86 | vmp_core::Arch::X86_64 => build_x86_int3_trampoline(idx as u32),
            _ => build_brk_trampoline(idx as u32),
        };
        payload.extend_from_slice(&tramp);
    }
    payload.extend_from_slice(b"QVMP");
    let packed = pack_blob(blob);
    payload.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    payload.extend_from_slice(&packed);

    // 文件对齐
    let raw_size = ((payload.len() as u32 + file_align - 1) / file_align) * file_align;
    let virtual_size = payload.len() as u32;

    // 追加 section 数据到文件末尾，先做 file alignment
    while (out.len() as u32) % file_align != 0 {
        out.push(0);
    }
    let raw_data_off = out.len() as u32;
    out.extend_from_slice(&payload);
    while (out.len() as u32) < raw_data_off + raw_size {
        out.push(0);
    }

    // 选 RVA：原 SizeOfImage 是下一个空 RVA（已对齐 SectionAlignment）
    let new_rva = LittleEndian::read_u32(&out[size_of_image_off..size_of_image_off + 4]);

    // 写 section header
    let mut sh = [0u8; 40];
    let name = b".qvmp";
    sh[..name.len()].copy_from_slice(name);
    LittleEndian::write_u32(&mut sh[8..12], virtual_size);
    LittleEndian::write_u32(&mut sh[12..16], new_rva);
    LittleEndian::write_u32(&mut sh[16..20], raw_size);
    LittleEndian::write_u32(&mut sh[20..24], raw_data_off);
    // characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_READ | MEM_EXECUTE
    LittleEndian::write_u32(&mut sh[36..40], 0x4000_0040 | 0x2000_0000);
    out[new_section_off..new_section_off + 40].copy_from_slice(&sh);

    // 更新 NumberOfSections
    LittleEndian::write_u16(&mut out[coff_off + 2..coff_off + 4], num_sections + 1);
    // 更新 SizeOfImage
    let new_size_of_image =
        ((new_rva + virtual_size + sec_align - 1) / sec_align) * sec_align;
    LittleEndian::write_u32(
        &mut out[size_of_image_off..size_of_image_off + 4],
        new_size_of_image,
    );

    Ok((
        out,
        PeRewriteReport {
            patched_entries: 0,
            new_section_rva: new_rva,
            new_section_size: virtual_size,
            blob_offset: (raw_data_off as u64) + (blob.regions.len() as u64) * 16,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        // 用一个 8 字节假 ELF 做 LoadedObject —— 这里测的是路径分支，rewrite 应当 Unsupported
        let lo = LoadedObject {
            arch: vmp_core::Arch::X86_64,
            os: vmp_core::Os::Linux,
            format: vmp_core::ObjectFormat::Elf,
            kind: BinaryKind::Executable,
            code: vec![],
            symbols: vec![],
            entry: 0,
            raw: vec![0; 8],
        };
        let blob = StubBlob {
            spec: vmp_isa::IsaRandomizer::new(0, 1, false).build(),
            regions: vec![],
            bytecode_pool: vec![],
            entry_region: 0,
            data_segments: vec![],
        };
        let r = rewrite_pe(&lo, &blob, &PeRewriteOptions::default());
        assert!(r.is_err());
    }
}
