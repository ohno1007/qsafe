//! ELF 重写：在原 ELF 末尾追加 PT_LOAD segment，把 stub blob + 跳板表写入新段，
//! 同时在每个被保护函数的入口写一条 `B <trampoline>`。
//!
//! 实现策略最小可行版（**MVP**）：
//! 1. 把整个原 ELF 字节流读到内存。
//! 2. 在文件末尾追加：
//!    - 跳板表：每个 region 一个 16-byte 跳板（顺序与 `regions` 一致）
//!    - magic + blob 长度 + blob 字节
//! 3. 给原 ELF 增加一个新的 program-header 项（PT_LOAD，可读+可执行）。
//!    - 这要求 ELF 文件原本在 `e_phoff..e_phoff + e_phnum * e_phentsize` 之后还有
//!      足够空间放新 entry；否则得整体 relocate program-header 表（更复杂）。
//!    - 实践上 LLD 链接的 ELF 通常 e_phoff 紧跟 ELF header 后，phdr 之后是 .interp
//!      或第一个 LOAD segment，没有空隙。**这里把 phdr 整体复制到文件末尾的新位置**
//!      并把 `e_phoff` 指向新位置（这样能放下额外条目）。
//! 4. 在每个 region 的 patch_addr 写 `B <对应跳板虚拟地址>`。
//!
//! 注意：
//! - 不重写 .dynsym / .dynamic / .rela.dyn —— 不动这些不会破坏现有动态链接。
//! - 不修复 .eh_frame —— 我们覆盖的指令位于函数入口，正常异常展开不会回退到首条指令。
//! - 新追加的 segment 不写入任何 dynamic 标记，OS 加载时把它当普通可执行 LOAD 段。

use crate::patcher::{build_brk_trampoline, encode_b};
use crate::{Result, RewriteError};
use byteorder::{ByteOrder, LittleEndian};
use vmp_loader::{BinaryKind, LoadedObject};
use vmp_stub::{pack_blob, StubBlob, StubRegion};

#[derive(Debug, Default, Clone)]
pub struct RewriteOptions {
    /// 输出新 ELF 时是否也把每个 region 的 `patch_addr` 写一条 B 跳板。
    /// 关闭时仅嵌入 blob，不动原 .text（适合"先嵌入字节码后续再 patch"的两阶段）。
    pub write_entry_trampolines: bool,
}

#[derive(Debug, Default)]
pub struct RewriteReport {
    pub patched_entries: usize,
    pub trampoline_table_offset: u64,
    pub blob_offset: u64,
    pub new_segment_vaddr: u64,
    pub new_segment_size: u64,
}

/// 把 `blob` 嵌入 `loaded` 原 ELF，写入跳板（可选），返回新 ELF 字节。
pub fn rewrite_elf(
    loaded: &LoadedObject,
    blob: &StubBlob,
    opts: &RewriteOptions,
) -> Result<(Vec<u8>, RewriteReport)> {
    if !matches!(loaded.kind, BinaryKind::Executable | BinaryKind::SharedObject) {
        return Err(RewriteError::Unsupported);
    }
    let mut out = loaded.raw.clone();

    // ---- 1. 在末尾对齐到 0x1000 边界 ----
    let page_align = 0x1000usize;
    while out.len() % page_align != 0 {
        out.push(0);
    }
    let new_segment_off = out.len();

    // 选择新 segment 的 vaddr：找到所有 PT_LOAD 中最高 vaddr+memsz，向上对齐 0x1000。
    // 紧贴原 ELF 最高 LOAD vaddr 之后（对齐 0x1000），让 B-imm26 跳板偏移在 ±128MB 内
    let new_vaddr_base = next_load_vaddr(&loaded.raw)?;

    // ---- 2. 跳板表（每个 region 16 字节）----
    let trampoline_table_off = out.len();
    for (idx, _r) in blob.regions.iter().enumerate() {
        let tramp = build_brk_trampoline(idx as u32);
        out.extend_from_slice(&tramp);
    }

    // ---- 3. 嵌入 blob ----
    let blob_off = out.len();
    out.extend_from_slice(b"QVMP");
    let packed = pack_blob(blob);
    let mut len_buf = [0u8; 4];
    LittleEndian::write_u32(&mut len_buf, packed.len() as u32);
    out.extend_from_slice(&len_buf);
    out.extend_from_slice(&packed);

    // 对齐到页边界结束新 segment
    while (out.len() - new_segment_off) % page_align != 0 {
        out.push(0);
    }
    let new_segment_size = out.len() - new_segment_off;

    // ---- 4. 添加新 PT_LOAD program header（先把整个 phdr 复制到末尾再增加一条）----
    let new_segment_vaddr = new_vaddr_base;
    add_load_phdr(&mut out, new_segment_off, new_segment_vaddr, new_segment_size)?;

    // ---- 5. 在每个 region 的 patch_addr 写 B <trampoline> ----
    let mut patched_entries = 0usize;
    if opts.write_entry_trampolines {
        for (idx, region) in blob.regions.iter().enumerate() {
            let target_vaddr = new_segment_vaddr + (idx * 16) as u64;
            let file_off = match vaddr_to_file_off(&loaded.raw, region.patch_addr) {
                Some(o) => o,
                None => continue,
            };
            let rel = (target_vaddr as i64) - (region.patch_addr as i64);
            // 偏移可能溢出 ±128MB；超出时跳过（rewriter 还原成只嵌入不 patch）。
            let b_inst = match encode_b(rel as i32) {
                Ok(v) => v,
                Err(_) => {
                    log::warn!(
                        "region {} patch_addr {:#x} 距离跳板 {:#x} 超过 B 范围，跳过 patch",
                        idx, region.patch_addr, target_vaddr
                    );
                    continue;
                }
            };
            if file_off + 4 > out.len() {
                continue;
            }
            LittleEndian::write_u32(&mut out[file_off..file_off + 4], b_inst);
            patched_entries += 1;
        }
    }

    Ok((
        out,
        RewriteReport {
            patched_entries,
            trampoline_table_offset: trampoline_table_off as u64,
            blob_offset: blob_off as u64,
            new_segment_vaddr,
            new_segment_size: new_segment_size as u64,
        },
    ))
}

/// 找到所有 PT_LOAD segment 中最大的 vaddr+memsz，向上对齐 0x1000。
fn next_load_vaddr(elf_bytes: &[u8]) -> Result<u64> {
    use goblin::elf::Elf;
    let elf = Elf::parse(elf_bytes).map_err(|e| RewriteError::Parse(e.to_string()))?;
    let mut max_end = 0u64;
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            let end = ph.p_vaddr + ph.p_memsz;
            if end > max_end {
                max_end = end;
            }
        }
    }
    let aligned = (max_end + 0xFFF) & !0xFFFu64;
    Ok(aligned)
}

/// 把 patch_addr (虚拟地址) 转成原 ELF 文件内的字节偏移。
fn vaddr_to_file_off(elf_bytes: &[u8], vaddr: u64) -> Option<usize> {
    use goblin::elf::Elf;
    let elf = Elf::parse(elf_bytes).ok()?;
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && vaddr >= ph.p_vaddr
            && vaddr < ph.p_vaddr + ph.p_filesz
        {
            return Some((ph.p_offset + (vaddr - ph.p_vaddr)) as usize);
        }
    }
    None
}

/// 复制原 program header table 到文件末尾，并追加一个新的 PT_LOAD 条目。
/// 同时把 ELF header 中的 `e_phoff` / `e_phnum` 更新指向新位置。
fn add_load_phdr(
    out: &mut Vec<u8>,
    seg_file_off: usize,
    seg_vaddr: u64,
    seg_size: usize,
) -> Result<()> {
    use goblin::elf::Elf;
    let elf = Elf::parse(&out[..]).map_err(|e| RewriteError::Parse(e.to_string()))?;
    if !elf.is_64 {
        return Err(RewriteError::Unsupported);
    }
    let phentsize = elf.header.e_phentsize as usize;
    let old_phoff = elf.header.e_phoff as usize;
    let old_phnum = elf.header.e_phnum as usize;
    let old_phdr_bytes = out[old_phoff..old_phoff + old_phnum * phentsize].to_vec();

    // 在文件末尾对齐 8 字节，然后写入旧 phdr + 新 phdr 项
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let new_phoff = out.len();
    out.extend_from_slice(&old_phdr_bytes);

    // 构造新 PT_LOAD entry (Elf64_Phdr, 56 字节)
    let mut entry = [0u8; 56];
    LittleEndian::write_u32(&mut entry[0..4], goblin::elf::program_header::PT_LOAD);
    // p_flags: PF_R | PF_X (可读 + 可执行)
    LittleEndian::write_u32(&mut entry[4..8], 0x4 | 0x1);
    LittleEndian::write_u64(&mut entry[8..16], seg_file_off as u64);
    LittleEndian::write_u64(&mut entry[16..24], seg_vaddr);
    LittleEndian::write_u64(&mut entry[24..32], seg_vaddr); // p_paddr
    LittleEndian::write_u64(&mut entry[32..40], seg_size as u64); // p_filesz
    LittleEndian::write_u64(&mut entry[40..48], seg_size as u64); // p_memsz
    LittleEndian::write_u64(&mut entry[48..56], 0x1000); // p_align
    if entry.len() != phentsize {
        // 不匹配（理论上 64-bit 永远是 56 字节）
        return Err(RewriteError::Internal(format!(
            "phentsize 不匹配: {} vs {}",
            phentsize,
            entry.len()
        )));
    }
    out.extend_from_slice(&entry);

    // 更新 ELF header 中的 e_phoff (offset 0x20, 8 bytes) + e_phnum (offset 0x38, 2 bytes)
    LittleEndian::write_u64(&mut out[0x20..0x28], new_phoff as u64);
    LittleEndian::write_u16(&mut out[0x38..0x3A], (old_phnum + 1) as u16);
    Ok(())
}
