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
    /// 嵌入 cdylib runtime（libqvmp_runtime.so 的字节）。提供后 rewriter 会：
    ///   1. 把 .so bytes 追加到新 LOAD segment 末尾
    ///   2. 生成 bootstrap stub (open+write+dlopen+unlink)
    ///   3. 在 INIT_ARRAY 头插一条指向 bootstrap 的入口
    /// 这样最终 ELF 是完全自包含的，运行时不需要单独的 .so 文件。
    pub embed_runtime_so: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct RewriteReport {
    pub patched_entries: usize,
    pub trampoline_table_offset: u64,
    pub blob_offset: u64,
    pub new_segment_vaddr: u64,
    pub new_segment_size: u64,
    /// 当 `RewriteOptions::embed_runtime_so` 提供时填充：
    pub embedded_so_vaddr: u64,
    pub embedded_so_len: u64,
    pub bootstrap_vaddr: u64,
    pub init_array_vaddr: u64,
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

    // 关键：选 vaddr 同时拿到原有 LOAD 的最大 p_align（典型现代 ARM64 binary
    // 是 0x4000 = 16KB）。新 LOAD 必须用同样对齐，否则 16KB 页设备 mmap 会
    // 跟前段最后一页冲突 → bionic 报通用 PIE error。
    let (new_vaddr_base, page_align_u64) = next_load_vaddr(&loaded.raw)?;
    let page_align = page_align_u64 as usize;

    // ---- 1. 在末尾对齐到 page 边界（同时也要让 (vaddr - file_off) % p_align == 0）----
    // file offset 必须满足: (new_vaddr_base - file_off) % p_align == 0
    // → file_off ≡ new_vaddr_base (mod p_align)
    let target_off_mod = (new_vaddr_base as usize) & (page_align - 1);
    while (out.len() & (page_align - 1)) != target_off_mod {
        out.push(0);
    }
    let new_segment_off = out.len();

    // ---- 2. 跳板表（每个 region 16 字节）----
    let trampoline_table_off = out.len();
    for (idx, _r) in blob.regions.iter().enumerate() {
        let tramp = build_brk_trampoline(idx as u32);
        out.extend_from_slice(&tramp);
    }

    // ---- 3. 嵌入 blob ----
    // Header layout (32 bytes total):
    //   [0..4]   "QVMP"
    //   [4..8]   payload_len:u32
    //   [8..16]  rodata_vaddr:u64   (filled by armor::encrypt_rodata)
    //   [16..24] rodata_len:u64
    //   [24]     log_flag:u8        (filled by apply_armor; 1 = stderr+logcat on)
    //   [25..32] reserved
    let blob_off = out.len();
    out.extend_from_slice(b"QVMP");
    let packed = pack_blob(blob);
    let mut len_buf = [0u8; 4];
    LittleEndian::write_u32(&mut len_buf, packed.len() as u32);
    out.extend_from_slice(&len_buf);
    out.extend_from_slice(&[0u8; 24]); // 16 rodata + 1 log + 7 reserved
    out.extend_from_slice(&packed);

    // ---- 3b. 嵌入 runtime cdylib + bootstrap ----
    let mut embedded_so_vaddr = 0u64;
    let mut embedded_so_len = 0u64;
    let mut bootstrap_vaddr = 0u64;
    let mut init_array_vaddr_new = 0u64;

    let new_segment_vaddr = new_vaddr_base;

    if let Some(so_bytes) = &opts.embed_runtime_so {
        // dlopen PLT must exist in main ELF. If not, bail loudly.
        let dlopen_plt = crate::bootstrap::find_dlopen_plt(&loaded.raw).ok_or_else(|| {
            RewriteError::Internal(
                "main ELF does not import dlopen — cannot embed runtime in single-file mode"
                    .into(),
            )
        })?;

        // Derive a per-build XOR key from ELF header bytes — keeps `strings`
        // / `grep` over the embedded runtime silent and the key trivially
        // recoverable from the live process (since it's stored in the
        // bootstrap stub literal).
        let mut key_bytes = [0u8; 8];
        for i in 0..8 {
            key_bytes[i] =
                loaded.raw[i] ^ loaded.raw.get(0x18 + i).copied().unwrap_or(0) ^ (0xA5 ^ i as u8);
        }
        let xor_key = u64::from_le_bytes(key_bytes);
        let so_encrypted = crate::bootstrap::xor_runtime(so_bytes, xor_key);

        // 8-byte align before bootstrap so its u64 literals load fine.
        while out.len() % 8 != 0 {
            out.push(0);
        }
        let bootstrap_file_off = out.len();
        let bootstrap_vaddr_local =
            new_segment_vaddr + (bootstrap_file_off - new_segment_off) as u64;

        let stub_len = crate::bootstrap::BOOTSTRAP_BIN.len();
        let embedded_so_file_off = bootstrap_file_off + stub_len;
        let embedded_so_vaddr_local =
            new_segment_vaddr + (embedded_so_file_off - new_segment_off) as u64;

        let stub_bytes = crate::bootstrap::patch_bootstrap(
            bootstrap_vaddr_local,
            embedded_so_vaddr_local,
            so_encrypted.len() as u64,
            dlopen_plt,
            xor_key,
        )?;
        out.extend_from_slice(&stub_bytes);
        out.extend_from_slice(&so_encrypted);

        embedded_so_vaddr = embedded_so_vaddr_local;
        embedded_so_len = so_encrypted.len() as u64;
        bootstrap_vaddr = bootstrap_vaddr_local;
    }

    // 对齐到页边界结束新 segment
    while (out.len() - new_segment_off) % page_align != 0 {
        out.push(0);
    }
    let new_segment_size = out.len() - new_segment_off;

    // ---- 4. 添加新 PT_LOAD program header（先把整个 phdr 复制到末尾再增加一条）----
    add_load_phdr(&mut out, new_segment_off, new_segment_vaddr, new_segment_size, page_align_u64)?;

    // ---- 4b. 改写 INIT_ARRAY[0] 的 R_AARCH64_RELATIVE 让它先跑 bootstrap ----
    if bootstrap_vaddr != 0 {
        init_array_vaddr_new =
            patch_init_array_hijack(&mut out, &loaded.raw, bootstrap_vaddr, page_align_u64)?;
    }

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
            embedded_so_vaddr,
            embedded_so_len,
            bootstrap_vaddr,
            init_array_vaddr: init_array_vaddr_new,
            patched_entries,
            trampoline_table_offset: trampoline_table_off as u64,
            blob_offset: blob_off as u64,
            new_segment_vaddr,
            new_segment_size: new_segment_size as u64,
        },
    ))
}

/// Hijack INIT_ARRAY[0] in place — modify its R_AARCH64_RELATIVE relocation's
/// `r_addend` to point at a wrapper that does our bootstrap then tail-calls
/// the original first init function. This avoids relocating .init_array
/// itself (which would require chasing every relocation that targets it) and
/// keeps .dynamic untouched.
///
/// Layout written into `out`:
///   [bootstrap stub][embedded .so][...padding...][wrapper stub]
/// The wrapper, freshly minted here, calls bootstrap and then jumps to the
/// original first-init function (whose address is read out of the existing
/// relocation's addend).
///
/// Returns vaddr of the wrapper (== new addend value).
fn patch_init_array_hijack(
    out: &mut Vec<u8>,
    orig_elf: &[u8],
    bootstrap_vaddr: u64,
    page_align: u64,
) -> Result<u64> {
    use goblin::elf::Elf;
    use goblin::elf::dynamic::DT_INIT_ARRAY;
    use goblin::elf::reloc::R_AARCH64_RELATIVE;

    let elf = Elf::parse(orig_elf).map_err(|e| RewriteError::Parse(e.to_string()))?;
    let dynamic = elf
        .dynamic
        .as_ref()
        .ok_or_else(|| RewriteError::Internal("missing PT_DYNAMIC".into()))?;

    let mut init_array_vaddr: Option<u64> = None;
    for d in &dynamic.dyns {
        if d.d_tag == DT_INIT_ARRAY {
            init_array_vaddr = Some(d.d_val);
        }
    }
    let ia_vaddr =
        init_array_vaddr.ok_or_else(|| RewriteError::Internal("DT_INIT_ARRAY missing".into()))?;

    // Find the .rela.dyn relocation whose r_offset == ia_vaddr (= INIT_ARRAY[0])
    // and which is R_AARCH64_RELATIVE (= 1027 on aarch64).
    let mut rela_file_off: Option<usize> = None;
    let mut original_addend: i64 = 0;
    {
        // .rela.dyn is referenced from PT_DYNAMIC (DT_RELA / DT_RELASZ); use
        // goblin's parsed view to iterate, but we need the FILE offset of the
        // matching entry to patch it.
        let rela_section = elf.section_headers.iter().find(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map_or(false, |n| n == ".rela.dyn")
        });
        let rela_off = rela_section
            .map(|sh| sh.sh_offset as usize)
            .ok_or_else(|| RewriteError::Internal(".rela.dyn missing".into()))?;
        let rela_sz = rela_section.map(|sh| sh.sh_size as usize).unwrap_or(0);
        let entsize = 24usize; // Elf64_Rela: r_offset(8) + r_info(8) + r_addend(8)
        let mut i = 0;
        while i + entsize <= rela_sz {
            let p = rela_off + i;
            let r_offset = LittleEndian::read_u64(&orig_elf[p..p + 8]);
            let r_info = LittleEndian::read_u64(&orig_elf[p + 8..p + 16]);
            let r_addend = LittleEndian::read_i64(&orig_elf[p + 16..p + 24]);
            let r_type = (r_info & 0xffff_ffff) as u32;
            if r_offset == ia_vaddr && r_type == R_AARCH64_RELATIVE {
                rela_file_off = Some(p);
                original_addend = r_addend;
                break;
            }
            i += entsize;
        }
    }
    let rela_p = rela_file_off
        .ok_or_else(|| RewriteError::Internal("no R_RELATIVE for INIT_ARRAY[0]".into()))?;

    // Build a small wrapper:
    //   stp x29,x30,[sp,#-16]!
    //   bl bootstrap
    //   ldp x29,x30,[sp],#16
    //   b orig_init_func
    while out.len() % 4 != 0 {
        out.push(0);
    }
    let wrapper_file_off = out.len();
    // Determine current last LOAD's vaddr/file_off to compute wrapper's vaddr.
    let new_elf = Elf::parse(out).map_err(|e| RewriteError::Parse(e.to_string()))?;
    let mut last_load: Option<&goblin::elf::ProgramHeader> = None;
    for ph in &new_elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && last_load.map_or(true, |p| ph.p_vaddr > p.p_vaddr)
        {
            last_load = Some(ph);
        }
    }
    let last = last_load.ok_or_else(|| RewriteError::Internal("no PT_LOAD".into()))?;
    let last_seg_file = last.p_offset as usize;
    let last_seg_vaddr = last.p_vaddr;
    let wrapper_vaddr = last_seg_vaddr + (wrapper_file_off - last_seg_file) as u64;

    // Encode the 4 instructions.
    let mut emit = |w: u32| {
        let mut b = [0u8; 4];
        LittleEndian::write_u32(&mut b, w);
        out.extend_from_slice(&b);
    };
    emit(0xa9bf7bfd); // STP X29,X30,[SP,#-16]!
    // BL bootstrap (PC = wrapper_vaddr + 4)
    let bl_pc = wrapper_vaddr + 4;
    let bl_imm26 = ((bootstrap_vaddr as i64 - bl_pc as i64) / 4) & 0x3ff_ffff;
    emit(0x94_00_00_00u32 | bl_imm26 as u32);
    emit(0xa8c17bfd); // LDP X29,X30,[SP],#16
    // B orig_init_func (PC = wrapper_vaddr + 12)
    let b_pc = wrapper_vaddr + 12;
    let b_imm26 = ((original_addend - b_pc as i64) / 4) & 0x3ff_ffff;
    emit(0x14_00_00_00u32 | b_imm26 as u32);

    // Page-align tail and extend the last PT_LOAD's filesz/memsz to cover
    // the wrapper.
    let page = page_align as usize;
    let aligned_end = (out.len() + page - 1) & !(page - 1);
    while out.len() < aligned_end {
        out.push(0);
    }
    extend_last_load_to_file_end(out)?;

    // Patch the relocation's r_addend to wrapper_vaddr.
    LittleEndian::write_u64(&mut out[rela_p + 16..rela_p + 24], wrapper_vaddr);

    Ok(wrapper_vaddr)
}

/// Bump the last PT_LOAD's filesz/memsz to reach the current end of `out`.
/// Used after appending content past the original new-LOAD boundary.
fn extend_last_load_to_file_end(out: &mut Vec<u8>) -> Result<()> {
    use goblin::elf::Elf;
    let elf = Elf::parse(out).map_err(|e| RewriteError::Parse(e.to_string()))?;
    let phoff = elf.header.e_phoff as usize;
    let phentsize = elf.header.e_phentsize as usize;
    let phnum = elf.header.e_phnum as usize;
    let mut best_idx: Option<usize> = None;
    let mut best_vaddr = 0u64;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p_type = LittleEndian::read_u32(&out[off..off + 4]);
        if p_type != goblin::elf::program_header::PT_LOAD {
            continue;
        }
        let p_vaddr = LittleEndian::read_u64(&out[off + 16..off + 24]);
        if best_idx.is_none() || p_vaddr > best_vaddr {
            best_idx = Some(i);
            best_vaddr = p_vaddr;
        }
    }
    let i = best_idx
        .ok_or_else(|| RewriteError::Internal("no PT_LOAD to extend".into()))?;
    let off = phoff + i * phentsize;
    let p_offset = LittleEndian::read_u64(&out[off + 8..off + 16]);
    let new_size = (out.len() as u64) - p_offset;
    LittleEndian::write_u64(&mut out[off + 32..off + 40], new_size); // p_filesz
    LittleEndian::write_u64(&mut out[off + 40..off + 48], new_size); // p_memsz
    Ok(())
}

/// 找到所有 PT_LOAD segment 中最大的 vaddr+memsz，向上对齐到与原有 LOAD
/// 一致的 page 大小。返回 (aligned_vaddr, page_size)。
///
/// 关键：Android 14+ 在 Pixel 6+ / 高通新 SoC 上**默认 16KB 页**。原 binary 通常
/// 编译时按 16KB 对齐 (LOAD `p_align=0x4000`)，新 LOAD 必须用相同对齐，否则
/// 16KB 页系统的 mmap 会拒绝（与上一段的最后一页相冲），bionic 给出
/// 通用 "Android only supports PIE" 错误。
fn next_load_vaddr(elf_bytes: &[u8]) -> Result<(u64, u64)> {
    use goblin::elf::Elf;
    let elf = Elf::parse(elf_bytes).map_err(|e| RewriteError::Parse(e.to_string()))?;
    let mut max_end = 0u64;
    let mut max_align = 0x1000u64;
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            let end = ph.p_vaddr + ph.p_memsz;
            if end > max_end {
                max_end = end;
            }
            if ph.p_align > max_align {
                max_align = ph.p_align;
            }
        }
    }
    let mask = max_align - 1;
    let aligned = (max_end + mask) & !mask;
    Ok((aligned, max_align))
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
///
/// 关键点（早期版本踩坑）：
/// - PHDR table 移动后，原 `PT_PHDR` 条目里 `p_offset` / `p_vaddr` / `p_filesz`
///   指向旧位置；Android linker64 的 `FindPhdr()` 依赖该条目，链接器报
///   "Could not find a PHDR: broken executable" 然后 abort 即源于此。必须把
///   `PT_PHDR` 条目改写到新位置。
/// - 新 PHDR table 必须落在某个 PT_LOAD 的 file/vaddr 范围内（否则它根本不会
///   被 mmap 到内存里，PT_PHDR.vaddr 验证失败）。我们把新 PHDR table 直接接在
///   新 LOAD segment 后面，并把该 segment 的 `p_filesz`/`p_memsz` 延伸覆盖之。
fn add_load_phdr(
    out: &mut Vec<u8>,
    seg_file_off: usize,
    seg_vaddr: u64,
    _seg_size: usize,
    page_align: u64,
) -> Result<()> {
    use goblin::elf::Elf;
    use goblin::elf::program_header::{PT_LOAD, PT_PHDR};
    let elf = Elf::parse(&out[..]).map_err(|e| RewriteError::Parse(e.to_string()))?;
    if !elf.is_64 {
        return Err(RewriteError::Unsupported);
    }
    let phentsize = elf.header.e_phentsize as usize;
    let old_phoff = elf.header.e_phoff as usize;
    let old_phnum = elf.header.e_phnum as usize;
    let mut phdr_bytes = out[old_phoff..old_phoff + old_phnum * phentsize].to_vec();

    let new_phnum = old_phnum + 1;
    let new_phdr_total = new_phnum * phentsize;

    // 把 PHDR table 放在新 LOAD segment 内部、紧接现有 trampolines+blob 之后。
    // 对齐到 8 字节就够了（PHDR 自身要求 alignof(Elf64_Phdr) = 8）；不需要页对齐。
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let new_phoff = out.len();

    // 新 PHDR table 的虚拟地址：落在新 LOAD segment 内部
    let new_phdr_vaddr = seg_vaddr + (new_phoff as u64 - seg_file_off as u64);

    // 改写 phdr_bytes 里的 PT_PHDR 条目
    for i in 0..old_phnum {
        let off = i * phentsize;
        let p_type = LittleEndian::read_u32(&phdr_bytes[off..off + 4]);
        if p_type == PT_PHDR {
            LittleEndian::write_u64(&mut phdr_bytes[off + 8..off + 16], new_phoff as u64);
            LittleEndian::write_u64(&mut phdr_bytes[off + 16..off + 24], new_phdr_vaddr);
            LittleEndian::write_u64(&mut phdr_bytes[off + 24..off + 32], new_phdr_vaddr);
            LittleEndian::write_u64(&mut phdr_bytes[off + 32..off + 40], new_phdr_total as u64);
            LittleEndian::write_u64(&mut phdr_bytes[off + 40..off + 48], new_phdr_total as u64);
            break;
        }
    }

    // 1) 写 PHDR table（旧 phdrs + 新 LOAD entry）
    // 2) 向上 page-pad 文件，让 PHDR table 完整落在 page-aligned 段内
    // 3) 新 LOAD entry 的 filesz/memsz 延伸覆盖 padding 后整个范围
    let mask = (page_align - 1) as usize;
    let raw_end = new_phoff + new_phdr_total;
    let aligned_end = (raw_end + mask) & !mask;
    let extended_seg_size = aligned_end - seg_file_off;
    let mut entry = [0u8; 56];
    LittleEndian::write_u32(&mut entry[0..4], PT_LOAD);
    LittleEndian::write_u32(&mut entry[4..8], 0x4 | 0x1); // PF_R | PF_X
    LittleEndian::write_u64(&mut entry[8..16], seg_file_off as u64);
    LittleEndian::write_u64(&mut entry[16..24], seg_vaddr);
    LittleEndian::write_u64(&mut entry[24..32], seg_vaddr);
    LittleEndian::write_u64(&mut entry[32..40], extended_seg_size as u64);
    LittleEndian::write_u64(&mut entry[40..48], extended_seg_size as u64);
    LittleEndian::write_u64(&mut entry[48..56], page_align);
    if entry.len() != phentsize {
        return Err(RewriteError::Internal(format!(
            "phentsize 不匹配: {} vs {}",
            phentsize,
            entry.len()
        )));
    }

    // (1) PHDR table goes here, at new_phoff
    out.extend_from_slice(&phdr_bytes);
    out.extend_from_slice(&entry);
    // (2) page-pad to aligned_end so the new LOAD's filesz lands on a page boundary
    while out.len() < aligned_end {
        out.push(0);
    }

    // 更新 ELF header：e_phoff (offset 0x20, 8B) + e_phnum (offset 0x38, 2B)
    LittleEndian::write_u64(&mut out[0x20..0x28], new_phoff as u64);
    LittleEndian::write_u16(&mut out[0x38..0x3A], new_phnum as u16);
    Ok(())
}
