use crate::{BinaryKind, LoadedObject};
use byteorder::{ByteOrder, LittleEndian};
use goblin::elf::Elf;
use goblin::elf::header::{ET_DYN, ET_EXEC, ET_REL};
use goblin::elf::section_header::SHF_EXECINSTR;
use vmp_core::{Arch, CodeRegion, Error, ObjectFormat, Os, Result, Symbol};

pub fn parse(bytes: &[u8], elf: Elf, format: ObjectFormat) -> Result<LoadedObject> {
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_AARCH64 => Arch::Arm64,
        goblin::elf::header::EM_X86_64 => Arch::X86_64,
        goblin::elf::header::EM_386 => Arch::X86,
        goblin::elf::header::EM_ARM => Arch::Arm32,
        m => return Err(Error::parse(format!("ELF 未知架构: {}", m))),
    };
    let os = Os::Linux;

    let mut code = Vec::new();
    for sh in &elf.section_headers {
        if (sh.sh_flags as u32) & SHF_EXECINSTR != 0 && sh.sh_size > 0 {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            if end > bytes.len() {
                return Err(Error::parse("ELF section 越界"));
            }
            code.push(CodeRegion {
                vaddr: sh.sh_addr,
                bytes: bytes[start..end].to_vec(),
            });
        }
    }

    let mut symbols = Vec::new();
    for sym in elf.syms.iter() {
        if sym.is_function() && sym.st_size > 0 {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                symbols.push(Symbol {
                    name: name.to_string(),
                    vaddr: sym.st_value,
                    size: sym.st_size,
                });
            }
        }
    }

    // Stripped binary fallback：`.symtab` 没函数符号时，从 `.eh_frame_hdr` 的二进制
    // 搜索表挖 FDE 起点；相邻起点之差近似函数大小（最后一个用 `.text` 末尾兜底）。
    // Android NDK 默认带 `-funwind-tables`（即便 release+strip 也保留 .eh_frame_hdr）。
    if symbols.is_empty() {
        symbols = mine_funcs_from_eh_frame_hdr(bytes, &elf).unwrap_or_default();
    }

    let kind = match elf.header.e_type {
        ET_EXEC => BinaryKind::Executable,
        ET_DYN => BinaryKind::SharedObject,  // PIE 可执行也归这里；rewriter 路径相同
        ET_REL => BinaryKind::Other,         // .o relocatable 单独处理
        _ => BinaryKind::Other,
    };

    Ok(LoadedObject {
        arch,
        os,
        format,
        kind,
        code,
        symbols,
        entry: elf.entry,
        raw: bytes.to_vec(),
    })
}

/// 从 `.eh_frame_hdr` 挖函数起点。.eh_frame_hdr 头部是固定 4 字节：
/// `version(=1)|eh_frame_ptr_enc|fde_count_enc|table_enc`，后接编码值。
///
/// 我们假设 NDK / GCC 的常见编码：
/// - eh_frame_ptr_enc = 0x1B (DW_EH_PE_pcrel | sdata4)
/// - fde_count_enc   = 0x03 (udata4)
/// - table_enc       = 0x3B (DW_EH_PE_datarel | sdata4) —— 相对 .eh_frame_hdr 起点
///
/// 表项 = (initial_pc_offset, fde_offset)，都是 4 字节 signed。
/// initial_pc 真实值 = .eh_frame_hdr_vaddr + initial_pc_offset。
///
/// 不解析 FDE 内部（避免完整 DWARF）；函数 size 用相邻 FDE start 之差近似。
fn mine_funcs_from_eh_frame_hdr(bytes: &[u8], elf: &Elf) -> Option<Vec<Symbol>> {
    use goblin::elf::section_header::SHF_EXECINSTR;
    // 找 .eh_frame_hdr section
    let (hdr_off, hdr_size, hdr_va) = elf
        .section_headers
        .iter()
        .find_map(|sh| {
            let nm = elf.shdr_strtab.get_at(sh.sh_name)?;
            if nm == ".eh_frame_hdr" {
                Some((sh.sh_offset as usize, sh.sh_size as usize, sh.sh_addr))
            } else {
                None
            }
        })?;
    if hdr_off + 12 > bytes.len() || hdr_size < 12 {
        return None;
    }
    let header = &bytes[hdr_off..hdr_off + hdr_size];
    let version = header[0];
    let eh_frame_ptr_enc = header[1];
    let fde_count_enc = header[2];
    let table_enc = header[3];
    if version != 1 {
        return None;
    }
    // 期望编码：见 doc 注释；任何不匹配直接放弃 mining，回到 0 函数（用户可改 CLI）。
    if eh_frame_ptr_enc != 0x1B || fde_count_enc != 0x03 || table_enc != 0x3B {
        return None;
    }
    let mut p = 4usize;
    // skip eh_frame_ptr (sdata4)
    p += 4;
    if p + 4 > header.len() {
        return None;
    }
    let fde_count = LittleEndian::read_u32(&header[p..p + 4]) as usize;
    p += 4;
    // 表项每个 8 字节：(initial_pc_pcrel_sdata4, fde_offset_pcrel_sdata4)
    let entry_size = 8;
    if p + fde_count * entry_size > header.len() {
        return None;
    }
    // 找最大 .text 范围（用于最后一个函数 size 兜底）
    let mut text_end: u64 = 0;
    for sh in &elf.section_headers {
        if (sh.sh_flags as u32) & SHF_EXECINSTR != 0 && sh.sh_size > 0 {
            let end = sh.sh_addr + sh.sh_size;
            if end > text_end {
                text_end = end;
            }
        }
    }

    let mut starts: Vec<u64> = Vec::with_capacity(fde_count);
    for i in 0..fde_count {
        let off = p + i * entry_size;
        let init_pc_offset = LittleEndian::read_i32(&header[off..off + 4]) as i64;
        // 编码 0x3B (DW_EH_PE_datarel) 的 base 是 .eh_frame_hdr 自身的 vaddr
        let pc = (hdr_va as i64 + init_pc_offset) as u64;
        starts.push(pc);
    }
    starts.sort();
    starts.dedup();

    let mut out = Vec::with_capacity(starts.len());
    for (i, &pc) in starts.iter().enumerate() {
        let next = starts.get(i + 1).copied().unwrap_or(text_end);
        if next <= pc || next - pc > 1024 * 1024 {
            // 异常：跳过；防止把巨长尾巴当成单个函数
            continue;
        }
        out.push(Symbol {
            name: format!("fn_{:08x}", pc),
            vaddr: pc,
            size: next - pc,
        });
    }
    Some(out)
}
