use crate::{BinaryKind, LoadedObject};
use goblin::elf::Elf;
use goblin::elf::header::{ET_DYN, ET_EXEC, ET_REL};
use goblin::elf::section_header::SHF_EXECINSTR;
use vmp_core::{Arch, CodeRegion, Error, ObjectFormat, Os, Result, Symbol};

/// Recover function boundaries (start vaddr + byte size) from `.eh_frame` FDEs.
/// Stripped binaries have no `.symtab`; FDE coverage is the next-best ground truth
/// (compilers emit one FDE per function for unwinding). Returns sorted, deduped vec.
fn discover_via_eh_frame(bytes: &[u8], elf: &Elf) -> Vec<(u64, u64)> {
    use gimli::{BaseAddresses, CieOrFde, EhFrame, NativeEndian, UnwindSection};

    let mut eh_frame_addr: u64 = 0;
    let mut eh_frame_data: &[u8] = &[];
    let mut text_addr: u64 = 0;
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name == ".eh_frame" {
            eh_frame_addr = sh.sh_addr;
            let s = sh.sh_offset as usize;
            let e = s + sh.sh_size as usize;
            if e <= bytes.len() {
                eh_frame_data = &bytes[s..e];
            }
        } else if name == ".text" {
            text_addr = sh.sh_addr;
        }
    }
    if eh_frame_data.is_empty() {
        return Vec::new();
    }

    let bases = BaseAddresses::default()
        .set_eh_frame(eh_frame_addr)
        .set_text(text_addr);
    let eh = EhFrame::new(eh_frame_data, NativeEndian);
    let mut entries = eh.entries(&bases);
    let mut out: Vec<(u64, u64)> = Vec::new();
    while let Ok(Some(entry)) = entries.next() {
        if let CieOrFde::Fde(partial) = entry {
            if let Ok(fde) = partial.parse(|_, bases, off| eh.cie_from_offset(bases, off)) {
                let start = fde.initial_address();
                let len = fde.len();
                if len > 0 {
                    out.push((start, len));
                }
            }
        }
    }
    out.sort_by_key(|p| p.0);
    out.dedup_by_key(|p| p.0);
    out
}

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
            if let Some(Ok(name)) = elf.strtab.get(sym.st_name) {
                symbols.push(Symbol {
                    name: name.to_string(),
                    vaddr: sym.st_value,
                    size: sym.st_size,
                });
            }
        }
    }

    // Stripped binary fallback: synthesize symbols from `.eh_frame` FDE coverage.
    // Each FDE pins exactly one function with byte size, which is what the protect
    // pipeline needs. Names are synthetic `fn_<vaddr>` since strings are gone.
    if symbols.is_empty() {
        let fdes = discover_via_eh_frame(bytes, &elf);
        log::info!("eh_frame fallback: discovered {} functions via FDEs", fdes.len());
        for (vaddr, size) in fdes {
            symbols.push(Symbol {
                name: format!("fn_{:x}", vaddr),
                vaddr,
                size,
            });
        }
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
