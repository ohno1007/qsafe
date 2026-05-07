use crate::{BinaryKind, LoadedObject};
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
