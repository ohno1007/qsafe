use crate::{BinaryKind, LoadedObject};
use goblin::pe::PE;
use vmp_core::{Arch, CodeRegion, Error, ObjectFormat, Os, Result, Symbol};

pub fn parse(bytes: &[u8], pe: PE, format: ObjectFormat) -> Result<LoadedObject> {
    let arch = match pe.header.coff_header.machine {
        0x8664 => Arch::X86_64,
        0x14C => Arch::X86,
        0xAA64 => Arch::Arm64,
        0x1C0 | 0x1C2 | 0x1C4 => Arch::Arm32,
        m => return Err(Error::parse(format!("PE 未知架构: 0x{:x}", m))),
    };
    let os = Os::Windows;

    let mut code = Vec::new();
    for s in &pe.sections {
        let chars = s.characteristics;
        const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        if chars & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0 && s.size_of_raw_data > 0 {
            let start = s.pointer_to_raw_data as usize;
            let end = start + s.size_of_raw_data as usize;
            if end > bytes.len() {
                continue;
            }
            code.push(CodeRegion {
                vaddr: pe.image_base as u64 + s.virtual_address as u64,
                bytes: bytes[start..end].to_vec(),
            });
        }
    }

    let mut symbols = Vec::new();
    for export in &pe.exports {
        if let Some(name) = &export.name {
            symbols.push(Symbol {
                name: (*name).to_string(),
                vaddr: pe.image_base as u64 + export.rva as u64,
                size: export.size as u64,
            });
        }
    }

    let kind = if pe.is_lib {
        BinaryKind::SharedObject
    } else {
        BinaryKind::Executable
    };

    Ok(LoadedObject {
        arch,
        os,
        format,
        kind,
        code,
        symbols,
        entry: pe.entry as u64,
        raw: bytes.to_vec(),
    })
}
