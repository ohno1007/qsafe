//! Bootstrap stub embedded in the hardened ELF's INIT_ARRAY.
//!
//! See `bootstrap.S` for the source asm. The compiled bytes live in
//! `bootstrap.bin`. This module patches three slots at rewrite time:
//!
//!   - `BL <dlopen_plt_vaddr>` at file offset 0x58
//!   - `.quad embedded_so_runtime_vaddr` at 0x80
//!   - `.quad embedded_so_len`           at 0x88
//!
//! After patching, the bytes are appended to the new LOAD segment alongside
//! the trampolines and the encrypted blob.

use byteorder::{ByteOrder, LittleEndian};

pub const BOOTSTRAP_BIN: &[u8] = include_bytes!("bootstrap.bin");

/// Offset within BOOTSTRAP_BIN of the `BL` instruction that should call
/// dlopen. At assembly time it's a NOP (0xd503201f). We rewrite the 4 bytes
/// to a `BL imm26` whose target lands on dlopen's PLT entry.
const BL_DLOPEN_OFFSET: usize = 0x58;
/// Offset of the .quad cell to fill with the runtime vaddr of the embedded .so.
const SO_ADDR_OFFSET: usize = 0x80;
/// Offset of the .quad cell to fill with the embedded .so byte count.
const SO_LEN_OFFSET: usize = 0x88;

/// Patch the bootstrap stub for a specific runtime layout. Returns the
/// finished byte sequence ready to embed.
pub fn patch_bootstrap(
    bootstrap_runtime_vaddr: u64,
    embedded_so_runtime_vaddr: u64,
    embedded_so_len: u64,
    dlopen_plt_vaddr: u64,
) -> Result<Vec<u8>, crate::RewriteError> {
    let mut bytes = BOOTSTRAP_BIN.to_vec();

    // BL imm26: opcode 100101 + imm26.  imm26 = (target - pc) / 4, in ±128 MB.
    let bl_pc = bootstrap_runtime_vaddr.wrapping_add(BL_DLOPEN_OFFSET as u64);
    let delta = dlopen_plt_vaddr as i64 - bl_pc as i64;
    if delta % 4 != 0 {
        return Err(crate::RewriteError::Internal(
            "dlopen PLT not 4-byte aligned".into(),
        ));
    }
    let imm26 = delta / 4;
    if !(-(1 << 25)..(1 << 25)).contains(&imm26) {
        return Err(crate::RewriteError::BranchTooFar);
    }
    let bl_word = 0x94_00_00_00u32 | ((imm26 as u32) & 0x03ff_ffff);
    LittleEndian::write_u32(
        &mut bytes[BL_DLOPEN_OFFSET..BL_DLOPEN_OFFSET + 4],
        bl_word,
    );

    LittleEndian::write_u64(
        &mut bytes[SO_ADDR_OFFSET..SO_ADDR_OFFSET + 8],
        embedded_so_runtime_vaddr,
    );
    LittleEndian::write_u64(
        &mut bytes[SO_LEN_OFFSET..SO_LEN_OFFSET + 8],
        embedded_so_len,
    );

    Ok(bytes)
}

/// Walk the ELF's `.rela.plt` to find the PLT entry for `dlopen`.
/// Returns the runtime vaddr of that PLT entry, or None if dlopen isn't
/// imported (in which case the caller cannot embed the bootstrap and must
/// fall back to LD_PRELOAD or a separate-file deployment).
pub fn find_dlopen_plt(elf_bytes: &[u8]) -> Option<u64> {
    use goblin::elf::Elf;
    let elf = Elf::parse(elf_bytes).ok()?;

    // `.plt` section base + entry size. AArch64 PLT entries are 16 bytes,
    // and PLT[0] is the resolver — actual import stubs start at PLT[1].
    let mut plt_addr: u64 = 0;
    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name == ".plt" {
                plt_addr = sh.sh_addr;
                break;
            }
        }
    }
    if plt_addr == 0 {
        return None;
    }

    // Iterate JMPREL relocations in order; the i-th JUMP_SLOT corresponds to
    // PLT entry (i + 1) for AArch64.
    for (idx, rela) in elf.pltrelocs.iter().enumerate() {
        let sym_idx = rela.r_sym;
        let sym = elf.dynsyms.get(sym_idx)?;
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name == "dlopen" {
                // PLT entry idx+1, each 16 bytes
                return Some(plt_addr + 16 + (idx as u64) * 16);
            }
        }
    }
    None
}
