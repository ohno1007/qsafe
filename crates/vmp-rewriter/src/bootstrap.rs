//! Bootstrap stub embedded in the hardened ELF's INIT_ARRAY.
//!
//! See `bootstrap.S` for the source asm. The compiled bytes live in
//! `bootstrap.bin`. This module patches four slots at rewrite time:
//!
//!   - `BL <dlopen_plt_vaddr>` at file offset 0xB8
//!   - `.quad embedded_so_runtime_vaddr` at 0xE0
//!   - `.quad embedded_so_len`           at 0xE8
//!   - `.quad xor_key (8 bytes)`         at 0xF0
//!
//! After patching, the bytes are appended to the new LOAD segment alongside
//! the trampolines and the encrypted blob. The bootstrap chunk-decrypts the
//! embedded runtime via the same 8-byte rotating XOR before dlopen-ing it.

use byteorder::{ByteOrder, LittleEndian};

pub const BOOTSTRAP_BIN: &[u8] = include_bytes!("bootstrap.bin");

/// Offset within BOOTSTRAP_BIN of the `BL` instruction that should call
/// dlopen. At assembly time it's a NOP. We rewrite the 4 bytes to a
/// `BL imm26` whose target lands on dlopen's PLT entry.
const BL_DLOPEN_OFFSET: usize = 0xBC;
/// Offset of the .quad cell to fill with the runtime vaddr of the embedded .so.
const SO_ADDR_OFFSET: usize = 0xE8;
/// Offset of the .quad cell to fill with the embedded .so byte count.
const SO_LEN_OFFSET: usize = 0xF0;
/// Offset of the 8-byte rotating XOR key used to decrypt the embedded .so.
const KEY_OFFSET: usize = 0xF8;

/// Patch the bootstrap stub for a specific runtime layout. Returns the
/// finished byte sequence ready to embed.
pub fn patch_bootstrap(
    bootstrap_runtime_vaddr: u64,
    embedded_so_runtime_vaddr: u64,
    embedded_so_len: u64,
    dlopen_plt_vaddr: u64,
    xor_key: u64,
) -> Result<Vec<u8>, crate::RewriteError> {
    let mut bytes = BOOTSTRAP_BIN.to_vec();
    let len = bytes.len();

    // Patch BL → dlopen if the slot exists in this bootstrap variant.
    if BL_DLOPEN_OFFSET + 4 <= len {
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
    }

    if SO_ADDR_OFFSET + 8 <= len {
        LittleEndian::write_u64(
            &mut bytes[SO_ADDR_OFFSET..SO_ADDR_OFFSET + 8],
            embedded_so_runtime_vaddr,
        );
    }
    if SO_LEN_OFFSET + 8 <= len {
        LittleEndian::write_u64(
            &mut bytes[SO_LEN_OFFSET..SO_LEN_OFFSET + 8],
            embedded_so_len,
        );
    }
    if KEY_OFFSET + 8 <= len {
        LittleEndian::write_u64(&mut bytes[KEY_OFFSET..KEY_OFFSET + 8], xor_key);
    }

    Ok(bytes)
}

/// Walk the ELF's `.rela.plt` to find the PLT entry for `dlopen`.
/// Returns the runtime vaddr of that PLT entry, or None if dlopen isn't
/// imported (in which case the caller cannot embed the bootstrap and must
/// fall back to LD_PRELOAD or a separate-file deployment).
pub fn find_dlopen_plt(elf_bytes: &[u8]) -> Option<u64> {
    use goblin::elf::Elf;
    let elf = Elf::parse(elf_bytes).ok()?;

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

    for (idx, rela) in elf.pltrelocs.iter().enumerate() {
        let sym_idx = rela.r_sym;
        let sym = elf.dynsyms.get(sym_idx)?;
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name == "dlopen" {
                return Some(plt_addr + 16 + (idx as u64) * 16);
            }
        }
    }
    None
}

/// XOR-encrypt `so_bytes` with an 8-byte rotating `key`. The bootstrap stub
/// performs the same XOR (per-byte, key index = global offset % 8) on the
/// way out to disk before dlopen.
pub fn xor_runtime(so_bytes: &[u8], key: u64) -> Vec<u8> {
    let key_bytes = key.to_le_bytes();
    so_bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key_bytes[i % 8])
        .collect()
}

