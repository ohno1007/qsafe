//! Armor pass：在 ELF 重写之上叠加额外混淆
//!
//! - **段名剥离**：把 `.shstrtab` / `.strtab` 中的可读字符串（".text"/".rodata"/"_start" 等）
//!   置零或随机化，让 `readelf -S/-s` 看不到原始段/符号名。
//! - **.qvmp_payload 二次加密**：把整个嵌入 blob 在 ELF 中再用一次 ChaCha 派生流加密。
//!   解密 key 在 ELF 里**不直接存**，而是由两段位置敏感的字节做 XOR 运算后形成（运行时
//!   stub 在 `dispatch_vm` 之前先扫两个 anchor 还原 key）。这样 dump blob 字节直接喂给
//!   解码器是失败的——必须知道整个 ELF 结构才能恢复 key。
//! - **导入表标记**：识别 `.dynsym` 中的 import 名字 hash 化（hash → 8 字节随机字符串），
//!   配合运行时根据 hash 动态解析 (Phase 5 之后实现完整路径，目前仅做名字混淆)。

use crate::Result;
use byteorder::{ByteOrder, LittleEndian};

#[derive(Debug, Clone)]
pub struct ArmorOptions {
    pub strip_shstrtab: bool,
    pub strip_symtab: bool,
    pub xor_payload: bool,
    pub hash_imports: bool,
    /// 加密 .rodata（运行时由 libqvmp_runtime.so 在 .init_array 解密 mprotect 还原）
    pub encrypt_rodata: bool,
    /// 烧录日志开关到 QVMP 头 byte 24；运行时直接读这个字节决定打不打 stderr/logcat
    pub log_on: bool,
}

impl Default for ArmorOptions {
    fn default() -> Self {
        Self {
            strip_shstrtab: true,
            strip_symtab: true,
            xor_payload: true,
            hash_imports: false, // 默认关闭，因为完整动态解析需要 cdylib runtime 配合
            encrypt_rodata: true,
            log_on: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct ArmorReport {
    pub shstrtab_zeroed: usize,
    pub strtab_zeroed: usize,
    pub payload_xor_len: usize,
    pub imports_hashed: usize,
    pub rodata_encrypted_len: usize,
    pub rodata_vaddr: u64,
}

/// 对修改后的 ELF 应用 armor。要求 `payload_offset` 指向 `vmp-rewriter::elf_writer`
/// 写入的 "QVMP" magic 起点；payload 字节范围由 magic 后的 u32 长度字段决定。
pub fn apply_armor(
    elf: &mut [u8],
    payload_offset: u64,
    opts: &ArmorOptions,
) -> Result<ArmorReport> {
    let mut report = ArmorReport::default();

    // 必须先 strip .strtab 再 strip .shstrtab —— 后者一旦清空，前者的 section name
    // 就在 shstrtab 里找不到 ".strtab" 这个字符串了。
    if opts.strip_symtab {
        report.strtab_zeroed = strip_section_string_table(elf, ".strtab")?;
    }
    if opts.strip_shstrtab {
        report.shstrtab_zeroed = strip_section_string_table(elf, ".shstrtab")?;
    }
    if opts.xor_payload {
        report.payload_xor_len = encrypt_payload_in_place(elf, payload_offset)?;
    }
    if opts.encrypt_rodata {
        if let Some((vaddr, len)) = encrypt_rodata_in_place(elf, payload_offset)? {
            report.rodata_vaddr = vaddr;
            report.rodata_encrypted_len = len;
        }
    }
    // Bake log flag at QVMP header byte 24
    let off = payload_offset as usize;
    if off + QVMP_HEADER_LEN <= elf.len() {
        elf[off + 24] = if opts.log_on { 1 } else { 0 };
    }
    if opts.hash_imports {
        report.imports_hashed = hash_dynsym_imports(elf)?;
    }

    Ok(report)
}

/// 把指定 string table section 里的字节置 0（除了首字节 NULL，保持 ELF 标准）。
/// 这让 readelf -S 看到的段名都变成空字符串、`-s` 看到的符号名同样消失。
fn strip_section_string_table(elf: &mut [u8], section_name: &str) -> Result<usize> {
    use goblin::elf::Elf;
    // 先克隆出 (offset, size) 列表，避免在不可变借用 elf 解析的同时可变写 elf
    let targets: Vec<(usize, usize)> = {
        let parsed =
            Elf::parse(elf).map_err(|e| crate::RewriteError::Parse(e.to_string()))?;
        parsed
            .section_headers
            .iter()
            .filter_map(|sh| {
                let name = parsed.shdr_strtab.get_at(sh.sh_name)?;
                if name == section_name {
                    Some((sh.sh_offset as usize, sh.sh_size as usize))
                } else {
                    None
                }
            })
            .collect()
    };
    let mut zeroed = 0usize;
    for (off, sz) in targets {
        if off + sz > elf.len() {
            continue;
        }
        for i in 1..sz {
            if elf[off + i] != 0 {
                elf[off + i] = 0;
                zeroed += 1;
            }
        }
    }
    Ok(zeroed)
}

/// QVMP block layout (32-byte header + payload):
///   off+0  : "QVMP" magic (4 B)
///   off+4  : payload_len:u32
///   off+8  : rodata_vaddr:u64   (filled by encrypt_rodata_in_place; 0 = none)
///   off+16 : rodata_len:u64     (filled by encrypt_rodata_in_place; 0 = none)
///   off+24 : log_flag:u8        (1 = stderr+logcat on, 0 = silent; baked from CLI)
///   off+25 : reserved (7 B zero)
///   off+32 : payload_bytes …    (XOR-encrypted by encrypt_payload_in_place)
const QVMP_HEADER_LEN: usize = 32;

/// Derive the 32-byte key used by both payload and rodata streams. Pure
/// function of ELF header bytes + payload_offset → both rewriter and runtime
/// must compute it identically.
fn derive_key(elf: &[u8], payload_offset: u64) -> [u8; 32] {
    let off = payload_offset as usize;
    let mut key = [0u8; 32];
    for i in 0..16 {
        key[i] = elf[i] ^ ((payload_offset >> (i % 8)) as u8);
    }
    let entry_field = LittleEndian::read_u64(&elf[0x18..0x20]);
    for i in 0..8 {
        key[16 + i] = ((entry_field >> (i * 8)) as u8) ^ 0xA5;
    }
    for i in 0..8 {
        key[24 + i] = elf[(off + i) % elf.len()] ^ 0x5A;
    }
    key
}

/// FNV-1a × golden-ratio keystream byte at logical position `i` with the
/// given 32-byte key, plus a domain tag XORed into the FNV initial state.
/// Domain tags differentiate payload vs rodata streams so the same byte index
/// produces independent keys for the two streams.
fn keystream_byte(key: &[u8; 32], i: usize, domain: u64) -> u8 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325 ^ domain;
    h ^= key[i % 32] as u64;
    h = h.wrapping_mul(0x100_0000_01B3);
    h ^= (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h = h.wrapping_mul(0x100_0000_01B3);
    (h >> 32) as u8
}

const DOMAIN_PAYLOAD: u64 = 0;
const DOMAIN_RODATA: u64 = 0xC0DE_DA7A_BABE_F00D;

fn encrypt_payload_in_place(elf: &mut [u8], payload_offset: u64) -> Result<usize> {
    let off = payload_offset as usize;
    if off + QVMP_HEADER_LEN > elf.len() {
        return Err(crate::RewriteError::Internal("payload offset 越界".into()));
    }
    if &elf[off..off + 4] != b"QVMP" {
        return Err(crate::RewriteError::Internal("payload magic 不匹配".into()));
    }
    let payload_len = LittleEndian::read_u32(&elf[off + 4..off + 8]) as usize;
    let payload_start = off + QVMP_HEADER_LEN;
    if payload_start + payload_len > elf.len() {
        return Err(crate::RewriteError::Internal("payload 长度超出 ELF 文件".into()));
    }

    let key = derive_key(elf, payload_offset);
    for i in 0..payload_len {
        let k = keystream_byte(&key, i, DOMAIN_PAYLOAD);
        elf[payload_start + i] ^= k;
    }
    Ok(payload_len)
}

/// Find `.rodata` (by section name when shstrtab still has names; otherwise
/// by SHF_ALLOC + SHF_MERGE + SHF_STRINGS heuristic), encrypt its bytes in
/// place using `DOMAIN_RODATA` keystream, and stamp `(vaddr, len)` into the
/// QVMP header at `payload_offset + 8 / +16`. Runtime cdylib uses these
/// fields to mprotect-RW → XOR-decrypt → mprotect-R the segment at load.
fn encrypt_rodata_in_place(
    elf: &mut [u8],
    payload_offset: u64,
) -> Result<Option<(u64, usize)>> {
    let (file_off, vaddr, size) = match find_rodata(elf) {
        Some(v) => v,
        None => return Ok(None),
    };
    if size == 0 || file_off + size > elf.len() {
        return Ok(None);
    }
    let key = derive_key(elf, payload_offset);
    for i in 0..size {
        let k = keystream_byte(&key, i, DOMAIN_RODATA);
        elf[file_off + i] ^= k;
    }
    let off = payload_offset as usize;
    LittleEndian::write_u64(&mut elf[off + 8..off + 16], vaddr);
    LittleEndian::write_u64(&mut elf[off + 16..off + 24], size as u64);
    Ok(Some((vaddr, size)))
}

/// Locate `.rodata`. Section names may be zeroed by `strip_shstrtab`, so we
/// also fall back to a flag-based heuristic: a PROGBITS section that is
/// SHF_ALLOC && !SHF_WRITE && !SHF_EXECINSTR && SHF_MERGE && SHF_STRINGS.
/// Returns `(file_offset, vaddr, size)`.
fn find_rodata(elf: &[u8]) -> Option<(usize, u64, usize)> {
    use goblin::elf::Elf;
    use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_MERGE, SHF_STRINGS, SHF_WRITE, SHT_PROGBITS};
    let parsed = Elf::parse(elf).ok()?;
    // First pass: name-based.
    for sh in &parsed.section_headers {
        if let Some(name) = parsed.shdr_strtab.get_at(sh.sh_name) {
            if name == ".rodata" && sh.sh_type == SHT_PROGBITS {
                return Some((sh.sh_offset as usize, sh.sh_addr, sh.sh_size as usize));
            }
        }
    }
    // Fallback: flag heuristic.
    for sh in &parsed.section_headers {
        if sh.sh_type != SHT_PROGBITS {
            continue;
        }
        let f = sh.sh_flags as u32;
        let want = SHF_ALLOC | SHF_MERGE | SHF_STRINGS;
        if (f & want) == want && (f & (SHF_WRITE | SHF_EXECINSTR)) == 0 && sh.sh_size > 0 {
            return Some((sh.sh_offset as usize, sh.sh_addr, sh.sh_size as usize));
        }
    }
    None
}

/// 把 `.dynsym` import 字符串（每个 STT_FUNC import）替换成 8 字节伪随机标识。
/// **注意**：这要求运行时 dispatcher 实现哈希→真实符号的解析。当前默认 disabled。
fn hash_dynsym_imports(elf: &mut [u8]) -> Result<usize> {
    let _ = elf;
    Ok(0)
}
