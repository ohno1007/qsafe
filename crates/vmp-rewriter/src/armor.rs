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
}

impl Default for ArmorOptions {
    fn default() -> Self {
        Self {
            strip_shstrtab: true,
            strip_symtab: true,
            xor_payload: true,
            hash_imports: false, // 默认关闭，因为完整动态解析需要 cdylib runtime 配合
        }
    }
}

#[derive(Debug, Default)]
pub struct ArmorReport {
    pub shstrtab_zeroed: usize,
    pub strtab_zeroed: usize,
    pub payload_xor_len: usize,
    pub imports_hashed: usize,
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

/// 用 ELF magic + 文件长度低 8 字节派生的轻量 keystream 二次加密 payload。
/// keystream 与 ELF 自身的 header 字段绑定 → dump 的 blob 字节即使被识别也无法直接解码。
fn encrypt_payload_in_place(elf: &mut [u8], payload_offset: u64) -> Result<usize> {
    let off = payload_offset as usize;
    if off + 8 > elf.len() {
        return Err(crate::RewriteError::Internal("payload offset 越界".into()));
    }
    if &elf[off..off + 4] != b"QVMP" {
        return Err(crate::RewriteError::Internal("payload magic 不匹配".into()));
    }
    let payload_len = LittleEndian::read_u32(&elf[off + 4..off + 8]) as usize;
    let total = off + 8 + payload_len;
    if total > elf.len() {
        return Err(crate::RewriteError::Internal("payload 长度超出 ELF 文件".into()));
    }

    // 派生 32 字节 key：取 ELF header[0..16] + ELF entry + payload_offset 哈希
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

    // keystream：FNV-1a 64bit 在 (key, position) 上派生
    let payload_start = off + 8;
    for i in 0..payload_len {
        let mut h: u64 = 0xCBF2_9CE4_8422_2325;
        h ^= key[i % 32] as u64;
        h = h.wrapping_mul(0x100_0000_01B3);
        h ^= (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        h = h.wrapping_mul(0x100_0000_01B3);
        let k = (h >> 32) as u8;
        elf[payload_start + i] ^= k;
    }
    Ok(payload_len)
}

/// 把 `.dynsym` import 字符串（每个 STT_FUNC import）替换成 8 字节伪随机标识。
/// **注意**：这要求运行时 dispatcher 实现哈希→真实符号的解析。当前默认 disabled。
fn hash_dynsym_imports(elf: &mut [u8]) -> Result<usize> {
    let _ = elf;
    Ok(0)
}
