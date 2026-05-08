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

use crate::imports::{djb2_hash64, pack_imports, should_preserve, ImportEntry};
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
    /// hash_imports 启用时产出的 import 表（cdylib runtime 用此做 hash → dlsym 解析）。
    pub imports_table: Vec<ImportEntry>,
    /// imports.tbl 在 ELF 内的字节偏移（0 表示未写入）。
    pub imports_table_offset: u64,
}

/// 对修改后的 ELF 应用 armor。要求 `payload_offset` 指向 `vmp-rewriter::elf_writer`
/// 写入的 "QVMP" magic 起点；payload 字节范围由 magic 后的 u32 长度字段决定。
///
/// 顺序很重要：
/// 1. **hash_imports 必须放在 strip 之前**：依赖 `.dynsym/.dynstr` 名字才能找 import；
///    `strip_symtab` 只清 `.strtab`（debug 名字），不动 `.dynstr`，所以两者不冲突。
/// 2. **strip_symtab 在 strip_shstrtab 之前**：一旦 `.shstrtab` 清空，".strtab" 这个
///    名字就找不到了，因此 strip 顺序固定。
/// 3. **xor_payload 最后**：payload 加密把 ELF header 当 key 派生，要在所有改 ELF 字节
///    的步骤都完成之后再做 —— 否则后续 strip / hash 会破坏 keystream 解出的字节。
pub fn apply_armor(
    elf: &mut [u8],
    payload_offset: u64,
    opts: &ArmorOptions,
) -> Result<ArmorReport> {
    let mut report = ArmorReport::default();

    if opts.hash_imports {
        let (n, table) = hash_dynsym_imports(elf)?;
        report.imports_hashed = n;
        report.imports_table = table;
    }

    if opts.strip_symtab {
        report.strtab_zeroed = strip_section_string_table(elf, ".strtab")?;
    }
    if opts.strip_shstrtab {
        report.shstrtab_zeroed = strip_section_string_table(elf, ".shstrtab")?;
    }
    if opts.xor_payload {
        report.payload_xor_len = encrypt_payload_in_place(elf, payload_offset)?;
    }

    Ok(report)
}

/// 在 ELF 末尾追加 imports.tbl blob（"QIMP" 起头）。返回写入起点的文件偏移。
/// cdylib runtime 启动时通过扫描 PT_LOAD segment 找到 "QIMP" magic 还原表。
pub fn append_imports_table(elf: &mut Vec<u8>, table: &[ImportEntry]) -> u64 {
    if table.is_empty() {
        return 0;
    }
    // 8 字节对齐
    while elf.len() % 8 != 0 {
        elf.push(0);
    }
    let off = elf.len() as u64;
    elf.extend_from_slice(&pack_imports(table));
    off
}

/// 在 ELF 末尾追加完整性 hash（"QHSH" 起头 + SHA-256 of post-rewrite .text）。
/// runtime 通过 dl_iterate_phdr 找 PF_X PT_LOAD，重新算 hash 比对。
///
/// 格式：
/// ```text
/// magic[4] = "QHSH"
/// version u16 = 1
/// hash[32]    SHA-256
/// ```
pub fn append_integrity_hash(elf: &mut Vec<u8>) -> u64 {
    use sha2::{Digest, Sha256};
    use goblin::elf::Elf;
    use goblin::elf::program_header::{PF_X, PT_LOAD};

    let parsed = match Elf::parse(elf) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let mut h = Sha256::new();
    let mut snapshots: Vec<(u64, u64, u64)> = Vec::new();
    for ph in &parsed.program_headers {
        if ph.p_type != PT_LOAD || (ph.p_flags & PF_X) == 0 {
            continue;
        }
        snapshots.push((ph.p_offset, ph.p_filesz, ph.p_memsz));
    }
    drop(parsed);
    for (off, fsz, msz) in snapshots {
        let off = off as usize;
        let fsz = fsz as usize;
        let msz = msz as usize;
        if off + fsz > elf.len() {
            continue;
        }
        h.update(&elf[off..off + fsz]);
        // memsz > filesz 部分（BSS）按零填充也喂给 hash —— 与 runtime
        // dl_iterate_phdr 读 memsz 范围一致。
        if msz > fsz {
            let zeros = vec![0u8; msz - fsz];
            h.update(&zeros);
        }
    }
    let digest = h.finalize();

    // 8 字节对齐
    while elf.len() % 8 != 0 {
        elf.push(0);
    }
    let pos = elf.len() as u64;
    elf.extend_from_slice(b"QHSH");
    elf.extend_from_slice(&1u16.to_le_bytes());
    elf.extend_from_slice(&digest);
    pos
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

/// 派生 payload 加密 key：取 ELF header[0..16] + e_entry + payload_offset 锚字节。
/// runtime 与 rewriter 必须用同一函数 → 抽出来给 cdylib 复用。
pub fn derive_payload_key(elf: &[u8], payload_offset: u64) -> [u8; 32] {
    let off = payload_offset as usize;
    let mut key = [0u8; 32];
    for i in 0..16 {
        key[i] = elf.get(i).copied().unwrap_or(0) ^ ((payload_offset >> (i % 8)) as u8);
    }
    let entry_field = if elf.len() >= 0x20 {
        LittleEndian::read_u64(&elf[0x18..0x20])
    } else {
        0
    };
    for i in 0..8 {
        key[16 + i] = ((entry_field >> (i * 8)) as u8) ^ 0xA5;
    }
    let elf_len = elf.len();
    for i in 0..8 {
        let probe = if elf_len > 0 { (off + i) % elf_len } else { 0 };
        key[24 + i] = elf.get(probe).copied().unwrap_or(0) ^ 0x5A;
    }
    key
}

/// 用派生的 key 对 [start..start+len] 字节做 FNV-1a 派生 keystream XOR。
/// 加解密对称：调用同一函数恢复明文。
pub fn apply_payload_keystream(buf: &mut [u8], key: &[u8; 32]) {
    for (i, b) in buf.iter_mut().enumerate() {
        let mut h: u64 = 0xCBF2_9CE4_8422_2325;
        h ^= key[i % 32] as u64;
        h = h.wrapping_mul(0x100_0000_01B3);
        h ^= (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        h = h.wrapping_mul(0x100_0000_01B3);
        let k = (h >> 32) as u8;
        *b ^= k;
    }
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

    let key = derive_payload_key(elf, payload_offset);
    let payload_start = off + 8;
    apply_payload_keystream(&mut elf[payload_start..payload_start + payload_len], &key);
    Ok(payload_len)
}

/// 扫 `.dynsym`，找 STT_FUNC + UND（即从其他 .so 导入的函数）符号；
/// 计算 djb2 hash → 8 字节十六进制串原地覆盖 `.dynstr` 中的名字字节。
/// 返回 (替换数量, 原始名 → hash 表)。
///
/// 要点：
/// - 仅替换名字长度 ≥ 8 的（保证 hex 串能放下，否则会写出 NUL 截断邻居字符串）
/// - PRESERVE_NAMES 列表中的符号永远跳过（例如 `__libc_start_main` 必须保留原名
///   动态链接器才能初始化进程）
/// - 因为 .dynstr 可能被多个 sym 共享同一字符串偏移，当前实现假设每个 import sym
///   对应**独立**字符串（这是绝大多数链接器的行为；hash 完成后 ELF 仍能用 `objdump -T`
///   读取，但 import 名变成 `h_xxxxxxxx`）。
fn hash_dynsym_imports(elf: &mut [u8]) -> Result<(usize, Vec<ImportEntry>)> {
    use goblin::elf::Elf;
    use goblin::elf::sym::{STT_FUNC, STT_NOTYPE};

    // (dynstr_file_offset, original_name_bytes_offset_in_dynstr, original_name_string)
    struct Plan {
        name_off: usize,        // 文件内绝对偏移（dynstr_file_off + sym.st_name）
        original_len: usize,
        original_name: String,
    }
    let plans: Vec<Plan> = {
        let parsed =
            Elf::parse(elf).map_err(|e| crate::RewriteError::Parse(e.to_string()))?;
        // 找 .dynstr section 的文件偏移
        let dynstr_file_off = parsed
            .section_headers
            .iter()
            .find_map(|sh| {
                let nm = parsed.shdr_strtab.get_at(sh.sh_name)?;
                if nm == ".dynstr" {
                    Some(sh.sh_offset as usize)
                } else {
                    None
                }
            });
        let dynstr_off = match dynstr_file_off {
            Some(o) => o,
            None => return Ok((0, Vec::new())),
        };
        let mut plans = Vec::new();
        for sym in parsed.dynsyms.iter() {
            // 仅 import: UND (st_shndx == 0) 且 type 在 FUNC / NOTYPE（部分 weak ref）
            if sym.st_shndx != 0 {
                continue;
            }
            let stt = sym.st_type();
            if stt != STT_FUNC && stt != STT_NOTYPE {
                continue;
            }
            let name = match parsed.dynstrtab.get_at(sym.st_name) {
                Some(n) => n,
                None => continue,
            };
            if name.is_empty() || should_preserve(name) || name.len() < 8 {
                continue;
            }
            plans.push(Plan {
                name_off: dynstr_off + sym.st_name,
                original_len: name.len(),
                original_name: name.to_string(),
            });
        }
        plans
    };

    let mut table = Vec::with_capacity(plans.len());
    let mut replaced = 0usize;
    for p in &plans {
        let h = djb2_hash64(p.original_name.as_bytes());
        // 16 字节 hex 字符串塞回原字符串槽位；不足填 0。
        let hex = format!("h_{:014x}", h & 0x00FF_FFFF_FFFF_FFFFu64); // 长度恒为 16
        let bytes = hex.as_bytes();
        // 选择稳定写法：写入 min(len, original_len) 然后用 NUL 填到原长，保留终止符。
        let n = bytes.len().min(p.original_len);
        if p.name_off + p.original_len + 1 > elf.len() {
            continue;
        }
        for i in 0..n {
            elf[p.name_off + i] = bytes[i];
        }
        for i in n..p.original_len {
            elf[p.name_off + i] = 0;
        }
        // 保证 NUL 终止符（dynstr 已经在 original_len 处放过 NUL，这里多写一遍稳妥）
        elf[p.name_off + p.original_len] = 0;
        replaced += 1;
        table.push(ImportEntry { hash: h, original_name: p.original_name.clone() });
    }
    Ok((replaced, table))
}
