//! 导入表（imports.tbl）—— 把 ELF `.dynsym` 中的 import 名字 hash 化后，
//! 把「hash → 原字符串名」的映射写到一段独立的 blob，附在 ELF 末尾。
//! cdylib runtime（`libqvmp_runtime.so`）启动时扫描所有已加载 .so 的导出名，
//! 用同一 hash 算法建立全局表，匹配本 ELF 的 imports.tbl 找到真实地址，
//! 再回填到 .got 完成绑定。
//!
//! 落到 ELF 中的格式（独立 magic 与 payload 分开，不污染 QVMP blob）：
//! ```text
//!   "QIMP"       4B
//!   version u16  = 1
//!   count   u32
//!   entry[count]:
//!      hash u64  (djb2 hash of original UTF-8 name)
//!      orig_name_len u16
//!      orig_name bytes (UTF-8)
//! ```
//!
//! 设计要点：
//! - **轻量 hash**：djb2（init=5381，每字节 `h = h * 33 + c`），输出 64 bit
//! - **不混淆原名**：既然 runtime 必须能恢复原名做 dlsym，必然需要保留原字符串 —— 但
//!   这段保留只在 imports.tbl 内（hash 索引）；ELF `.dynsym/.dynstr` 中的 import 名
//!   全部被替换为 hash 的 hex 字符串，让 `readelf -s` 看到 "h_xxxxxxxx" 而非 `pthread_create`。
//! - **过滤短名 / 必要符号**：动态链接 bootstrap 需要的符号（如 `__libc_start_main`、
//!   `_init`、`_fini`）必须保留原名，否则进程根本起不来。runtime 解析路径只覆盖
//!   "可被运行时再绑定的"符号 —— 这是 *Phase 5* 才能完整启用的能力，本文件只产
//!   出数据 + 默认 disabled。

use byteorder::{ByteOrder, LittleEndian};

/// djb2 64-bit 风格 hash：稳定、低碰撞、可在汇编里 ~10 行实现。
pub fn djb2_hash64(name: &[u8]) -> u64 {
    let mut h: u64 = 5381;
    for &c in name {
        h = h.wrapping_mul(33).wrapping_add(c as u64);
    }
    h
}

/// imports.tbl 一条记录：hash 与原始名（runtime dlsym 用）。
#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub hash: u64,
    pub original_name: String,
}

pub const IMPORTS_MAGIC: &[u8; 4] = b"QIMP";
pub const IMPORTS_VERSION: u16 = 1;

/// 序列化 import 表为字节流（不含外层 ELF 加密）。
pub fn pack_imports(entries: &[ImportEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + entries.len() * 32);
    out.extend_from_slice(IMPORTS_MAGIC);
    out.extend_from_slice(&IMPORTS_VERSION.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.hash.to_le_bytes());
        let bytes = e.original_name.as_bytes();
        out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

/// 反序列化（runtime / inspect 工具用）。
pub fn unpack_imports(data: &[u8]) -> Result<Vec<ImportEntry>, &'static str> {
    if data.len() < 10 || &data[..4] != IMPORTS_MAGIC {
        return Err("QIMP magic mismatch");
    }
    let ver = LittleEndian::read_u16(&data[4..6]);
    if ver != IMPORTS_VERSION {
        return Err("QIMP version unsupported");
    }
    let count = LittleEndian::read_u32(&data[6..10]) as usize;
    let mut p = 10usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if p + 10 > data.len() {
            return Err("QIMP truncated entry");
        }
        let hash = LittleEndian::read_u64(&data[p..p + 8]);
        p += 8;
        let nlen = LittleEndian::read_u16(&data[p..p + 2]) as usize;
        p += 2;
        if p + nlen > data.len() {
            return Err("QIMP truncated name");
        }
        let name = std::str::from_utf8(&data[p..p + nlen])
            .map_err(|_| "QIMP non-utf8 name")?
            .to_string();
        p += nlen;
        out.push(ImportEntry { hash, original_name: name });
    }
    Ok(out)
}

/// 哪些符号必须保留原名（动态链接 bootstrap 阶段用到）—— 即便 hash_imports 启用，
/// 这些符号也跳过。覆盖 glibc / Bionic 的关键 entrypoint。
const PRESERVE_NAMES: &[&str] = &[
    "__libc_start_main",
    "__libc_init",
    "__cxa_finalize",
    "__cxa_atexit",
    "__gmon_start__",
    "_init",
    "_fini",
    "_ITM_registerTMCloneTable",
    "_ITM_deregisterTMCloneTable",
    // dlfcn / dlopen：runtime 自身依赖，先用原生绑定再做 hash 解析
    "dlopen",
    "dlsym",
    "dlclose",
    "dlerror",
    "dl_iterate_phdr",
    // 进程 bootstrap 必须保留
    "abort",
    "exit",
    "_exit",
];

pub fn should_preserve(name: &str) -> bool {
    PRESERVE_NAMES.iter().any(|n| *n == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn djb2_known_values() {
        // 经典 djb2 反例：对空串返回种子 5381。
        assert_eq!(djb2_hash64(b""), 5381);
        // hash 必须确定且分布大致均匀（仅做 sanity check）。
        let h_a = djb2_hash64(b"pthread_create");
        let h_b = djb2_hash64(b"pthread_join");
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let entries = vec![
            ImportEntry { hash: 0x1234, original_name: "malloc".into() },
            ImportEntry { hash: 0x5678, original_name: "pthread_create".into() },
        ];
        let packed = pack_imports(&entries);
        let parsed = unpack_imports(&packed).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].hash, 0x1234);
        assert_eq!(parsed[1].original_name, "pthread_create");
    }

    #[test]
    fn preserve_critical_symbols() {
        assert!(should_preserve("__libc_start_main"));
        assert!(!should_preserve("user_func"));
    }
}
