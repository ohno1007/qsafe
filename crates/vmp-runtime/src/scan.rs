//! 扫描已加载模块（已载入进程的 .so / .exe），找出嵌在末尾的 QVMP / QIMP blob。
//!
//! Linux 路径：`dl_iterate_phdr` 遍历 `link_map`，对每个模块的 PT_LOAD segment
//! 在内存映射里搜索 magic（4 字节 `b"QVMP"` / `b"QIMP"`）。找到后：
//! - QVMP：解密 payload → 调 `vmp_stub::unpack_blob` → 缓存 (region_id → blob/PC)
//! - QIMP：解析 imports 表 → 与本进程 dlsym 解析 → 缓存 hash → 真实地址
//!
//! 平台支持：当前只在 Linux / Android 启用真实扫描；Windows / macOS 留 stub。
//! 数据结构走 `unsafe` 静态可变 + `Once` 初始化（cdylib 内 std::sync::Mutex 在
//! ld_init 阶段不可用，会 deadlock 在 std runtime 启动）。

use std::sync::OnceLock;
use vmp_stub::StubBlob;

/// 一个被发现的 QVMP payload 描述。
pub struct DiscoveredBlob {
    /// 模块基址（dl_phdr_info::dlpi_addr）
    pub module_base: u64,
    /// payload 在内存中的起点（即 'QVMP' magic 第一个字节地址）
    pub payload_va: u64,
    /// 所属模块的 ELF header 起点（解密 key 派生需要）
    pub elf_header_va: u64,
    /// 解密后的 blob
    pub blob: StubBlob,
}

static DISCOVERED: OnceLock<Vec<DiscoveredBlob>> = OnceLock::new();

pub fn scan_loaded_modules() {
    let _ = DISCOVERED.set(scan_impl());
}

pub fn discovered() -> &'static [DiscoveredBlob] {
    DISCOVERED.get().map(|v| v.as_slice()).unwrap_or(&[])
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn scan_impl() -> Vec<DiscoveredBlob> {
    use core::ffi::c_void;
    extern "C" {
        fn dl_iterate_phdr(
            cb: extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> i32,
            data: *mut c_void,
        ) -> i32;
    }

    #[repr(C)]
    struct DlPhdrInfo {
        dlpi_addr: usize,
        dlpi_name: *const u8,
        dlpi_phdr: *const u8,
        dlpi_phnum: u16,
        // 后面字段不用
    }

    extern "C" fn cb(info: *mut DlPhdrInfo, _size: usize, data: *mut c_void) -> i32 {
        unsafe {
            let out = &mut *(data as *mut Vec<DiscoveredBlob>);
            let info = &*info;
            let elf_header_va = info.dlpi_addr as u64;
            // 扫每个 PT_LOAD：基地址 + p_vaddr，长度 p_memsz
            // ARM64 ELF64 program header = 56 字节
            for i in 0..(info.dlpi_phnum as isize) {
                let phdr = info.dlpi_phdr.offset(i * 56);
                let p_type = core::ptr::read_unaligned(phdr as *const u32);
                if p_type != 1 {
                    // PT_LOAD = 1
                    continue;
                }
                let p_vaddr = core::ptr::read_unaligned((phdr as *const u8).offset(16) as *const u64);
                let p_memsz = core::ptr::read_unaligned((phdr as *const u8).offset(40) as *const u64);
                let seg_va = (info.dlpi_addr as u64).wrapping_add(p_vaddr);
                if let Some(blob) = try_extract_qvmp(elf_header_va, seg_va, p_memsz) {
                    out.push(blob);
                }
            }
        }
        0
    }

    let mut out: Vec<DiscoveredBlob> = Vec::new();
    unsafe {
        dl_iterate_phdr(cb, &mut out as *mut _ as *mut c_void);
    }
    out
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn scan_impl() -> Vec<DiscoveredBlob> {
    // Windows / macOS：留 stub，待 Phase 5 用 EnumProcessModules / dyld API 实现
    Vec::new()
}

/// 在一段内存范围内搜 QVMP magic，命中后：
/// 1. 读 4 字节 length
/// 2. 拷贝出 `length` 字节 payload
/// 3. 用 ELF header 派生 key 解密
/// 4. unpack_blob 还原 StubBlob
#[cfg(any(target_os = "linux", target_os = "android"))]
fn try_extract_qvmp(elf_header_va: u64, seg_va: u64, seg_len: u64) -> Option<DiscoveredBlob> {
    use byteorder::{ByteOrder, LittleEndian};

    if seg_len < 8 {
        return None;
    }
    // 单段最大扫描量限制：rewriter 把 QVMP blob 写到末尾追加的 PT_LOAD，所以从段尾
    // 往前找比从头扫快得多。同时 cap 在 16MB —— 商用 .so 极少超过这个体积；超出
    // 部分极可能不是 QVMP 段，跳过避免 host 上 dl_iterate_phdr 把 cargo test 的
    // 巨大主二进制（debug 信息）当作扫描目标导致几秒延迟。
    const SCAN_CAP: u64 = 16 * 1024 * 1024;
    let cap_len = seg_len.min(SCAN_CAP) as usize;
    let bytes = unsafe { core::slice::from_raw_parts(seg_va as *const u8, cap_len) };

    // 从尾部扫起：rewriter 写 QVMP 在新追加 PT_LOAD 内，离段起点很远。
    let mut magic_off: Option<usize> = None;
    for i in (0..bytes.len().saturating_sub(4)).rev().step_by(4) {
        if &bytes[i..i + 4] == b"QVMP" {
            magic_off = Some(i);
            break;
        }
    }
    let off = magic_off?;
    if off + 8 > bytes.len() {
        return None;
    }
    let len = LittleEndian::read_u32(&bytes[off + 4..off + 8]) as usize;
    if off + 8 + len > bytes.len() {
        return None;
    }
    // payload 在内存里仍是加密形态。复制出来后用 ELF header 字节派生 key 解密。
    let payload_va = seg_va.wrapping_add(off as u64);
    let payload_offset_in_elf = payload_va.wrapping_sub(elf_header_va);
    let elf_header_slice = unsafe {
        // ELF header + e_phoff = 64 bytes，取前 256 字节足够（对齐到 0x1000 边界，但
        // 实际只用前 32 字节做 key 派生）
        core::slice::from_raw_parts(elf_header_va as *const u8, 256.min(seg_len as usize))
    };

    let key = vmp_rewriter::armor::derive_payload_key(elf_header_slice, payload_offset_in_elf);
    let mut buf = bytes[off + 8..off + 8 + len].to_vec();
    vmp_rewriter::armor::apply_payload_keystream(&mut buf, &key);

    let blob = vmp_stub::unpack_blob(&buf).ok()?;
    Some(DiscoveredBlob {
        module_base: elf_header_va,
        payload_va,
        elf_header_va,
        blob,
    })
}
