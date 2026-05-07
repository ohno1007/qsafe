//! 反脱壳 —— 校验代码段完整性。
//!
//! 思路：在 build 阶段把 `.text` SHA-256 写入 `expected_text_hash`；运行时
//! 重新计算并比对。若 dumper 在内存里替换了一段 .text（例如手工补丁），hash 会变。
//!
//! 实现：
//! - 自身 .so 的 .text 范围通过 `dl_iterate_phdr` + ELF parse 得到
//! - 选第一个 PT_LOAD r-x 段做 SHA-256
//! - 与 build-time embed 的 hash 比对
//!
//! 注意：当 vmp-rewriter 写跳板覆盖原 .text 时，hash 校验也得在跳板写入之后做；
//! 否则永远不通过。所以 `expected_text_hash` 应该是 *post-rewrite* 的 hash，由
//! rewriter 在 emit 后计算并嵌入到 ProtectionPlan。

use crate::integrity::sha256;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn verify_text_hash(expected: &[u8; 32]) -> bool {
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
    }

    extern "C" fn cb(info: *mut DlPhdrInfo, _size: usize, data: *mut c_void) -> i32 {
        unsafe {
            let info = &*info;
            // 仅处理主程序（dlpi_name 通常是空串或 process path）
            for i in 0..(info.dlpi_phnum as isize) {
                let phdr = info.dlpi_phdr.offset(i * 56);
                let p_type = core::ptr::read_unaligned(phdr as *const u32);
                let p_flags = core::ptr::read_unaligned((phdr as *const u8).offset(4) as *const u32);
                if p_type != 1 {
                    continue;
                }
                // PF_X = 1
                if p_flags & 1 == 0 {
                    continue;
                }
                let p_vaddr = core::ptr::read_unaligned((phdr as *const u8).offset(16) as *const u64);
                let p_memsz = core::ptr::read_unaligned((phdr as *const u8).offset(40) as *const u64);
                let va = (info.dlpi_addr as u64).wrapping_add(p_vaddr);
                let bytes = core::slice::from_raw_parts(va as *const u8, p_memsz as usize);
                let hash = crate::integrity::sha256(bytes);
                let out = data as *mut [u8; 32];
                *out = hash;
                return 1; // 停止迭代
            }
            0
        }
    }

    let mut got = [0u8; 32];
    unsafe {
        dl_iterate_phdr(cb, (&mut got) as *mut [u8; 32] as *mut c_void);
    }
    &got == expected
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn verify_text_hash(_expected: &[u8; 32]) -> bool {
    // host 侧无 dl_iterate_phdr 等 ELF API：保持兼容，假定通过
    true
}

/// 一个简单的接口：给一段 buf 算 sha256，方便外部 API 复用 integrity 路径。
pub fn hash_buf(buf: &[u8]) -> [u8; 32] {
    sha256(buf)
}
