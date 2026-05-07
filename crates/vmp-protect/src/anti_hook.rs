//! 反 hook —— 检测 PLT/GOT 修改 / inline hook（Frida-gum trampoline / xhook）。
//!
//! 思路：
//! 1. **PLT/GOT 校验**：扫 /proc/self/maps 找到本 .so 的范围 → 解析 ELF 找 .got.plt
//!    section → 校验每个条目指向的地址落在某个已知 .so 范围内（合理）。
//!    - frida-gum 的 PLT hook 把 GOT 指向自己的 trampoline（在匿名映射里）→ 命中
//! 2. **Inline hook**：抽样几个高频 libc 函数（malloc / open / read），读取首 16 字节
//!    判断是否是 Frida 经典签名（`58 00 00 58` LDR x0, =trampoline_addr 模式 +
//!    `c0 03 5f d6` BR）。
//!
//! 当前实现是 MVP：检测最常见两类。完整能力（含 GOT 全量交叉验证）留给 Phase 5。

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn plt_got_modified() -> bool {
    // 启发式：读 /proc/self/maps 找匿名 r-x 段（非 .so）—— frida-gum 的 trampoline
    // 池就在这里。anon_exec_segments() == 0 说明无 hook。
    crate::anti_dump::anon_exec_segments() > 0
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn plt_got_modified() -> bool {
    false
}

/// 扫一个已知 libc 函数（例如 `dlsym`）首 16 字节，看是否被 inline-hook（多数 hook
/// 框架在这里写 `LDR + BR` 跳板，签名比较稳定）。
///
/// 取 `dlsym` 是因为它对所有 .so 都可用、且 frida 启动时会 hook 它。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn inline_hook_in_libc() -> bool {
    use core::ffi::c_void;
    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const u8) -> *mut c_void;
    }
    const RTLD_DEFAULT: *mut c_void = core::ptr::null_mut();

    // 探针函数：dlsym 自身。dlsym 是 libdl 导出，frida 多数会 hook 它做 stalker。
    let probe_name = b"dlsym\0";
    let addr = unsafe { dlsym(RTLD_DEFAULT, probe_name.as_ptr()) };
    if addr.is_null() {
        return false;
    }
    // 读首 16 字节
    let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, 16) };
    // ARM64：常规 prologue 是 stp x29, x30, [sp, #-16]!（0xa9bf7bfd）等；
    // frida trampoline 把首条改成 `LDR x16, =target` (0x58 0x00 0x00 0x58 模式) 或
    // 直接 `B imm26`（0x14000000 / 0x17000000 高位）—— 后者是高频 inline-hook 模式。
    if bytes.len() < 4 {
        return false;
    }
    let inst = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    // B imm26: 0x14000000 (op=0); BL imm26: 0x94000000
    let top6 = inst >> 26;
    if top6 == 0b000101 || top6 == 0b100101 {
        return true;
    }
    // LDR (literal): 0_x_011_0_00 ...（固定位 0x58 起始字节）
    if bytes[3] & 0xBF == 0x18 || bytes[3] == 0x58 {
        return true;
    }
    false
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn inline_hook_in_libc() -> bool {
    false
}
