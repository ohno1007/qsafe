//! libqvmp_runtime — cdylib 运行时分发器。
//!
//! 以 `crate-type = ["cdylib"]` 编译时，本 crate 输出 `libqvmp_runtime.so`
//! （或 Windows `qvmp_runtime.dll`），用法：
//!
//! - **APK 内**：把 `libqvmp_runtime.so` 放入 `lib/arm64-v8a/`，让 `System.loadLibrary`
//!   优先加载。`JNI_OnLoad` 入口注册 SIGTRAP handler，并扫描所有已加载 `.so` 找
//!   `QVMP` magic 解析 blob 表。
//! - **Linux 通用**：用 `LD_PRELOAD=./libqvmp_runtime.so` 启动目标二进制，
//!   `__attribute__((constructor))` 等价的 ctor 在 `dl_init` 期间触发同样初始化。
//! - **Windows**：DllMain DLL_PROCESS_ATTACH 调用同一初始化入口。
//!
//! 当前实现是 **架构骨架**：核心数据结构 + 启动初始化路径 + SIGTRAP 注册都在；
//! 实际 BRK 触发后从 ucontext 恢复寄存器、执行 dispatch_vm、回填寄存器需要架构特化的
//! inline asm，本文件给出 ARM64 的最小可行版本，其它架构留 stub。
//!
//! 设计要点：
//! - 不依赖 `std::sync::Mutex`（cdylib 在 ld_init 阶段不能拿到完整锁服务），用
//!   `OnceLock` + `Vec<Arc<...>>` 的 unsafe 静态布局即可。
//! - **不动 .text 权限**：BRK 触发后我们读 mov x16, #imm 拿到 region_id，
//!   不去改回 BRK 指令；下次 hit 同一函数时 OS 仍发 SIGTRAP，handler 再来一次。
//!   性能略损但可以反 instruction cache scrubbing。
//! - **payload 解密**：vmp-rewriter 用 ELF header 派生的 keystream 加密了 QVMP blob
//!   字节；runtime 必须用同一函数（`vmp_rewriter::derive_payload_key` 复用）逆向。

#![allow(clippy::missing_safety_doc)]

use std::sync::Once;

pub mod page_crypto;
pub mod policy;
pub mod resolver;
pub mod scan;
pub mod sig;

/// 全局初始化入口。`JNI_OnLoad` / `__attribute__((constructor))` / `DllMain`
/// 都在第一次进入时调用本函数。多次调用安全（Once 保护）。
///
/// 顺序：
/// 1. 安装 SIGTRAP handler（VMP BRK 跳板触发后由它接管）
/// 2. 扫描已加载 .so / .exe 找 QVMP / QIMP blob，建立全局 region 表
/// 3. dlsym 解析 imports.tbl 中的 hash → 真实地址
/// 4. 跑反分析检查（按环境变量 / 编译期 flag）；命中威胁触发 [`policy`] 决定的响应
///
/// 测试旁路：设 `QVMP_INIT_BYPASS=1` 时只跑步骤 4 的反分析（不扫模块、不注册
/// 信号 handler）。host 集成测试用此路径避免 dl_iterate_phdr 在 cargo test 的
/// 主二进制（含巨大 debug 段）上耗时数秒。
pub fn qvmp_runtime_init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let bypass = std::env::var_os("QVMP_INIT_BYPASS").is_some();
        if !bypass {
            sig::install_sigtrap_handler();
            scan::scan_loaded_modules();
            resolver::resolve_imports_for_all();
        }

        // 反分析探测：默认从 QVMP_FLAGS env var 读，未设置 = DEFAULT_HEAVY
        let flags = vmp_protect::ProtectFlags::from_env();
        let verdict = vmp_protect::run_checks(flags, None);
        if verdict.any_threat() {
            policy::on_threat(&verdict);
        }
    });
}

// ============================================================================
// JNI 入口（Android）。`System.loadLibrary("qvmp_runtime")` 触发动态链接器调用。
// ============================================================================
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn JNI_OnLoad(
    _vm: *mut core::ffi::c_void,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    qvmp_runtime_init();
    // JNI_VERSION_1_6
    0x0001_0006
}

// ============================================================================
// Linux .so 构造函数（LD_PRELOAD / 普通 dlopen）。
// 用 .init_array 段链接器 hook，比 ctor 名更稳。
// ============================================================================
#[cfg(any(target_os = "linux", target_os = "android"))]
#[link_section = ".init_array"]
#[used]
static QVMP_INIT_CTOR: extern "C" fn() = qvmp_init_ctor;

#[cfg(any(target_os = "linux", target_os = "android"))]
extern "C" fn qvmp_init_ctor() {
    // 测试 / 集成场景设 `QVMP_DISABLE_CTOR=1` 跳过自动 init，由测试代码显式调用
    // qvmp_runtime_init 控制时机。生产 cdylib 部署时此 env 不存在，ctor 正常工作。
    if std::env::var_os("QVMP_DISABLE_CTOR").is_some() {
        return;
    }
    qvmp_runtime_init();
}

// ============================================================================
// Windows DLL 入口
// ============================================================================
#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(
    _hinst: *mut core::ffi::c_void,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        qvmp_runtime_init();
    }
    1
}

// ============================================================================
// 公开 C ABI：用户可在 native 代码里直接调用 `qvmp_dispatch` 触发 VMP 解释器，
// 无需依赖 BRK trap 路径（用于不能注册 SIGTRAP 的环境，例如某些沙箱）。
// ============================================================================
#[no_mangle]
pub unsafe extern "C" fn qvmp_dispatch(
    region_id: u32,
    args: *const u64,
    nargs: usize,
) -> u64 {
    let slice = if args.is_null() || nargs == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(args, nargs.min(8))
    };
    match resolver::dispatch_region(region_id as usize, slice) {
        Ok(v) => v,
        Err(_) => u64::MAX,
    }
}
