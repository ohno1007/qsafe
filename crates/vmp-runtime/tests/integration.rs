//! Host-side cdylib runtime 集成测试。
//!
//! 不依赖 NDK / 真机；直接在 host x86_64 上 link `qvmp_runtime` rlib，模拟
//! `JNI_OnLoad` 路径的初始化 + dispatch 行为：
//! - `qvmp_runtime_init`：扫不到任何 QVMP blob 也不能 panic
//! - `qvmp_dispatch(no-blob)`：返回 u64::MAX 作 error 哨兵，不 abort
//! - `ProtectFlags::from_env` 在 QVMP_FLAGS 未设置时返回 DEFAULT_HEAVY
//!
//! 这套测试覆盖 cdylib 入口的"启动不崩"基线，避免 sig handler / scan 路径
//! 在某次重构后突然 SIGSEGV 而无人知。

use qvmp_runtime::{qvmp_dispatch, qvmp_runtime_init};

// 集成测试上下文：bypass 重型路径，只测 API 表面 + 反 * 检查。
// 真机端到端测试见 samples/realworld/build_apk.sh。
//
// **重要**：QVMP_DISABLE_CTOR 必须在 .init_array ctor 触发前设上 —— 这意味着用户
// 跑 cargo test 时需要先 `export QVMP_DISABLE_CTOR=1`。我们在测试 binary 里也再设
// 一遍兜底（防止 cargo test 没继承）。如果 ctor 已经跑过，本函数无副作用。
fn ensure_bypass() {
    std::env::set_var("QVMP_DISABLE_CTOR", "1");
    std::env::set_var("QVMP_INIT_BYPASS", "1");
    std::env::set_var("QVMP_FLAGS", "none");
    std::env::set_var("QVMP_RESPONSE", "silent");
}

#[test]
fn init_does_not_panic_without_blob() {
    ensure_bypass();
    qvmp_runtime_init();
    qvmp_runtime_init(); // 二次调用仍然安全（Once 保护）
}

#[test]
fn dispatch_unknown_region_returns_sentinel() {
    ensure_bypass();
    qvmp_runtime_init();
    let r = unsafe { qvmp_dispatch(0xDEAD_BEEF, core::ptr::null(), 0) };
    assert_eq!(r, u64::MAX); // 哨兵值
}

#[test]
fn protect_flags_env_default() {
    std::env::remove_var("QVMP_FLAGS");
    let f = vmp_protect::ProtectFlags::from_env();
    assert!(f.contains(vmp_protect::ProtectFlags::ANTI_DEBUG_PTRACE));
}

#[test]
fn protect_flags_env_paranoid() {
    std::env::set_var("QVMP_FLAGS", "paranoid");
    let f = vmp_protect::ProtectFlags::from_env();
    assert!(f.contains(vmp_protect::ProtectFlags::HWBP_OCCUPY));
    std::env::remove_var("QVMP_FLAGS");
}

#[test]
fn run_checks_does_not_panic_for_lightweight_subset() {
    // 仅启用最轻量的几个，跳过 ptrace_traceme（不可逆 + 影响 cargo test runner）
    let f = vmp_protect::ProtectFlags::ANTI_DEBUG_TRACER_PID
        | vmp_protect::ProtectFlags::ANTI_INJECT_FRIDA
        | vmp_protect::ProtectFlags::ANTI_INJECT_XPOSED
        | vmp_protect::ProtectFlags::ANTI_INJECT_SUBSTRATE
        | vmp_protect::ProtectFlags::ANTI_VM
        | vmp_protect::ProtectFlags::ANTI_EMULATOR;
    let v = vmp_protect::run_checks(f, None);
    let _ = v.any_threat();
}
