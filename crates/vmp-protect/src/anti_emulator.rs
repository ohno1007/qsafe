//! 反 Android 模拟器 —— Genymotion / BlueStacks / Android Studio AVD / Nox / LDPlayer / MuMu。
//!
//! 检测要点（命中任一即视作模拟器）：
//! 1. `ro.kernel.qemu` system property = "1"（AVD 标志，ARM 真机永远 = 0）
//! 2. `/dev/qemu_pipe` / `/dev/socket/qemud` 存在 → AVD goldfish kernel
//! 3. `/system/lib/libdroid4x.so`（droid4x）/ `/system/lib/libnoxd.so`（Nox）
//! 4. `ro.product.cpu.abi` 矛盾：CPU 实际架构与声称的不一致
//! 5. `/proc/cpuinfo` 含 `Hardware : ranchu` / `goldfish`
//! 6. `getprop ro.hardware` 含 `goldfish` / `ranchu`
//!
//! 由于 Android system property 接口在 native 层是 `__system_property_get`（libc.so
//! 导出），通过 dlsym 调用，不需要 NDK header。

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn detect() -> Vec<&'static str> {
    let mut out = Vec::new();
    if check_qemu_pipes() {
        out.push("qemu_pipes");
    }
    if check_emulator_libs() {
        out.push("emulator_libs");
    }
    if check_cpuinfo() {
        out.push("cpuinfo_goldfish");
    }
    if get_prop("ro.kernel.qemu") == Some("1".to_string()) {
        out.push("ro_kernel_qemu");
    }
    if let Some(hw) = get_prop("ro.hardware") {
        if hw.contains("goldfish") || hw.contains("ranchu") || hw.contains("ttvm") {
            out.push("ro_hardware_emu");
        }
    }
    out
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn detect() -> Vec<&'static str> {
    Vec::new()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn check_qemu_pipes() -> bool {
    use std::path::Path;
    Path::new("/dev/qemu_pipe").exists()
        || Path::new("/dev/socket/qemud").exists()
        || Path::new("/dev/goldfish_pipe").exists()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn check_emulator_libs() -> bool {
    use std::path::Path;
    let probes = [
        "/system/lib/libdroid4x.so",
        "/system/lib64/libdroid4x.so",
        "/system/lib/libnoxd.so",
        "/system/lib64/libnoxd.so",
        "/system/lib/libldutils.so",
        "/system/lib64/libldutils.so",
        "/system/bin/qemu-props",
    ];
    probes.iter().any(|p| Path::new(p).exists())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn check_cpuinfo() -> bool {
    let s = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(s) => s,
        Err(_) => return false,
    };
    s.contains("goldfish") || s.contains("ranchu") || s.contains("vbox")
}

/// 通过 Android Bionic 的 `__system_property_get` 拿 system property。
/// 只在 Android 真实环境有意义；普通 Linux 上 dlsym 找不到该符号 → 返回 None。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn get_prop(name: &str) -> Option<String> {
    use core::ffi::c_void;
    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const u8) -> *mut c_void;
    }
    const RTLD_DEFAULT: *mut c_void = core::ptr::null_mut();
    type SysGet =
        unsafe extern "C" fn(name: *const u8, value: *mut u8) -> i32;
    let sym = b"__system_property_get\0";
    let p = unsafe { dlsym(RTLD_DEFAULT, sym.as_ptr()) };
    if p.is_null() {
        return None;
    }
    let func: SysGet = unsafe { core::mem::transmute(p) };
    let mut buf = [0u8; 92]; // PROP_VALUE_MAX
    let mut name_buf: Vec<u8> = name.bytes().collect();
    name_buf.push(0);
    let n = unsafe { func(name_buf.as_ptr(), buf.as_mut_ptr()) };
    if n <= 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n as usize]).to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[allow(dead_code)]
fn get_prop(_: &str) -> Option<String> {
    None
}
