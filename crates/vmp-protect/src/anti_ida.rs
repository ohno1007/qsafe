//! 反 IDA —— 检测 IDA Pro / Hex-Rays debug server 的痕迹。
//!
//! IDA debug server 在 Linux/Android 上以 `linux_server64` / `android_server64`
//! 进程运行，并且 attach target 后会在 target 进程的 `/proc/self/maps` 留下：
//! - 监听 socket（`tcp:<port>`，默认 23946）
//! - 注入到 target 进程的 stub（`linux_stub` / `android_x64_stub`）
//!
//! 检测实现：
//! 1. 扫 `/proc/<pid>/comm` 看是否有 `linux_server64` / `android_server` 进程
//! 2. 扫自己 `/proc/self/maps` 看是否有 `linux_stub` / `android_x64_stub` 的映射
//! 3. 扫自己的环境变量是否含 `IDA_HOME` / `IDAUSR`
//!
//! 这些都是启发式，IDA 老版本可能漏报；新版本基本命中。

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn detect() -> Vec<&'static str> {
    let mut out = Vec::new();
    if check_maps_for_ida_stub() {
        out.push("ida_stub_in_maps");
    }
    if check_proc_for_ida_server() {
        out.push("ida_server_running");
    }
    if std::env::var("IDA_HOME").is_ok() || std::env::var("IDAUSR").is_ok() {
        out.push("ida_env_var");
    }
    out
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn detect() -> Vec<&'static str> {
    Vec::new()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn check_maps_for_ida_stub() -> bool {
    let s = match std::fs::read_to_string("/proc/self/maps") {
        Ok(s) => s,
        Err(_) => return false,
    };
    s.contains("linux_stub")
        || s.contains("android_x64_stub")
        || s.contains("android_server")
        || s.contains("linux_server")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn check_proc_for_ida_server() -> bool {
    // 扫描 /proc/*/comm —— 性能成本大约 50 us，可接受
    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return false,
    };
    let needles = [
        "linux_server64",
        "linux_server32",
        "android_server",
        "android_x64_server",
        "ida64",
        "ida",
    ];
    for ent in dir.flatten() {
        let name = ent.file_name();
        let n = name.to_string_lossy();
        if !n.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(ent.path().join("comm")) {
            let c = comm.trim();
            if needles.iter().any(|n| c == *n) {
                return true;
            }
        }
    }
    false
}
