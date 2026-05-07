//! 反注入 —— 检测 frida-server / xposed / substrate 注入。
//!
//! 思路：扫 `/proc/self/maps`，匹配每种框架特征文件名：
//! - frida：`libfrida-agent.so`、`linjector` 内置 stub、`gum-js-loop` 线程名
//! - xposed：`/system/framework/xposed.jar`、`xposed_art` 库
//! - substrate (Cydia / Substrate Tweaks)：`libsubstrate.so`、`MSHookFunction`
//!
//! 性能成本：单次 read 整段 `/proc/self/maps`（一般几十 KB），strstr ~10 us。

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_maps() -> Option<String> {
    std::fs::read_to_string("/proc/self/maps").ok()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn frida_in_maps() -> bool {
    let s = match read_maps() {
        Some(s) => s,
        None => return false,
    };
    s.contains("libfrida")
        || s.contains("frida-agent")
        || s.contains("linjector-")
        || s.contains("gum-js-loop")
        || frida_thread_name()
        || frida_listening_port()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn frida_in_maps() -> bool {
    false
}

/// frida-server / frida-gadget 的主线程通常叫 "gmain" / "gum-js-loop"；
/// 自身进程的线程名表暴露在 /proc/self/task/<tid>/comm。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn frida_thread_name() -> bool {
    let dir = match std::fs::read_dir("/proc/self/task") {
        Ok(d) => d,
        Err(_) => return false,
    };
    for ent in dir.flatten() {
        if let Ok(comm) = std::fs::read_to_string(ent.path().join("comm")) {
            let c = comm.trim();
            if c == "gum-js-loop" || c == "gmain" || c == "linjector-cli" || c == "frida-srv-mai" {
                return true;
            }
        }
    }
    false
}

/// frida-server 默认在 27042 端口监听。读 /proc/net/tcp 快速判断。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn frida_listening_port() -> bool {
    // /proc/net/tcp 行格式：" sl local_address rem_address st ..."
    // local_address = "00000000:69A2"（大端 hex，27042 = 0x69A2）
    let s = match std::fs::read_to_string("/proc/net/tcp") {
        Ok(s) => s,
        Err(_) => return false,
    };
    // 匹配 :69A2 监听
    s.contains(":69A2") && s.lines().any(|l| l.contains(":69A2") && l.contains(" 0A "))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn xposed_in_maps() -> bool {
    let s = match read_maps() {
        Some(s) => s,
        None => return false,
    };
    s.contains("xposed")
        || s.contains("XposedBridge")
        || s.contains("LSPosed")
        || s.contains("EdXposed")
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn xposed_in_maps() -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn substrate_in_maps() -> bool {
    let s = match read_maps() {
        Some(s) => s,
        None => return false,
    };
    s.contains("libsubstrate.so")
        || s.contains("CydiaSubstrate")
        || s.contains("MSHookFunction")
        || s.contains("substrate-loader")
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn substrate_in_maps() -> bool {
    false
}
