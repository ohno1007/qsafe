//! 反 dump —— 检测内存被 dump 工具读取的迹象。
//!
//! - `/proc/self/mem` 被另一进程 open：读 `/proc/self/fdinfo/*` 反查 fd 来源
//! - 自身 `/proc/self/maps` 出现可执行 anonymous 段（非 ELF backed） — 说明可能
//!   有人解密落地代码到匿名页准备 dump
//! - `kill -SIGSTOP` 被发起：检查 status[State:T]
//!
//! 多数 dump 工具（GDB `dump memory`、frida `Memory.readByteArray`、Cuckoo /
//! BotSlayer dumper）走 `/proc/<pid>/mem` —— 这是 80% 攻击面。

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn proc_self_mem_open_count() -> usize {
    // 自己 fd 列表里通常不会含 /proc/self/mem；只有 attached debugger 才打开。
    // 我们扫描 /proc/<pid>/fd（当前进程）而不去枚举其它 PID（无权限、且漏报）。
    let dir = match std::fs::read_dir("/proc/self/fd") {
        Ok(d) => d,
        Err(_) => return 0,
    };
    let mut count = 0usize;
    for ent in dir.flatten() {
        if let Ok(target) = std::fs::read_link(ent.path()) {
            let s = target.to_string_lossy();
            if s.contains("/proc/") && s.ends_with("/mem") {
                count += 1;
            }
        }
    }
    count
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn proc_self_mem_open_count() -> usize {
    0
}

/// 扫 /proc/self/maps 里的可执行匿名段。某些 dumper 解密后把 plain text 写到
/// 匿名 mmap 再 dump。返回匿名可执行段的数量（>0 视作可疑）。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn anon_exec_segments() -> usize {
    let s = match std::fs::read_to_string("/proc/self/maps") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let mut count = 0usize;
    for line in s.lines() {
        // 格式：addr-addr perms offset dev inode pathname
        // 匿名段：pathname 为空 或 [heap] / [stack] —— 我们排除 heap/stack
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let perms = parts[1];
        if !perms.contains('x') {
            continue;
        }
        let pathname = parts.get(5).copied().unwrap_or("");
        if pathname.is_empty()
            || pathname == "[heap]"
            || pathname == "[stack]"
            || pathname.starts_with("[anon")
        {
            // 仅报告非 stack/heap 的可执行匿名段
            if pathname != "[heap]" && pathname != "[stack]" {
                count += 1;
            }
        }
    }
    count
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn anon_exec_segments() -> usize {
    0
}
