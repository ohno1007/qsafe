//! 反虚拟机 —— 检测 hypervisor / 通用 VM 痕迹（与 anti_emulator 区分：
//! 后者专攻 Android 模拟器特征；本模块覆盖 KVM / VirtualBox / VMware / Xen / Hyper-V）。
//!
//! ARM64 视角：
//! - `/proc/cpuinfo` 含 `KVM` / `Microsoft` / `Xen` 字样
//! - `/sys/class/dmi/id/sys_vendor` / `bios_vendor` 暴露 VMware / VirtualBox / QEMU
//! - `dmesg` 含 `Booting paravirtualized kernel on KVM` 等串
//!
//! 单一 evidence 不足以下结论；run_checks 把所有 hits 收集后由调用方决定响应。

#[derive(Debug, Clone, Copy)]
pub enum Strategy {
    CpuidHvBit,
    DmiVendorString,
    SmcSelfCheck,
    TimingDilation,
}

pub fn default_strategies() -> Vec<Strategy> {
    vec![
        Strategy::CpuidHvBit,
        Strategy::DmiVendorString,
        Strategy::SmcSelfCheck,
        Strategy::TimingDilation,
    ]
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn detect_vm() -> Vec<&'static str> {
    let mut out = Vec::new();
    if let Ok(s) = std::fs::read_to_string("/proc/cpuinfo") {
        let lower = s.to_lowercase();
        if lower.contains("hypervisor")
            || lower.contains(" kvm ")
            || lower.contains("microsoft hv")
            || lower.contains("xen")
        {
            out.push("cpuinfo_hv");
        }
    }
    for f in &["/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/bios_vendor"] {
        if let Ok(s) = std::fs::read_to_string(f) {
            let lower = s.to_lowercase();
            if lower.contains("vmware")
                || lower.contains("virtualbox")
                || lower.contains("innotek")
                || lower.contains("qemu")
                || lower.contains("xen")
                || lower.contains("microsoft corporation")
            {
                out.push("dmi_vendor");
                break;
            }
        }
    }
    out
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn detect_vm() -> Vec<&'static str> {
    Vec::new()
}
