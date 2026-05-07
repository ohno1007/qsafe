//! 反虚拟机/沙盒检测。
//!
//! 与 anti_debug 一致，这里只是策略描述；最终 stub 中实现：
//! - CPUID hypervisor 位（x86）
//! - dmidecode / /sys/class/dmi 检查 VirtualBox / VMware / QEMU 字串
//! - SMC：检测自身代码段是否被 hook
//! - 时间膨胀：rdtsc 前后时间差异常

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
