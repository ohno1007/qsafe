//! Linux 主机桥接：通过 `svc #0` 真实下发系统调用 + 直接读写宿主进程地址空间。
//!
//! 仅在 `target_os = "linux"` 上启用。aarch64 / x86_64 / arm 共用同一接口，但 `raw_syscall`
//! 由架构特化（这里仅实现 aarch64；新增其它架构按 ARM ABI 模式照葫芦画瓢即可）。

use vmp_core::{Error, Result};
use vmp_interpreter::HostBridge;
use vmp_isa::Width;

pub struct LinuxHost {
    pub allow_raw_memory: bool,
    /// dispatch_vm 总耗时基准（new 时刻），用于在 sys_exit 时打印 VMP 总损耗
    pub start: std::time::Instant,
    /// 缓存 /proc/self/maps 中的可执行段区间，懒加载。
    exec_ranges: Vec<(u64, u64)>,
}

impl Default for LinuxHost {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxHost {
    pub fn new() -> Self {
        Self {
            allow_raw_memory: true,
            start: std::time::Instant::now(),
            exec_ranges: Vec::new(),
        }
    }

    /// 解析 /proc/self/maps，重建可执行段表。失败静默 —— 后续校验会降级为
    /// "不在 cache 内即不允许"，但调用方可选择忽略不校验。
    fn refresh_exec_ranges(&mut self) {
        let Ok(s) = std::fs::read_to_string("/proc/self/maps") else { return };
        let mut v: Vec<(u64, u64)> = Vec::new();
        for line in s.lines() {
            // 行格式: addr-addr perms offset dev inode path
            let mut it = line.split_whitespace();
            let Some(range) = it.next() else { continue };
            let Some(perms) = it.next() else { continue };
            if perms.len() < 3 || perms.as_bytes().get(2) != Some(&b'x') {
                continue;
            }
            let Some((a, b)) = range.split_once('-') else { continue };
            let (Ok(start), Ok(end)) = (
                u64::from_str_radix(a, 16),
                u64::from_str_radix(b, 16),
            ) else { continue };
            v.push((start, end));
        }
        self.exec_ranges = v;
    }

    fn target_in_exec(&self, t: u64) -> bool {
        self.exec_ranges.iter().any(|&(s, e)| t >= s && t < e)
    }
}

impl HostBridge for LinuxHost {
    fn load(&mut self, addr: u64, w: Width) -> Result<u64> {
        if !self.allow_raw_memory {
            return Err(Error::vm("LinuxHost: 已禁用裸地址加载"));
        }
        unsafe {
            let v = match w {
                Width::W8 => *(addr as *const u8) as u64,
                Width::W16 => *(addr as *const u16) as u64,
                Width::W32 => *(addr as *const u32) as u64,
                Width::W64 => *(addr as *const u64),
            };
            Ok(v)
        }
    }

    fn store(&mut self, addr: u64, value: u64, w: Width) -> Result<()> {
        if !self.allow_raw_memory {
            return Err(Error::vm("LinuxHost: 已禁用裸地址写入"));
        }
        unsafe {
            match w {
                Width::W8 => *(addr as *mut u8) = value as u8,
                Width::W16 => *(addr as *mut u16) = value as u16,
                Width::W32 => *(addr as *mut u32) = value as u32,
                Width::W64 => *(addr as *mut u64) = value,
            }
        }
        Ok(())
    }

    fn native_call(&mut self, target: u64, args: &[u64]) -> Result<u64> {
        // 第一道防线：基本健全性。
        if target == 0 {
            return Err(Error::vm("native_call: 空指针 target=0"));
        }
        if target & 3 != 0 {
            return Err(Error::vm(format!(
                "native_call: target 未对齐 {:#x}",
                target
            )));
        }
        if target < 0x1000 {
            return Err(Error::vm(format!(
                "native_call: target 落在低地址（疑似垃圾） {:#x}",
                target
            )));
        }

        // 第二道：必须落在某个 r-x 段。第一次未命中时刷新一次 cache，
        // 应对 dlopen 之后新映射的库。
        if !self.target_in_exec(target) {
            self.refresh_exec_ranges();
            if !self.target_in_exec(target) {
                return Err(Error::vm(format!(
                    "native_call: target {:#x} 不在任何可执行映射内",
                    target
                )));
            }
        }

        // ARM64 AAPCS64 支持 x0..x7 全部为整数参数。固定走 F8 即可，
        // 多出的参数在被调函数侧会被忽略 —— 比 F6 截断更兼容。
        type F8 = extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64;
        let mut a = [0u64; 8];
        for (i, v) in args.iter().take(8).enumerate() {
            a[i] = *v;
        }
        let p = target as *const ();
        let r = unsafe {
            (core::mem::transmute::<_, F8>(p))(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])
        };
        Ok(r)
    }

    fn syscall(&mut self, no: u64, args: &[u64]) -> Result<u64> {
        // sys_exit / sys_exit_group 前打印总耗时，方便外部对比 native vs VMP 损耗
        if no == 93 || no == 94 {
            let el = self.start.elapsed();
            eprintln!("[vmp] elapsed: {}us ({}ms)", el.as_micros(), el.as_millis());
        }
        let mut a = [0u64; 6];
        for (i, v) in args.iter().take(6).enumerate() {
            a[i] = *v;
        }
        Ok(unsafe { raw_syscall(no, a[0], a[1], a[2], a[3], a[4], a[5]) })
    }

    fn map_data(&mut self, vaddr: u64, bytes: &[u8], prot: u8) -> Result<()> {
        let page = 0x1000u64;
        let aligned_addr = vaddr & !(page - 1);
        let off_in_page = (vaddr - aligned_addr) as usize;
        let total = (off_in_page + bytes.len() + page as usize - 1) & !(page as usize - 1);
        let prot_rw = 0x1u64 | 0x2u64;
        let flags = 0x10u64 | 0x20u64 | 0x02u64;
        let mmap_no: u64 = 222;
        let r = unsafe {
            raw_syscall(mmap_no, aligned_addr, total as u64, prot_rw, flags, u64::MAX, 0)
        };
        log::debug!(
            "[map_data] mmap_fixed vaddr={:#x} aligned={:#x} total={:#x} → {:#x} (errno={})",
            vaddr, aligned_addr, total, r, (r as i64).wrapping_neg()
        );
        if (r as i64) < 0 && (r as i64) > -4096 {
            return Err(vmp_core::Error::vm("E:mmap"));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), vaddr as *mut u8, bytes.len());
        }
        let want_prot = (prot as u64) & 0x7;
        if want_prot != prot_rw && want_prot != 0 {
            let mprotect_no: u64 = 226;
            let _ = unsafe { raw_syscall(mprotect_no, aligned_addr, total as u64, want_prot, 0, 0, 0) };
        }
        log::debug!("[map_data] copied {} bytes to {:#x}; first 8 bytes = {:?}", bytes.len(), vaddr,
            unsafe { std::slice::from_raw_parts(vaddr as *const u8, 8.min(bytes.len())) });
        Ok(())
    }
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
unsafe fn raw_syscall(no: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    // Linux/Android aarch64 syscall ABI：
    //   - syscall 号在 X8；参数 X0..X5；返回值 X0
    //   - 内核保留 X19..X29 / SP；可能改写 X1..X18 与 NZCV
    // 用 inlateout/lateout 显式告知编译器这些寄存器在 svc 后值不可靠，
    // 否则编译器可能误以为参数寄存器 / flag 仍保留旧值并做错误的后续访问 → SIGSEGV。
    core::arch::asm!(
        "svc #0",
        in("x8") no,
        inlateout("x0") a0 => ret,
        inlateout("x1") a1 => _,
        inlateout("x2") a2 => _,
        inlateout("x3") a3 => _,
        inlateout("x4") a4 => _,
        inlateout("x5") a5 => _,
        lateout("x6") _,
        lateout("x7") _,
        lateout("x8") _,
        lateout("x9") _,
        lateout("x10") _,
        lateout("x11") _,
        lateout("x12") _,
        lateout("x13") _,
        lateout("x14") _,
        lateout("x15") _,
        lateout("x16") _,
        lateout("x17") _,
        options(nostack),
    );
    ret
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64"))]
unsafe fn raw_syscall(no: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    // Linux x86_64 syscall ABI：rax=系统调用号，rdi/rsi/rdx/r10/r8/r9=参数，
    // 返回值在 rax。`syscall` 指令使用 rcx 保存返回 RIP、r11 保存 RFLAGS，
    // 同时内核可能改写 EFLAGS 标志位 → 不能 preserves_flags。
    core::arch::asm!(
        "syscall",
        inlateout("rax") no => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r10") a3 => _,
        inlateout("r8") a4 => _,
        inlateout("r9") a5 => _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    ret
}

#[cfg(not(any(
    all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"),
    all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64"),
)))]
unsafe fn raw_syscall(_no: u64, _a0: u64, _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> u64 {
    // 非 Linux / 非 aarch64-x86_64：在加壳器进程内当作 noop（避免破坏 cargo test）。
    0
}
