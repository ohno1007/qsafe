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
    /// hybrid mode 用的 RWX thunk 页基址；按需 lazy mmap
    #[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
    pub thunk_page: core::cell::Cell<u64>,
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
            #[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
            thunk_page: core::cell::Cell::new(0),
        }
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
        if target == 0 {
            return Err(Error::vm("LinuxHost.native_call: 空指针"));
        }
        // 通过函数指针直接调用，最多 6 个 u64 参数（与 SysV / AAPCS64 对齐）
        unsafe {
            type F0 = extern "C" fn() -> u64;
            type F1 = extern "C" fn(u64) -> u64;
            type F2 = extern "C" fn(u64, u64) -> u64;
            type F3 = extern "C" fn(u64, u64, u64) -> u64;
            type F4 = extern "C" fn(u64, u64, u64, u64) -> u64;
            type F5 = extern "C" fn(u64, u64, u64, u64, u64) -> u64;
            type F6 = extern "C" fn(u64, u64, u64, u64, u64, u64) -> u64;
            let p = target as *const ();
            let r = match args.len() {
                0 => (core::mem::transmute::<_, F0>(p))(),
                1 => (core::mem::transmute::<_, F1>(p))(args[0]),
                2 => (core::mem::transmute::<_, F2>(p))(args[0], args[1]),
                3 => (core::mem::transmute::<_, F3>(p))(args[0], args[1], args[2]),
                4 => (core::mem::transmute::<_, F4>(p))(args[0], args[1], args[2], args[3]),
                5 => (core::mem::transmute::<_, F5>(p))(args[0], args[1], args[2], args[3], args[4]),
                _ => (core::mem::transmute::<_, F6>(p))(args[0], args[1], args[2], args[3], args[4], args[5]),
            };
            Ok(r)
        }
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

    /// 混合执行：在 RWX thunk 里跑一条 raw_instr。
    ///
    /// 流程：
    /// 1. lazy mmap 一个 64KB RWX 页（Android W^X 限制下需 PROT_NONE → R+W →
    ///    写指令 → R+X 切换；Bionic 较新版本允许直接 RWX）
    /// 2. 在该页放置定长 thunk 模板：load all regs from x16 → 执行 raw_instr →
    ///    save regs → ret
    /// 3. 每次调用前把 raw_instr 字节 patch 到模板中央的 `<orig_inst>` 位置
    /// 4. 把 [gpr, fpr, nzcv] 拷到 save_area；x16 = &save_area；调用 thunk；
    ///    thunk 返回后 save_area 已含执行后状态
    ///
    /// 不能跑：syscall（svc）、PC-relative load（adr/adrp）、branches —— 这些
    /// lifter 必须解码；hybrid 仅兜底数据处理 / NEON / LSE 等"纯运算"指令。
    #[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
    fn native_exec(
        &mut self,
        raw_instr: u32,
        gpr: &mut [u64; 31],
        fpr: &mut [u128; 32],
        nzcv: &mut u32,
    ) -> Result<()> {
        // 1) 确保 thunk 页已分配
        let mut page = self.thunk_page.get();
        if page == 0 {
            // mmap PROT_R | PROT_W | PROT_X
            const PROT_RWX: u64 = 0x1 | 0x2 | 0x4;
            const MAP_PRIVATE_ANON: u64 = 0x02 | 0x20;
            let r = unsafe {
                raw_syscall(222, 0, 0x10000, PROT_RWX, MAP_PRIVATE_ANON, u64::MAX, 0)
            };
            if (r as i64) < 0 && (r as i64) > -4096 {
                return Err(Error::vm("E:hybrid-mmap"));
            }
            page = r;
            self.thunk_page.set(page);
            // 安装 thunk 模板（永久；不依赖 raw_instr 内容）
            install_thunk_template(page);
        }
        // 2) patch raw_instr 到模板里的 RAW_INSTR 占位
        unsafe {
            let target_off = THUNK_RAW_INSTR_OFFSET as usize;
            let p = (page as *mut u32).add(target_off / 4);
            *p = raw_instr;
            // 自修改代码必须 dc cvau + ic ivau + dsb ish + isb 同步 I/D cache，
            // 否则旧译码留 cache → 新指令不生效
            core::arch::asm!(
                "dc cvau, {0}",
                "dsb ish",
                "ic ivau, {0}",
                "dsb ish",
                "isb",
                in(reg) p,
            );
        }
        // 3) 准备 save area + 调用 thunk
        let mut save: SaveArea = SaveArea::default();
        save.gpr = *gpr;
        save.fpr = *fpr;
        save.nzcv = *nzcv;
        unsafe {
            let entry: extern "C" fn(*mut SaveArea) = core::mem::transmute(page as *const ());
            entry(&mut save as *mut SaveArea);
        }
        *gpr = save.gpr;
        *fpr = save.fpr;
        *nzcv = save.nzcv;
        Ok(())
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

// =============================================================================
// Hybrid mode：thunk 模板 + SaveArea
// =============================================================================

/// 寄存器保存区。layout 必须与 thunk asm 严格对齐。
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
#[repr(C)]
#[derive(Default)]
struct SaveArea {
    /// X0..X30（注：X31=SP 不入 thunk；hybrid 不允许操作栈指针）
    gpr: [u64; 31],
    /// 16-byte 对齐占位（让 fpr 起始落到 +0x100）
    _pad1: [u64; 1],
    /// V0..V31（128-bit 每个）
    fpr: [u128; 32],
    /// NZCV，bit 31..28
    nzcv: u32,
    _pad2: [u32; 3],
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
const THUNK_RAW_INSTR_OFFSET: u32 = 0x180;

/// 把 thunk 模板写到 RWX 页起始位置。
/// 模板执行时收到 X0 = &SaveArea。
///
/// 模板布局（粗略；地址即 thunk 起 + offset）：
/// ```asm
/// 0x000  mov   x16, x0          ; x16 = &SaveArea（不可被 raw_instr clobber）
/// 0x004  ldr   w17, [x16, #0x300]
/// 0x008  msr   nzcv, x17        ; 装 NZCV
/// 0x00C  ldp   q0, q1, [x16, #0x100]
/// 0x014  ldp   q2, q3, [x16, #0x120]
/// ...    （V0..V31，16 条 ldp）
/// 0x0AC  ldp   x0, x1, [x16, #0x00]
/// 0x0B0  ldp   x2, x3, [x16, #0x10]
/// ...    （X0..X29，15 条 ldp = 60 字节）
/// 0x12C  ldr   x30, [x16, #0xF0]    ; X30 单读
/// 0x180  RAW_INSTR （4 字节占位，调用方 patch）
/// 0x184  mrs   x17, nzcv
/// 0x188  str   w17, [x16, #0x300]
/// 0x18C  stp   x0, x1, [x16, #0x00]
/// ...    save 全部 regs
/// 0x...  ret
/// ```
///
/// 当前实现：用最小可行版（只保存 / 恢复 GPR + NZCV，不 NEON），减少模板长度
/// 与对齐复杂度。NEON 路径未启用时大部分非加密 SDK 也能跑通。完整 NEON 保存
/// 留 Phase 9。
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
fn install_thunk_template(page: u64) {
    use byteorder::{ByteOrder, LittleEndian};
    let mut buf = vec![0u8; 0x400];
    let mut pos = 0usize;
    let mut emit = |buf: &mut Vec<u8>, p: &mut usize, inst: u32| {
        LittleEndian::write_u32(&mut buf[*p..*p + 4], inst);
        *p += 4;
    };

    // mov x16, x0  →  orr x16, xzr, x0  =  AA000010
    emit(&mut buf, &mut pos, 0xAA0003F0u32);
    // ldr w17, [x16, #0x300]: 0xB94300 11 → addr 0x300/4=192 in imm12
    // LDR Wt = (size=10), opc=01, Rn=16, imm12 =0x300/4=0xC0
    // encoding: 1011_1001_01 + imm12 + Rn + Rt
    let ldr_w17_nzcv = 0b1011_1001_01_000000_00000_10000_10001u32 | (0xC0 << 10);
    emit(&mut buf, &mut pos, ldr_w17_nzcv);
    // msr nzcv, x17: 0xD51B4011
    emit(&mut buf, &mut pos, 0xD51B4011);

    // ldp x{2i}, x{2i+1}, [x16, #(2i*8)]   for i in 0..15  (X0..X29)
    for i in 0..15u32 {
        let off = (i as i32) * 16;
        let imm7 = ((off / 8) & 0x7F) as u32;
        // LDP X (sf=1): 1010_1001_01 imm7 Rt2 Rn Rt
        // 64-bit: opc=10, V=0, L=1, idx=10 (signed offset)
        let inst = 0b1010_1001_01_0000000_00000_10000_00000u32
            | (imm7 << 15)
            | ((i * 2 + 1) << 10)
            | ((i * 2) & 0x1F);
        emit(&mut buf, &mut pos, inst);
    }
    // ldr x30, [x16, #0xF0]
    let ldr_x30 = 0b1111_1001_01_000000000000_10000_11110u32 | ((0xF0 / 8) << 10);
    emit(&mut buf, &mut pos, ldr_x30);

    // 把后续填充到 RAW_INSTR 偏移 0x180
    while pos < THUNK_RAW_INSTR_OFFSET as usize {
        emit(&mut buf, &mut pos, 0xD503201Fu32); // NOP
    }
    // RAW_INSTR 占位（调用方 patch；初始放 NOP）
    emit(&mut buf, &mut pos, 0xD503201Fu32);
    // mrs x17, nzcv: 0xD53B4011
    emit(&mut buf, &mut pos, 0xD53B4011);
    // str w17, [x16, #0x300]
    let str_w17_nzcv = 0b1011_1001_00_000000_00000_10000_10001u32 | (0xC0 << 10);
    emit(&mut buf, &mut pos, str_w17_nzcv);
    // stp X{2i}, X{2i+1}, [x16, #(2i*8)]
    for i in 0..15u32 {
        let off = (i as i32) * 16;
        let imm7 = ((off / 8) & 0x7F) as u32;
        let inst = 0b1010_1001_00_0000000_00000_10000_00000u32
            | (imm7 << 15)
            | ((i * 2 + 1) << 10)
            | ((i * 2) & 0x1F);
        emit(&mut buf, &mut pos, inst);
    }
    // str x30, [x16, #0xF0]
    let str_x30 = 0b1111_1001_00_000000000000_10000_11110u32 | ((0xF0 / 8) << 10);
    emit(&mut buf, &mut pos, str_x30);
    // ret
    emit(&mut buf, &mut pos, 0xD65F03C0u32);

    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), page as *mut u8, buf.len());
        // 全页同步 I cache
        core::arch::asm!(
            "dsb ish",
            "ic ialluis",
            "dsb ish",
            "isb",
        );
    }
}
