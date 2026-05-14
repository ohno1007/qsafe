//! libqvmp_runtime.so — on-device dispatcher for hardened ELFs.
//!
//! Lifecycle:
//!  1. ELF load (linker pulls this .so via DT_NEEDED **or** the user sets LD_PRELOAD).
//!  2. The dynamic linker invokes `qvmp_init` from `.init_array` once all .so's
//!     and the main exec are mapped.
//!  3. `qvmp_init` walks `dl_iterate_phdr`, scans every PT_LOAD for the
//!     `QVMP` magic the rewriter planted (8-byte header: 4-byte magic + u32
//!     length, followed by an XOR-encrypted packed StubBlob).
//!  4. The blob is decrypted with the same FNV+ELF-header keystream the
//!     rewriter used (`armor::encrypt_payload_in_place`), then `unpack_blob`'d.
//!  5. A SIGTRAP handler is installed via `sigaction(SIGTRAP, SA_SIGINFO)`.
//!  6. On every BRK trap fired by a rewriter trampoline, the handler reads X16
//!     (region_id), gathers GPR/FP arg regs, calls `dispatch_vm_fp`, writes
//!     the return into X0/D0, and sets PC := LR (X30) to return to caller.
//!
//! Trampoline layout (from vmp-rewriter::patcher):
//!   `mov x16, #region_id ; brk #(0x5156 | region_id_low8) ; nop ; b .`
//! BRK imm16 high byte = 0x51 ('Q'). We use that to filter unrelated SIGTRAPs.

#![cfg(any(target_os = "linux", target_os = "android"))]
#![cfg(target_arch = "aarch64")]

use std::ffi::c_void;
use std::sync::OnceLock;

use vmp_stub::StubBlob;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static BLOB: OnceLock<StubBlob> = OnceLock::new();

// ---------------------------------------------------------------------------
// .init_array constructor
// ---------------------------------------------------------------------------

#[link_section = ".init_array"]
#[used]
static INIT_ARRAY_ENTRY: extern "C" fn() = qvmp_init;

extern "C" fn qvmp_init() {
    if let Some(blob) = discover_and_decrypt_blob() {
        let _ = BLOB.set(blob);
        install_sigtrap_handler();
        log_msg(b"qvmp_runtime: blob loaded, SIGTRAP handler installed\0");
    } else {
        log_msg(b"qvmp_runtime: no QVMP payload found in any loaded ELF\0");
    }
}

#[cfg(target_os = "android")]
extern "C" {
    fn __android_log_write(
        prio: libc::c_int,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> libc::c_int;
}

// Logging is gated by a byte at QVMP-header-offset+24 — baked into the
// hardened ELF at rewrite time (`vmp rewrite --log on|off`). When non-zero
// we mirror messages to stderr (fd 2) so MT 管理器's run window / `adb shell`
// see them directly. No env-var lookup at runtime.
static LOG_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn log_enabled() -> bool {
    LOG_FLAG.load(std::sync::atomic::Ordering::Relaxed)
}

/// Format `<prefix><decimal id>\n\0` into `buf`, returns the byte length used.
/// Avoids heap allocations so it's safe to call from a signal handler.
fn format_dispatch_msg(buf: &mut [u8], prefix: &[u8], id: usize) -> usize {
    let mut pos = 0;
    for &b in prefix {
        if pos < buf.len() { buf[pos] = b; pos += 1; }
    }
    // Stringify id as decimal
    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut v = id;
    if v == 0 {
        digits[0] = b'0';
        n = 1;
    } else {
        while v > 0 {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
    }
    for i in (0..n).rev() {
        if pos < buf.len() { buf[pos] = digits[i]; pos += 1; }
    }
    if pos < buf.len() { buf[pos] = 0; }
    pos
}

fn log_msg(msg: &[u8]) {
    if !log_enabled() {
        return;
    }
    let stripped = if msg.last() == Some(&0) { &msg[..msg.len() - 1] } else { msg };
    unsafe {
        let prefix = b"[qvmp] ";
        libc::write(2, prefix.as_ptr() as *const _, prefix.len());
        libc::write(2, stripped.as_ptr() as *const _, stripped.len());
        libc::write(2, b"\n".as_ptr() as *const _, 1);
    }
    #[cfg(target_os = "android")]
    unsafe {
        __android_log_write(
            4,
            b"qvmp\0".as_ptr() as *const _,
            msg.as_ptr() as *const _,
        );
    }
}

// ---------------------------------------------------------------------------
// Blob discovery via dl_iterate_phdr
// ---------------------------------------------------------------------------

#[repr(C)]
struct DlPhdrInfo {
    dlpi_addr: usize,
    dlpi_name: *const libc::c_char,
    dlpi_phdr: *const libc::Elf64_Phdr,
    dlpi_phnum: u16,
}

extern "C" {
    fn dl_iterate_phdr(
        callback: extern "C" fn(*mut DlPhdrInfo, libc::size_t, *mut c_void) -> libc::c_int,
        data: *mut c_void,
    ) -> libc::c_int;
}

struct Find {
    magic_vaddr: usize,
    payload_len: usize,
    payload_file_offset: u64,
    elf_header: [u8; 32],
    rodata_vaddr: u64,
    rodata_len: u64,
    load_bias: usize,
    log_flag: bool,
}

/// QVMP header (32 bytes total):
///   [0..4]   "QVMP" magic
///   [4..8]   payload_len: u32
///   [8..16]  rodata_vaddr: u64
///   [16..24] rodata_len: u64
///   [24]     log_flag: u8         (1 = stderr+logcat on, 0 = silent)
///   [25..32] reserved (zero)
const QVMP_HEADER_LEN: usize = 32;

extern "C" fn iter_cb(info: *mut DlPhdrInfo, _size: libc::size_t, data: *mut c_void) -> libc::c_int {
    let info = unsafe { &*info };
    let out = unsafe { &mut *(data as *mut Option<Find>) };
    if out.is_some() {
        return 1;
    }
    let load_base = info.dlpi_addr;
    let phdrs = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize) };

    // Lowest PT_LOAD vaddr → in-memory ELF header start.
    let mut elf_hdr_addr: Option<usize> = None;
    for ph in phdrs {
        if ph.p_type == libc::PT_LOAD {
            let v = load_base + ph.p_vaddr as usize;
            elf_hdr_addr = Some(elf_hdr_addr.map_or(v, |x| x.min(v)));
        }
    }
    let elf_hdr_addr = match elf_hdr_addr {
        Some(v) => v,
        None => return 0,
    };

    for ph in phdrs {
        if ph.p_type != libc::PT_LOAD {
            continue;
        }
        let seg_start = load_base + ph.p_vaddr as usize;
        let seg_len = ph.p_filesz as usize;
        if seg_len < QVMP_HEADER_LEN {
            continue;
        }
        let bytes = unsafe { std::slice::from_raw_parts(seg_start as *const u8, seg_len) };
        let mut i = 0usize;
        while i + QVMP_HEADER_LEN <= bytes.len() {
            if &bytes[i..i + 4] == b"QVMP" {
                let payload_len = u32::from_le_bytes([
                    bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7],
                ]) as usize;
                let rodata_vaddr = u64::from_le_bytes([
                    bytes[i + 8],  bytes[i + 9],  bytes[i + 10], bytes[i + 11],
                    bytes[i + 12], bytes[i + 13], bytes[i + 14], bytes[i + 15],
                ]);
                let rodata_len = u64::from_le_bytes([
                    bytes[i + 16], bytes[i + 17], bytes[i + 18], bytes[i + 19],
                    bytes[i + 20], bytes[i + 21], bytes[i + 22], bytes[i + 23],
                ]);
                if i + QVMP_HEADER_LEN + payload_len <= bytes.len() {
                    let mut header = [0u8; 32];
                    let hdr = unsafe { std::slice::from_raw_parts(elf_hdr_addr as *const u8, 32) };
                    header.copy_from_slice(hdr);
                    let log_flag = bytes[i + 24] != 0;
                    *out = Some(Find {
                        magic_vaddr: seg_start + i,
                        payload_len,
                        payload_file_offset: ph.p_offset as u64 + i as u64,
                        elf_header: header,
                        rodata_vaddr,
                        rodata_len,
                        load_bias: load_base,
                        log_flag,
                    });
                    return 1;
                }
            }
            i += 4;
        }
    }
    0
}

/// Domain tags must match vmp-rewriter::armor.
const DOMAIN_PAYLOAD: u64 = 0;
const DOMAIN_RODATA: u64 = 0xC0DE_DA7A_BABE_F00D;

fn derive_key(elf_header: &[u8; 32], magic_vaddr: usize, payload_offset: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    for i in 0..16 {
        key[i] = elf_header[i] ^ ((payload_offset >> (i % 8)) as u8);
    }
    let entry_field = u64::from_le_bytes([
        elf_header[0x18], elf_header[0x19], elf_header[0x1a], elf_header[0x1b],
        elf_header[0x1c], elf_header[0x1d], elf_header[0x1e], elf_header[0x1f],
    ]);
    for i in 0..8 {
        key[16 + i] = ((entry_field >> (i * 8)) as u8) ^ 0xA5;
    }
    // For any real-sized binary, `elf[(off + i) % elf.len()]` lands at off..off+8
    // — the unencrypted QVMP magic + length bytes. Read those from live memory.
    for i in 0..8 {
        let byte = unsafe { *((magic_vaddr + i) as *const u8) };
        key[24 + i] = byte ^ 0x5A;
    }
    key
}

fn keystream_byte(key: &[u8; 32], i: usize, domain: u64) -> u8 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325 ^ domain;
    h ^= key[i % 32] as u64;
    h = h.wrapping_mul(0x100_0000_01B3);
    h ^= (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h = h.wrapping_mul(0x100_0000_01B3);
    (h >> 32) as u8
}

/// Make a vaddr range writable, run a closure, restore RX/RO. Page-aligns.
unsafe fn with_writable<F: FnOnce()>(addr: usize, len: usize, restore_prot: i32, f: F) -> bool {
    let page = 0x1000usize;
    let aligned_addr = addr & !(page - 1);
    let end = (addr + len + page - 1) & !(page - 1);
    let aligned_len = end - aligned_addr;
    let r1 = libc::mprotect(
        aligned_addr as *mut c_void,
        aligned_len,
        libc::PROT_READ | libc::PROT_WRITE,
    );
    if r1 != 0 {
        return false;
    }
    f();
    let r2 = libc::mprotect(aligned_addr as *mut c_void, aligned_len, restore_prot);
    r2 == 0
}

fn decrypt_rodata_in_place(f: &Find) {
    if f.rodata_len == 0 || f.rodata_vaddr == 0 {
        return;
    }
    let key = derive_key(&f.elf_header, f.magic_vaddr, f.payload_file_offset);
    let target = f.load_bias + f.rodata_vaddr as usize;
    let len = f.rodata_len as usize;
    unsafe {
        let ok = with_writable(target, len, libc::PROT_READ, || {
            let p = target as *mut u8;
            for i in 0..len {
                let k = keystream_byte(&key, i, DOMAIN_RODATA);
                *p.add(i) ^= k;
            }
        });
        if !ok {
            log_msg(b"qvmp_runtime: rodata mprotect failed; skipped decrypt\0");
        } else {
            log_msg(b"qvmp_runtime: rodata decrypted in place\0");
        }
    }
}

fn discover_and_decrypt_blob() -> Option<StubBlob> {
    let mut find: Option<Find> = None;
    unsafe {
        dl_iterate_phdr(iter_cb, &mut find as *mut _ as *mut c_void);
    }
    let f = find?;
    LOG_FLAG.store(f.log_flag, std::sync::atomic::Ordering::Relaxed);

    // Decrypt rodata FIRST — must happen before any code that references its
    // bytes runs. Our .init_array entry is invoked before the main binary's
    // .init_array (LD_PRELOAD ordering or NEEDED-deps-before-main ordering),
    // so this is the right window.
    decrypt_rodata_in_place(&f);

    // Snapshot the encrypted payload into a writable buffer.
    let payload_addr = f.magic_vaddr + QVMP_HEADER_LEN;
    let mut buf: Vec<u8> = unsafe {
        std::slice::from_raw_parts(payload_addr as *const u8, f.payload_len).to_vec()
    };

    let key = derive_key(&f.elf_header, f.magic_vaddr, f.payload_file_offset);
    for i in 0..f.payload_len {
        buf[i] ^= keystream_byte(&key, i, DOMAIN_PAYLOAD);
    }

    vmp_stub::unpack_blob(&buf).ok()
}

// ---------------------------------------------------------------------------
// SIGTRAP handler
// ---------------------------------------------------------------------------

fn install_sigtrap_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigtrap_handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTRAP, &sa, std::ptr::null_mut());
    }
}

// Bionic-specific ucontext_t layout offsets (from start of ucontext_t).
// Rust's libc crate assumes glibc layout (sigset_t = 128 bytes) but bionic
// uses sigset_t = 8 bytes + 120 bytes __padding. Reading `uc.uc_mcontext.pc`
// via Rust libc on Android lands in the padding region → garbage value →
// SEGV when used as a pointer. So we access via raw byte offsets that match
// bionic's actual layout:
//   ucontext_t {
//     uc_flags:   0
//     uc_link:    8
//     uc_stack:   16  (24 bytes)
//     uc_sigmask: 40  (8 bytes)
//     __padding:  48  (120 bytes)
//     uc_mcontext: 168 =
//       fault_address: 168
//       regs[31]:      176 .. 424
//       sp:            424
//       pc:            432
//       pstate:        440
//       __reserved:    448 (4096 bytes)
//   }
const UC_REGS_OFFSET: usize = 176; // regs[0]
const UC_PC_OFFSET: usize = 432;
const UC_RESERVED_OFFSET: usize = 448;

#[inline(always)]
unsafe fn uc_reg(ucontext: *mut c_void, idx: usize) -> u64 {
    let p = (ucontext as *const u8).add(UC_REGS_OFFSET + idx * 8) as *const u64;
    *p
}
#[inline(always)]
unsafe fn uc_set_reg(ucontext: *mut c_void, idx: usize, val: u64) {
    let p = (ucontext as *mut u8).add(UC_REGS_OFFSET + idx * 8) as *mut u64;
    *p = val;
}
#[inline(always)]
unsafe fn uc_pc(ucontext: *mut c_void) -> u64 {
    let p = (ucontext as *const u8).add(UC_PC_OFFSET) as *const u64;
    *p
}
#[inline(always)]
unsafe fn uc_set_pc(ucontext: *mut c_void, val: u64) {
    let p = (ucontext as *mut u8).add(UC_PC_OFFSET) as *mut u64;
    *p = val;
}

extern "C" fn sigtrap_handler(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut c_void,
) {
    log_msg(b"qvmp_runtime: SIGTRAP handler entered\0");

    // si_addr (kernel's authoritative trap address) is at byte offset 16
    // in siginfo_t for SIGTRAP. Read it directly to cross-check our PC offset.
    let si_addr = unsafe { *((info as *const u8).add(16) as *const u64) };
    {
        let mut buf = [0u8; 96];
        let n = format_dispatch_msg(&mut buf, b"qvmp_runtime: si_addr=", si_addr as usize);
        log_msg(&buf[..n]);
    }

    let pc = unsafe { uc_pc(ucontext) };
    {
        let mut buf = [0u8; 96];
        let n = format_dispatch_msg(&mut buf, b"qvmp_runtime: ucontext.pc=", pc as usize);
        log_msg(&buf[..n]);
    }

    // Use si_addr as the authoritative PC — it's what the kernel knows.
    let real_pc = si_addr;

    let inst = unsafe { *(real_pc as *const u32) };
    {
        let mut buf = [0u8; 96];
        let n = format_dispatch_msg(&mut buf, b"qvmp_runtime: inst@si_addr=", inst as usize);
        log_msg(&buf[..n]);
    }

    // Discover the actual regs offset: scan ucontext for a u64 == region_id
    // (low byte of BRK's imm16, plus a tentative match for x16). The trampoline
    // sets `mov x16, #region_id`, so somewhere in ucontext there must be a u64
    // equal to that region_id.
    let imm16_low = ((inst >> 5) & 0xFF) as u64;
    {
        let mut buf = [0u8; 96];
        let n = format_dispatch_msg(&mut buf, b"qvmp_runtime: expected x16=", imm16_low as usize);
        log_msg(&buf[..n]);
    }
    // Dump u64 values at offsets 176..464 (32-byte chunks should cover mcontext
    // regs + sp + pc). Format: "uc[OFFSET]=VALUE" so we can manually identify
    // which offset has x16 (should be region_id), x30 (LR), sp, pc, etc.
    {
        let base = ucontext as *const u8;
        let mut off = 176usize;
        while off < 472 {
            let v = unsafe { *((base.add(off)) as *const u64) };
            let mut buf = [0u8; 128];
            // Combined log: "uc[<off>]=<val>"
            let mut p = 0;
            let prefix = b"qvmp_runtime: uc[";
            for &b in prefix { if p < buf.len() { buf[p] = b; p += 1; } }
            // off as decimal
            let mut digits = [0u8; 8]; let mut n = 0; let mut v_o = off;
            if v_o == 0 { digits[0] = b'0'; n = 1; } else {
                while v_o > 0 { digits[n] = b'0' + (v_o % 10) as u8; v_o /= 10; n += 1; }
            }
            for i in (0..n).rev() { if p < buf.len() { buf[p] = digits[i]; p += 1; } }
            // "]="
            for &b in b"]=" { if p < buf.len() { buf[p] = b; p += 1; } }
            // val as decimal
            let mut vdig = [0u8; 24]; let mut vn = 0; let mut vv = v;
            if vv == 0 { vdig[0] = b'0'; vn = 1; } else {
                while vv > 0 { vdig[vn] = b'0' + (vv % 10) as u8; vv /= 10; vn += 1; }
            }
            for i in (0..vn).rev() { if p < buf.len() { buf[p] = vdig[i]; p += 1; } }
            if p < buf.len() { buf[p] = 0; }
            log_msg(&buf[..p]);
            off += 8;
        }
    }

    // For now, halt the loop to allow user to read the offsets
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGTRAP, &sa, std::ptr::null_mut());
    }
    return;

    #[allow(unreachable_code)]
    let pc = real_pc;

    // BRK encoding: 1101 0100 001 imm16 0 0000  →  base 0xD420_0000, imm16 in [20:5]
    if (inst & 0xFFE0_001F) != 0xD420_0000 {
        log_msg(b"qvmp_runtime: not a BRK; restoring SIG_DFL to avoid infinite loop\0");
        // Reset SIGTRAP to default so the kernel terminates the process instead
        // of re-invoking us on the same non-BRK instruction.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGTRAP, &sa, std::ptr::null_mut());
        }
        return;
    }
    let imm16 = ((inst >> 5) & 0xFFFF) as u16;
    if imm16 & 0xFF00 != 0x5100 {
        log_msg(b"qvmp_runtime: foreign BRK imm16, returning\0");
        return;
    }

    let blob = match BLOB.get() {
        Some(b) => b,
        None => {
            log_msg(b"qvmp_runtime: BLOB not set, returning\0");
            return;
        }
    };

    // X16 carries the full region_id (the trampoline `mov x16, #N` is the
    // authoritative source; imm16 only encodes the low byte).
    let region_id = unsafe { uc_reg(ucontext, 16) } as usize;
    if region_id >= blob.regions.len() {
        log_msg(b"qvmp_runtime: region_id OOB, returning\0");
        return;
    }

    let mut gpr_args = [0u64; 8];
    let mut fpr_args = [0u64; 8];
    for i in 0..8 {
        gpr_args[i] = unsafe { uc_reg(ucontext, i) };
    }
    // FP args via fpsimd_context inside reserved area
    if let Some(vregs) = read_fpsimd_raw(ucontext) {
        for i in 0..8 {
            fpr_args[i] = vregs[i] as u64;
        }
    }

    let lr = unsafe { uc_reg(ucontext, 30) };

    // Log the region we're about to dispatch (helps diagnose SEGV during VM run)
    {
        let mut buf = [0u8; 96];
        let n = format_dispatch_msg(&mut buf, b"qvmp_runtime: dispatching region=", region_id);
        log_msg(&buf[..n]);
    }

    let mut host = vmp_stub::linux::LinuxHost::new();
    let (gpr_ret, fpr_ret) = match vmp_stub::dispatch_vm_fp(
        blob,
        region_id,
        &gpr_args,
        &fpr_args,
        &mut host,
    ) {
        Ok(v) => v,
        Err(_) => {
            let mut buf = [0u8; 96];
            let n = format_dispatch_msg(&mut buf, b"qvmp_runtime: VM ERROR for region=", region_id);
            log_msg(&buf[..n]);
            return;
        }
    };

    // Log successful return
    {
        let mut buf = [0u8; 96];
        let n = format_dispatch_msg(&mut buf, b"qvmp_runtime: VM returned region=", region_id);
        log_msg(&buf[..n]);
    }

    if let Some(vregs_off) = find_fpsimd_offset_raw(ucontext) {
        unsafe {
            let p = (ucontext as *mut u8).add(vregs_off + FPSIMD_VREGS_OFFSET) as *mut u128;
            let upper = *p & !((1u128 << 64) - 1);
            *p = upper | (fpr_ret as u128);
        }
    }
    unsafe {
        uc_set_reg(ucontext, 0, gpr_ret);
        uc_set_pc(ucontext, lr);
    }
}

fn find_fpsimd_offset_raw(ucontext: *mut c_void) -> Option<usize> {
    // Scan reserved area for FPSIMD_MAGIC. reserved starts at UC_RESERVED_OFFSET.
    let base = ucontext as *const u8;
    for off in (UC_RESERVED_OFFSET..UC_RESERVED_OFFSET + 4096).step_by(16) {
        let p = unsafe { base.add(off) as *const u32 };
        let m = unsafe { p.read_unaligned() };
        if m == FPSIMD_MAGIC {
            return Some(off);
        }
    }
    None
}

fn read_fpsimd_raw(ucontext: *mut c_void) -> Option<[u128; 32]> {
    let off = find_fpsimd_offset_raw(ucontext)?;
    let base = (ucontext as *const u8).wrapping_add(off + FPSIMD_VREGS_OFFSET);
    let mut out = [0u128; 32];
    for i in 0..32 {
        let p = base.wrapping_add(i * 16) as *const u128;
        out[i] = unsafe { p.read_unaligned() };
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// fpsimd_context extraction from ucontext_t.uc_mcontext.__reserved
// ---------------------------------------------------------------------------
//
// Linux kernel layout (arch/arm64/include/uapi/asm/sigcontext.h):
//
//   struct fpsimd_context {
//       struct _aarch64_ctx head;   // u32 magic + u32 size
//       u32 fpsr;
//       u32 fpcr;
//       __uint128_t vregs[32];
//   };
//   #define FPSIMD_MAGIC 0x46508001
//
// __reserved[] is iterated as a chain of _aarch64_ctx records, terminated by
// a zero magic. We walk it to find FPSIMD_MAGIC.

const FPSIMD_MAGIC: u32 = 0x46508001;
const FPSIMD_VREGS_OFFSET: usize = 16; // head(8) + fpsr(4) + fpcr(4)

fn find_fpsimd_offset(uc: &libc::ucontext_t) -> Option<usize> {
    // libc's ucontext_t::uc_mcontext on aarch64 has field `__reserved: [u8; 4096]`
    // but the layout varies between bionic and glibc. We treat the entire
    // mcontext as a byte slice starting at `&mctx as *const _ as *const u8`,
    // and walk it from a known position past `regs[31] + sp + pc + pstate + fault_address`.
    // Easier: scan from a safe offset for the FPSIMD_MAGIC, since reserved
    // area is large (4096 bytes) and fully zeroed except for the chain.
    let base = uc as *const _ as *const u8;
    // Skip the fixed mcontext head: fault_address(8) + regs[31](248) + sp(8) + pc(8) + pstate(8) = 280 bytes.
    // We start scanning a little past that, in 16-byte stride.
    let start = std::mem::size_of::<libc::ucontext_t>().min(4096);
    // Scan within the ucontext itself (which embeds mcontext including reserved bytes):
    // we read 32-bit aligned u32 candidates for FPSIMD_MAGIC.
    for off in (0..start).step_by(16) {
        let p = unsafe { base.add(off) as *const u32 };
        let m = unsafe { p.read_unaligned() };
        if m == FPSIMD_MAGIC {
            return Some(off);
        }
    }
    None
}

fn read_fpsimd(uc: &libc::ucontext_t) -> Option<[u128; 32]> {
    let off = find_fpsimd_offset(uc)?;
    let base = (uc as *const _ as *const u8).wrapping_add(off + FPSIMD_VREGS_OFFSET);
    let mut out = [0u128; 32];
    for i in 0..32 {
        let p = base.wrapping_add(i * 16) as *const u128;
        out[i] = unsafe { p.read_unaligned() };
    }
    Some(out)
}

fn read_fpsimd_mut(uc: &mut libc::ucontext_t) -> Option<&mut [u128; 32]> {
    let off = find_fpsimd_offset(uc)?;
    let base = (uc as *mut _ as *mut u8).wrapping_add(off + FPSIMD_VREGS_OFFSET);
    Some(unsafe { &mut *(base as *mut [u128; 32]) })
}
