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

fn log_msg(msg: &[u8]) {
    #[cfg(target_os = "android")]
    unsafe {
        __android_log_write(
            4, // ANDROID_LOG_INFO
            b"qvmp\0".as_ptr() as *const _,
            msg.as_ptr() as *const _,
        );
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = msg;
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
    /// virtual address of the QVMP magic (start of header) in the host process
    magic_vaddr: usize,
    /// payload length (after the 8-byte header)
    payload_len: usize,
    /// the file offset of the magic in the *original* on-disk ELF —
    /// the keystream is derived from this exact value at rewrite time.
    payload_file_offset: u64,
    /// 32 bytes of host-ELF header (we need bytes 0..32 for key derivation)
    elf_header: [u8; 32],
}

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
        if seg_len < 8 {
            continue;
        }
        let bytes = unsafe { std::slice::from_raw_parts(seg_start as *const u8, seg_len) };
        let mut i = 0usize;
        while i + 8 <= bytes.len() {
            if &bytes[i..i + 4] == b"QVMP" {
                let payload_len = u32::from_le_bytes([
                    bytes[i + 4],
                    bytes[i + 5],
                    bytes[i + 6],
                    bytes[i + 7],
                ]) as usize;
                if i + 8 + payload_len <= bytes.len() {
                    let mut header = [0u8; 32];
                    let hdr = unsafe { std::slice::from_raw_parts(elf_hdr_addr as *const u8, 32) };
                    header.copy_from_slice(hdr);
                    *out = Some(Find {
                        magic_vaddr: seg_start + i,
                        payload_len,
                        // file offset of the magic = phdr.p_offset + (magic - seg_start)
                        payload_file_offset: ph.p_offset as u64 + i as u64,
                        elf_header: header,
                    });
                    return 1;
                }
            }
            i += 4;
        }
    }
    0
}

fn discover_and_decrypt_blob() -> Option<StubBlob> {
    let mut find: Option<Find> = None;
    unsafe {
        dl_iterate_phdr(iter_cb, &mut find as *mut _ as *mut c_void);
    }
    let f = find?;

    // Snapshot the encrypted payload into a writable buffer.
    let payload_addr = f.magic_vaddr + 8;
    let mut buf: Vec<u8> = unsafe {
        std::slice::from_raw_parts(payload_addr as *const u8, f.payload_len).to_vec()
    };

    // Mirror vmp-rewriter::armor::encrypt_payload_in_place key derivation exactly.
    let payload_offset = f.payload_file_offset;
    let mut key = [0u8; 32];
    for i in 0..16 {
        key[i] = f.elf_header[i] ^ ((payload_offset >> (i % 8)) as u8);
    }
    let entry_field = u64::from_le_bytes([
        f.elf_header[0x18],
        f.elf_header[0x19],
        f.elf_header[0x1a],
        f.elf_header[0x1b],
        f.elf_header[0x1c],
        f.elf_header[0x1d],
        f.elf_header[0x1e],
        f.elf_header[0x1f],
    ]);
    for i in 0..8 {
        key[16 + i] = ((entry_field >> (i * 8)) as u8) ^ 0xA5;
    }
    // The rewriter's third key chunk reads `elf[(off + i) % elf.len()] ^ 0x5A`
    // for i in 0..8. For any real-sized binary (off + 8 << file size), the
    // modulo doesn't wrap, so this reads bytes off..off+8 — i.e., the QVMP
    // magic + length header, which sits *unencrypted* in front of the payload.
    // We can read those exact bytes from the live mapping at magic_vaddr.
    for i in 0..8 {
        let byte = unsafe { *((f.magic_vaddr + i) as *const u8) };
        key[24 + i] = byte ^ 0x5A;
    }

    for i in 0..f.payload_len {
        let mut h: u64 = 0xCBF2_9CE4_8422_2325;
        h ^= key[i % 32] as u64;
        h = h.wrapping_mul(0x100_0000_01B3);
        h ^= (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        h = h.wrapping_mul(0x100_0000_01B3);
        let k = (h >> 32) as u8;
        buf[i] ^= k;
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

extern "C" fn sigtrap_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ucontext: *mut c_void,
) {
    // SAFETY: the kernel populates ucontext_t for the trapping thread; we only
    // mutate the mcontext_t::regs / pc of *this* signal frame, which is the
    // standard handoff pattern (e.g. JITs use this for guard pages).
    let uc = unsafe { &mut *(ucontext as *mut libc::ucontext_t) };
    let pc = uc.uc_mcontext.pc;

    // Verify this is one of our trampoline BRKs.
    let inst = unsafe { *(pc as *const u32) };
    // BRK encoding: 1101 0100 001 imm16 0 0000  →  base 0xD420_0000, imm16 in [20:5]
    if (inst & 0xFFE0_001F) != 0xD420_0000 {
        return;
    }
    let imm16 = ((inst >> 5) & 0xFFFF) as u16;
    if imm16 & 0xFF00 != 0x5100 {
        return; // BRK with foreign imm16 (debugger / ASAN), not ours
    }

    let blob = match BLOB.get() {
        Some(b) => b,
        None => return,
    };

    // X16 carries the full region_id (the trampoline `mov x16, #N` is the
    // authoritative source; imm16 only encodes the low byte).
    let region_id = uc.uc_mcontext.regs[16] as usize;
    if region_id >= blob.regions.len() {
        return;
    }

    let mut gpr_args = [0u64; 8];
    let mut fpr_args = [0u64; 8];
    for i in 0..8 {
        gpr_args[i] = uc.uc_mcontext.regs[i];
    }
    // FP args: D0..D7 = low 64 bits of V0..V7. ucontext exposes them via
    // fpsimd_context — bionic stores it inside mcontext.__reserved.
    if let Some(vregs) = read_fpsimd(uc) {
        for i in 0..8 {
            fpr_args[i] = vregs[i] as u64;
        }
    }

    let lr = uc.uc_mcontext.regs[30];
    let mut host = vmp_stub::linux::LinuxHost::new();
    let (gpr_ret, fpr_ret) = match vmp_stub::dispatch_vm_fp(
        blob,
        region_id,
        &gpr_args,
        &fpr_args,
        &mut host,
    ) {
        Ok(v) => v,
        Err(_) => return,
    };

    if let Some(vregs) = read_fpsimd_mut(uc) {
        let upper = vregs[0] & !((1u128 << 64) - 1);
        vregs[0] = upper | (fpr_ret as u128);
    }
    uc.uc_mcontext.regs[0] = gpr_ret;
    uc.uc_mcontext.pc = lr;
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
