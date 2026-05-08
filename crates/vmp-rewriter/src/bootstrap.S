// Bootstrap stub injected into hardened ELF's INIT_ARRAY.
//
// Runs from main binary's INIT_ARRAY at process start (after libc/libdl/libdeps
// are already mapped + initialized by the dynamic linker, before main()).
//
// Sequence:
//   1. open("/data/local/tmp/.qvmp.so", O_RDWR|O_CREAT|O_TRUNC, 0600) → fd
//   2. write(fd, embedded_so, embedded_so_len)
//   3. close(fd)
//   4. dlopen(path, RTLD_NOW)        — via main ELF's existing dlopen@plt
//   5. unlinkat(AT_FDCWD, path, 0)
//   6. ret
//
// All "external" calls are aarch64 Linux raw syscalls except dlopen which is
// reached by patching a `BL <plt_addr>` at rewrite time.
//
// External patch points (filled in by vmp-rewriter::bootstrap::patch_bootstrap):
//   - Two .quad cells at L_so_addr / L_so_len
//   - The BL near `bl_dlopen` placeholder (NOP at assembly time, BL imm26 patched
//     at rewrite time so it lands on dlopen's PLT)
//
// Build:
//   /opt/android-ndk-r26d/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang \
//       -c -nostdlib -fpic crates/vmp-rewriter/src/bootstrap.S \
//       -o /tmp/bootstrap.o
//   /opt/android-ndk-r26d/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy \
//       -O binary --only-section=.text /tmp/bootstrap.o \
//       crates/vmp-rewriter/src/bootstrap.bin

.section .text
.globl  qvmp_bootstrap
.type   qvmp_bootstrap, %function

qvmp_bootstrap:
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]

    // 1. fd = openat(AT_FDCWD=-100, path, O_RDWR|O_CREAT|O_TRUNC, 0600)
    //    SYS_openat = 56
    //    flags: O_RDWR=2 | O_CREAT=0o100=64 | O_TRUNC=0o1000=512  =>  578 = 0x242
    //    mode:  0o600 = 384 = 0x180
    mov     x0, #-100
    adr     x1, L_path
    mov     w2, #0x242
    mov     w3, #0x180
    mov     x8, #56
    svc     #0
    cmp     x0, #0
    b.lt    L_done                 // open failed; skip everything
    mov     x19, x0                // fd

    // 2. write(fd, embedded_so, embedded_so_len)  ;  SYS_write = 64
    mov     x0, x19
    ldr     x1, L_so_addr
    ldr     x2, L_so_len
    mov     x8, #64
    svc     #0

    // 3. close(fd)  ;  SYS_close = 57
    mov     x0, x19
    mov     x8, #57
    svc     #0

    // 4. dlopen(path, RTLD_NOW=2)
    adr     x0, L_path
    mov     w1, #2
bl_dlopen:
    nop                            // patched to: BL <dlopen_plt_vaddr>

    // 5. unlinkat(AT_FDCWD, path, 0)  ;  SYS_unlinkat = 35
    mov     x0, #-100
    adr     x1, L_path
    mov     w2, #0
    mov     x8, #35
    svc     #0

L_done:
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

.balign 8
L_so_addr:
    .quad   0                      // patched to embedded .so vaddr
L_so_len:
    .quad   0                      // patched to embedded .so byte count

L_path:
    .asciz  "/data/local/tmp/.qvmp.so"

.size qvmp_bootstrap, . - qvmp_bootstrap
