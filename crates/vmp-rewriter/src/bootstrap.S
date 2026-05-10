// Bootstrap stub injected into hardened ELF's INIT_ARRAY.
//
// Lifecycle (called once at process start, after libc/libdl mapped):
//   1. open(PATH, O_RDWR|O_CREAT|O_TRUNC, 0600) → fd
//   2. for each 256-byte chunk of the embedded (encrypted) runtime .so:
//        decrypt chunk into a stack buffer via XOR with 8-byte rotating key
//        write(fd, stack_buf, chunk_len)
//   3. close(fd)
//   4. dlopen(PATH, RTLD_NOW) — via main ELF's existing dlopen@plt
//   5. unlinkat(AT_FDCWD, PATH, 0)
//   6. ret
//
// The on-disk image of the embedded runtime is XOR-encrypted with an 8-byte
// per-build random key — `strings` / `grep` over the hardened ELF will not
// pick up Rust panic strings, crate paths, or the QVMP magic of the inner
// blob format.
//
// External patch points (filled in by vmp-rewriter::bootstrap::patch_bootstrap):
//   .quad cells L_so_addr, L_so_len, L_key — runtime vaddrs / byte counts /
//   8-byte key. The placeholder NOP at `bl_dlopen` becomes BL <dlopen_plt>.
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

#define CHUNK 256

qvmp_bootstrap:
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    sub     sp, sp, #CHUNK              // stack chunk buffer

    // ----- 1. fd = openat(AT_FDCWD=-100, PATH, O_RDWR|O_CREAT|O_TRUNC, 0600) -----
    mov     x0, #-100
    adr     x1, L_path
    mov     w2, #0x242                  // O_RDWR|O_CREAT|O_TRUNC = 578
    mov     w3, #0x180                  // 0o600
    mov     x8, #56                     // SYS_openat
    svc     #0
    cmp     x0, #0
    b.lt    L_done
    mov     x19, x0                     // x19 = fd

    // ----- 2. chunked decrypt + write -----
    ldr     x20, L_so_addr              // src ptr (encrypted .so bytes)
    ldr     x21, L_so_len               // remaining = total .so bytes
    adr     x22, L_key                  // 8-byte rotating XOR key base
    mov     x9, sp                      // x9 = stack chunk dst
    mov     x10, #0                     // global offset (for key indexing)

L_chunk_loop:
    cbz     x21, L_chunk_done
    mov     x11, #CHUNK
    cmp     x21, x11
    csel    x11, x21, x11, lt           // x11 = chunk_len = min(remaining, CHUNK)
    mov     x12, #0                     // i within chunk
L_inner:
    ldrb    w13, [x20, x12]             // src byte
    add     x14, x10, x12               // global offset
    and     x14, x14, #7
    ldrb    w15, [x22, x14]             // key byte
    eor     w13, w13, w15
    strb    w13, [x9, x12]
    add     x12, x12, #1
    cmp     x12, x11
    b.lt    L_inner

    // write(fd, stack_buf, chunk_len)
    mov     x0, x19
    mov     x1, x9
    mov     x2, x11
    mov     x8, #64                     // SYS_write
    svc     #0

    add     x20, x20, x11               // src += chunk
    add     x10, x10, x11               // global_off += chunk
    sub     x21, x21, x11
    b       L_chunk_loop

L_chunk_done:
    // ----- 3. close(fd) -----
    mov     x0, x19
    mov     x8, #57                     // SYS_close
    svc     #0

    // ----- 4. dlopen(PATH, RTLD_NOW=2) -----
    adr     x0, L_path
    mov     w1, #2
bl_dlopen:
    nop                                 // patched to BL <dlopen_plt_vaddr>

    // ----- 5. unlinkat(AT_FDCWD, PATH, 0) -----
    mov     x0, #-100
    adr     x1, L_path
    mov     w2, #0
    mov     x8, #35                     // SYS_unlinkat
    svc     #0

L_done:
    add     sp, sp, #CHUNK
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

.balign 8
L_so_addr:
    .quad   0                           // patched: encrypted .so vaddr
L_so_len:
    .quad   0                           // patched: encrypted .so byte count
L_key:
    .quad   0                           // patched: 8-byte XOR key

L_path:
    .asciz  "/data/local/tmp/.cachelib"

.size qvmp_bootstrap, . - qvmp_bootstrap
