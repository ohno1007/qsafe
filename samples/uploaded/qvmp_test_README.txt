qvmp_test.zip — v22 bionic ucontext_t 偏移修复
=================================================

v21 找到了真凶: Rust libc::ucontext_t 用的是 glibc 布局
(sigset_t=128 字节), 但 Android 用 bionic
(sigset_t=8 字节 + 120 字节 padding), 导致 uc.uc_mcontext.pc 读到
错误偏移 (落在 __padding 内, 拿到垃圾值). 用垃圾 PC 当指针解引用 → SEGV.

v22 用 bionic 真实偏移直接读 ucontext bytes:
  pc:        offset 432 (0x1B0)
  regs[N]:   offset 176 + N*8
  __reserved: offset 448

期望日志:

  [qvmp] qvmp_runtime: rodata decrypted in place
  [qvmp] qvmp_runtime: blob loaded, SIGTRAP handler installed
  [qvmp] qvmp_runtime: SIGTRAP handler entered
  [qvmp] qvmp_runtime: PC=<真实 PC 值, 应该是某个 trampoline 地址>
  [qvmp] qvmp_runtime: PC inst=0x<指令字>
  -- 进入 dispatch_vm --
  [qvmp] qvmp_runtime: dispatching region=N
  [qvmp] qvmp_runtime: VM returned region=N
  -- 循环很多次 --
  ... ImGui GUI 起来 ...

只换 libqvmp_runtime.so. MT 管理器双击 23_dt_needed.hardened.

把整段 [qvmp] 日志贴回来 (尤其那个 PC 值和 PC inst).

MD5:
  23_dt_needed.hardened   38c462247de8c6810b8862608b638d3a
  libqvmp_runtime.so      93f6c4058aeee04b58cef5a5cedc90d2
