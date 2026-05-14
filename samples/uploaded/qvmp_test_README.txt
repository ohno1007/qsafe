qvmp_test.zip — v23 si_addr 比对 + 死循环止血
==============================================

v22 出现 SIGTRAP 死循环: handler 接到 SIGTRAP, PC=高地址 (0x7FD14E5A30),
PC 上的指令是 ADR X3 (0x30D19763), 不是 BRK, 我们 return, kernel 重复
fire SIGTRAP. 永远不会触发我们的 trampoline.

可能原因:
  1. 我读的 PC offset 错了 (Rust libc 跟 bionic 不一致),
     高地址值是其它字段被误读
  2. PC offset 对的, 但 SIGTRAP 真的从那个非-BRK 地址触发的
     (硬件断点 / ptrace single-step / 你那 launcher 的某种监控)

v23 加两件事:

A. 同时读 siginfo_t.si_addr (kernel 写的"trap 地址") 和 ucontext.pc.
   两者应该一致. 如果差很多 → 我的 PC offset 错.
   用 si_addr 作为权威 PC 来读指令字.

B. 死循环止血: 如果不是 BRK, 还原 SIGTRAP 为默认 (SIG_DFL), kernel 接下来
   把进程杀掉, 至少不会卡死.

期望日志:

  [qvmp] ... rodata decrypted in place
  [qvmp] ... blob loaded, SIGTRAP handler installed
  [qvmp] ... SIGTRAP handler entered
  [qvmp] ... si_addr=<X>            ← kernel 说的 trap 地址
  [qvmp] ... ucontext.pc=<Y>        ← 我读的 PC
  [qvmp] ... inst@si_addr=<I>       ← si_addr 指向的指令字
  -- 然后看 inst 是不是 BRK --
  if BRK: [qvmp] ... dispatching region=N ...
  if NOT: [qvmp] ... not a BRK; restoring SIG_DFL...
  -- 然后进程死, 不再死循环 --

关键看:
  X == Y? 如果一样 → 我的 PC offset 对的, SIGTRAP 真从那地址触发
  X != Y? 数差多少 → 算出正确 offset

X 是真 PC. 如果 X 在主 exec 范围内 (= load_bias + 主 binary vaddr),
inst 应该是 BRK (0xD42...), 那我们就能 dispatch.
如果 X 在 high address (cdylib 或其它 .so 范围), 那 SIGTRAP 来源不是我们
的 trampoline, 是别的什么东西.

只换 libqvmp_runtime.so, MT 双击 23_dt_needed.hardened, 把前几条日志贴回来.

MD5:
  23_dt_needed.hardened   38c462247de8c6810b8862608b638d3a
  libqvmp_runtime.so      11167db729f9f81ea6184c35ae3c3513
