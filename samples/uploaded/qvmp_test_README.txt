qvmp_test.zip — v24 ucontext 偏移自动定位
==========================================

v23 关键发现:
  si_addr = 0x5805EDC134       (kernel 说的真 PC)
  ucontext.pc(我读) = 0x7FD4D22330  (跟 si_addr 完全不同!)
  inst@si_addr = 0xD42A2AE0    (★ 是 BRK! imm16 高字节 0x51='Q' ✓)
  imm16 低字节 0x57 = region_id 87

确认: SIGTRAP 真的从我们的 trampoline 触发, kernel 也正确告诉我 PC.
但我读 ucontext 的偏移错了 (差 120 字节左右), 所以读 regs[16] 拿到
垃圾, region_id OOB.

v24 自动扫描 ucontext 找到正确偏移:

  - 扫 0..1024 字节, 看哪个 u64 == 87 (region_id, 我们知道这个值)
  - 扫 0..1024 字节, 看哪个 u64 == si_addr (kernel 给我们的 PC)
  - 找到的偏移就是 x16 / pc 实际所在位置

打印两类候选位置, 然后还原 SIG_DFL 自杀退出 (不死循环).

跑完贴日志:
  [qvmp] qvmp_runtime: SIGTRAP handler entered
  [qvmp] qvmp_runtime: si_addr=...
  [qvmp] qvmp_runtime: ucontext.pc=...
  [qvmp] qvmp_runtime: inst@si_addr=...
  [qvmp] qvmp_runtime: expected x16=87
  [qvmp] qvmp_runtime: found x16 candidate at offset=N1   ← 关键
  [qvmp] qvmp_runtime: found x16 candidate at offset=N2 (可能多个)
  [qvmp] qvmp_runtime: found pc candidate at offset=M     ← 关键
  Segmentation fault / Trap

拿到 N (x16 偏移) 和 M (pc 偏移) 我就能写对所有 ucontext 访问.

只换 libqvmp_runtime.so. MT 双击 hardened.

MD5:
  23_dt_needed.hardened   38c462247de8c6810b8862608b638d3a
  libqvmp_runtime.so      47f8a7b0b2e55a0860c9e2d02faaf8e8
