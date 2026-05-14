qvmp_test.zip — v31 加 NativeCall pre-trace + SEGV 全 GPR dump
================================================================

v30 反馈:
  [qvmp] SIGSEGV sig=11
  [qvmp] SIGSEGV pc=536060413072      = 0x7CD8D33490   (库代码段)
  [qvmp] SIGSEGV addr=158712          = 0x26C78        (null + 大偏移?)
  [qvmp] SIGSEGV lr=536060395512      = 0x7CD8D2EFF8   (同库内)

意思是 VM 把控制转给某库的 native 函数，函数立刻去解引用一个低地址，
像是 x0 装的不是真 "this/struct"。要分清是 VM 传给 BLR 的 x0..x7 已
经错了还是 native 函数自身实现问题。v31 加两组数据:

1. **NativeCall pre-trace** (crates/vmp-interpreter/src/lib.rs)
   即将走 BLR 时先打:
     [qvmp] vm: BLR x16 target=0x7c... x0=0x... x1=... ... x7=...
   告诉你 VM 实际传出去的是什么. 如果 x0=0 / x0=0x... 像不像 this，
   一眼就能看出来 lifter 是否漏译了 BLR 前面的 mov x0, ...

2. **SIGSEGV 全 GPR dump** (crates/vmp-soruntime/src/lib.rs)
   SEGV 时把 x0..x30 + sp 全打出来 (31 行 + 1 行 sp). 这是 native
   函数在崩溃瞬间的寄存器状态，能看到它在用什么作 base 算出 0x26C78
   (例: 如果某 xN = 0x26C78 - <offset>，那条 ldr/str 就是元凶).

NativeCall trace 默认跟 --log on 联动（QVMP 头日志位打开就一起打开）.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/
  2. 31_segv_gpr_dump.hardened → 任意位置
  3. MT 双击

把 dispatching region=124 之后开始的所有 [qvmp] 日志全粘回来. 数量
会比之前多 (BLR trace 一行 + SEGV 一堆 GPR), 但全是有用诊断信息.

可能的发现:
  - "[qvmp] vm: BLR x16 target=0x... x0=0x0 x1=0x0 ..." → VM 没给函
    数准备 args，lifter 漏了。
  - "[qvmp] vm: BLR x16 target=0x... x0=0x7c..." 看起来合理 → 但
    SEGV 时 x0 已变 → native 函数被传入的某指针其实是悬空 / 早释放.
  - target=0x0 → BLR 寄存器没填好，前面 ADRP/LDR 没翻译.

MD5:
  31_segv_gpr_dump.hardened  d5772ccabd2becae7c1d9edc5f5eb71a
  libqvmp_runtime.so         32d05e8f82b282214ee54ef5eea91ef0
