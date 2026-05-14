qvmp_test.zip — v25 dump ucontext bytes 176..472
==================================================

v24 找到了 pc 在 offset 440 (而不是我猜的 432, 差 8 字节). 但没找到
x16=87 在任何位置. 怪.

这版直接 dump ucontext[176..472] 范围内所有 u64 值, 一个偏移一行,
让我们肉眼挑出谁是 x16 (= 87), 谁是 x30 (= LR, 大地址), 谁是 sp.

期望日志格式 (大量):
  [qvmp] qvmp_runtime: uc[176]=<v>     ← 应该是 fault_address (从 sigcontext 看)
  [qvmp] qvmp_runtime: uc[184]=<v>     ← 应该是 regs[0]
  [qvmp] qvmp_runtime: uc[192]=<v>     ← regs[1]
  ...
  [qvmp] qvmp_runtime: uc[312]=<v>     ← 标准 layout 下应该是 regs[16] = 87
  ...
  [qvmp] qvmp_runtime: uc[424]=<v>     ← regs[30] = LR
  [qvmp] qvmp_runtime: uc[432]=<v>     ← sp
  [qvmp] qvmp_runtime: uc[440]=<v>     ← pc (已确认)
  [qvmp] qvmp_runtime: uc[448]=<v>     ← pstate

我们找:
  - 哪个 offset 的 u64 等于 87 (region_id) → x16 真实偏移
  - 哪个 offset 的 u64 是 PC 附近的某值 → LR

把全部 uc[N]=V 行都贴回来. 数据很多但有规律, 我能从中识别字段位置.

MD5:
  23_dt_needed.hardened   38c462247de8c6810b8862608b638d3a
  libqvmp_runtime.so      2298906c67d659faf8271d9b1a9eda02
