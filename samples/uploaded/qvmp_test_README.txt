qvmp_test.zip — v38 leaf-only 包：只保护无 BLR/CallRegion 的"叶子函数"
========================================================================

v37 反馈:
  light 跟 standard 在完全一样的位置挂. 说明 root cause 不在 junk 或
  handler_duplication, 而在 VM 核心机制. SEGV 时 pc=0x781A0AC8E0
  这种地址跟之前 region 9 (free thunk) 返回的 heap 指针 (0xb40000781a...)
  高位匹配 — 程序把 **heap 数据当函数指针调用** 了, 最典型的就是
  vtable 损坏 (虚函数 dispatch 拿到野指针).

继续往下查难度很大: 没符号 + ImGui 的 C++ 代码大量 -fomit-frame-pointer
让 fp-chain 走不动 + bug 在不带 BLR trace 的某个 region 内部.

v38 做隔离实验: 加 `QVMP_LEAF_ONLY=1` env, protect 时丢掉所有含 BLR
(NativeCall) 或跨 region 调用 (CallRegion) 的 region. 这一类是最可能
踩 VM 间接调用相关 bug 的. 90 个 region 被丢, 剩 444 个纯叶子.

被丢的包括:
  - region 124 (Vulkan loader, 70+ BLR)
  - region 145 (vtable dispatch)
  - region 127 (operator new wrapper, br x2 tail call)
  - region 8/9 (malloc/free thunks)
  - 各种 indirect call helper

剩下的都是无间接调用的纯计算函数 — getter, setter, simple math, 各种
小 helper. 这类 VM 翻译风险最低.

A/B 实验方向:
  - 如果 38_leaf_only.hardened 能起 ImGui UI → 残留 bug 100% 锁定在
    含间接调用的 region. 下一步针对 NativeCall + VM 状态做更深入修.
  - 如果还是同样位置挂 → root cause 更深 (rodata 解密? FP 寄存器没传?
    syscall 缺翻译?), 我得换思路.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (沿用 v37 那份, 没换 .so)
  2. 38_leaf_only.hardened → 任意位置
  3. MT 双击

把日志全粘回来. 即使挂了也好, log 的形状会比之前更稀, 信噪比更高.

MD5:
  38_leaf_only.hardened  e8a0b7e7722b0a5477894499e5895b8d
  libqvmp_runtime.so     (跟 v37 standard 同, f06a1ee8de96935d7ea8740eb3b874db)
