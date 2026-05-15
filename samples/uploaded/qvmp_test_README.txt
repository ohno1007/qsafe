qvmp_test.zip — v44 终极二分: 单 region 保护 vs 全量 + handler 计数器
========================================================================

v43 (全量 standard, 无 malloc/Once/Instant) 还是相同位置挂. 说明真正
的 root cause 不是 async-signal-safety. 必须用最小集合确认是机制问题
还是累积问题.

v44 同时出两个包:

A. **44A_only_r0.hardened**: **只保护 region 0** (entry region 一个).
   全程只会有一次 SIGTRAP (entry trampoline 触发一次). 如果挂了 → 单
   次 handler 就会破坏状态, 是机制问题. 如果出 UI → 至少证明 handler
   单次可用, bug 是累积的.

B. **44B_full.hardened**: 完整 534 region (跟 v43 一样). 加 handler
   计数器: handler 每进入一次累 1, 在 N 是 2 的幂或 1000 倍数时打:
     [qvmp] handler entry #N
   能告诉我们挂之前总共 SIGTRAP 多少次. 如果 N 在挂前已经几千几万,
   那肯定是累积; 如果只有几百, 那就是某次具体 dispatch 出问题.

测试顺序:
  1. 跑 A. 出 UI 还是 SIGSEGV?
  2. 跑 B. 看最后一行 "handler entry #N" 是多少, 再看 SIGSEGV 那一段.

报告格式:
  A: 出 UI / SIGSEGV
  B: 出 UI / SIGSEGV 时计数器 N = ____

不用粘整段日志, 只要这两个数据点.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (新 .so, 必须更新)
  2. 44A_only_r0.hardened 或 44B_full.hardened → 任意位置
  3. 双击运行

MD5:
  44A_only_r0.hardened  4f64318979a07a4a2726f731b538b483
  44B_full.hardened     7e12b735c4fcdc3a33012025d8eb3473
  libqvmp_runtime.so    850e2eb263eec3c55b8eb9517a35a2f3
