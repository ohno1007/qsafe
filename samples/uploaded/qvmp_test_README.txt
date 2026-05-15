qvmp_test.zip — v45 指数二分: 6 个包逐倍扩大保护范围
=======================================================

A (1 region) 出 UI, B (534 regions) 挂在 #128 → 中间某一段 region 引入 bug.
A 跑通说明机制 ok, 现在指数二分找出转折点.

6 个包:
  45_n2.hardened    保护 region 0..2     (entry + 1 个)
  45_n4.hardened    保护 region 0..4
  45_n8.hardened    保护 region 0..8
  45_n16.hardened   保护 region 0..16
  45_n32.hardened   保护 region 0..32
  45_n64.hardened   保护 region 0..64

**只测试这一组**, 每个跑一遍, 报告:
  n2:  UI / SIGSEGV
  n4:  UI / SIGSEGV
  n8:  UI / SIGSEGV
  n16: UI / SIGSEGV
  n32: UI / SIGSEGV
  n64: UI / SIGSEGV

第一个 SIGSEGV 的 N 就是关键 — bug 在 region [N/2, N) 范围内. 下一轮我做
更细致的二分.

测试技巧: 把所有 6 个 hardened 都 push 到 /data/, 逐个双击.
.so 一份, 共用.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (用 v44 那一份, md5
     850e2eb263eec3c55b8eb9517a35a2f3)
  2. 任选一个 45_nXX.hardened → /data/, MT 双击
  3. 不挂(出 UI)就关掉换下一个

MD5:
  45_n2.hardened   04289256a558eab4b9bf503a658dad06
  45_n4.hardened   dccfefc0e33e6ba76c8cf43c002088a1
  45_n8.hardened   6e40a29bd3982011c4ebdabff0ad2933
  45_n16.hardened  9282a2f6f004b7b001460b597beb3abd
  45_n32.hardened  a72b8d5f883f21dfd02e4f3ebad020f6
  45_n64.hardened  0b8c1a9c9b31037ef9f9fa04e6370709
