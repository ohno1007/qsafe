qvmp_test.zip — v39 终极 A/B：no-trampolines 包，不动 .text 看是否还挂
========================================================================

v38 反馈:
  leaf-only (无 BLR/CallRegion 的 region) 也挂同样位置. SEGV 时寄存器
  pattern 跟 v37 高度一致: x4=128, x6=0x8000000000000000, x11≈0xFFFFFFFF,
  x13≈20416, x15=32, x25=8. 多次复现都是这套. 说明同一行 native 代码
  在跑, 拒绝 "VM 间接调用是元凶" 的假说.

最关键的结论是 **bug 跟我们改了多少 VM 行为无关**. 三个变体都同位置挂.

v39 做终极对照: `--write-trampolines false`. 完全不动 .text 任何字节,
不装任何跳板. 但保留:
  - rodata XOR 加密 + 运行时由 cdylib 在 .init_array 解
  - QVMP blob 嵌入 (734KB payload)
  - DT_NEEDED 加载 libqvmp_runtime.so
  - cdylib 的 SIGTRAP/SIGSEGV handler 安装

protect 还是 standard, 但 patched_entries=0. 整个 .text 跟原 binary
字节相同, 所有函数都纯 native 跑.

A/B 实验:
  - 如果 39_no_trampolines.hardened **能起 ImGui UI**:
    \-> 残留 bug 在 trampoline 写入 / VM 执行. 加密 + .so loading 是
       清白的. 下一步: 用 protect --only / --exclude 二分法定位坏的
       那个具体 region.
  - 如果 39_no_trampolines.hardened **同样位置挂**:
    \-> 残留 bug 在 rodata 加密 / .so loading / mprotect 引发的页权限
       变化. 我得换更核心的角度 (e.g. mprotect 4K vs 16K 对齐, .so 加
       载顺序破坏 C++ 全局构造顺序).

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (沿用上一份 .so 不用换)
  2. 39_no_trampolines.hardened → 任意位置
  3. MT 双击

把日志全粘. 如果出 UI 就告诉我 "出 UI 了" 就行, 不用粘日志.

MD5:
  39_no_trampolines.hardened  59702b0737c55b5d8ea25239cc0fc437
  libqvmp_runtime.so          f06a1ee8de96935d7ea8740eb3b874db (跟之前同)
