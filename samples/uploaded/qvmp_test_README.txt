qvmp_test.zip — v48 探针 + global_asm 重写 FP 调用蹦床
==========================================================

# v47 的问题

v47 silently 挂 (no logs). 但 .so 看着正常, 符号完整, 程序段对.
怀疑两个方向:
  A) inline asm! 的寄存器分配跟 BIND_NOW 之类的 .so 链接特性互冲
  B) qvmp_init 根本没跑到 (dlopen 失败 / 文件没刷)

v48 改两处帮排查:

1. **`crates/vmp-soruntime/src/lib.rs`** 在 qvmp_init 开头加一行**不经
   LOG_FLAG 控制**的 raw_write `[qvmp] qvmp_init: enter`. 这是探针:
     - 看到这行 → .init_array 跑了, .so 链接 OK; 然后 LOG_FLAG 也设上,
       后续 log_msg 才会出来.
     - 没看到 → dlopen 没跑成功 (deploy 没刷 .so / 路径不对 / .so 不兼容).

2. **`crates/vmp-stub/src/linux.rs`** 把 call_with_fp 从 `core::arch::asm!`
   inline 改成 `core::arch::global_asm!` 写一个 naked 函数 `qvmp_call_with_fp`.
   Rust 寄存器分配器完全不介入, 整个 ABI 由我们汇编直接定义:
     x0 = target, x1 = gpr_ptr, x2 = fpr_ptr  (入)
     x0, x1 = (gpr_ret, fpr_ret)              (出)

   这样 inline asm 跟 Rust register coloring 的任何潜在冲突彻底消除.

# 包

48_full.hardened: standard 534 region 全量, embed-runtime, 单文件双击.
libqvmp_runtime.so: 配套 .so (此 build 不依赖, 但还是放着).

# 部署

  1. 48_full.hardened → 任意位置
  2. MT 双击

# 预期

A) 看到 `[qvmp] qvmp_init: enter` 一行就够告诉我 .so 加载了; 后面再看
   能不能看到 `handler entry #1` 等正常日志.
B) 如果 v48 跑得跟 v46 一样 (从 handler #1 一路 log 到 handler #128 后
   SIGSEGV), 说明 FP 修复也没生效 — 我的诊断方向错了.
C) 如果 v48 一路 log 但比 v46 跑得远 (handler #N 远超 128), 说明 FP fix
   起作用了.
D) 如果 v48 还是 `[qvmp] qvmp_init: enter` 之后立刻挂, 那是我的 asm 调
   用约定有问题, 已经可以缩到 call_with_fp.

# MD5

  48_full.hardened    589b9143a2ec06dcb22930a44715d5f8
  libqvmp_runtime.so  db1a3a437a70c20742dca8e01fe1a632
