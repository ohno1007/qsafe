qvmp_test.zip — v47 真·真 root cause: FP 寄存器从未传给 native callee
=====================================================================

(回应反馈: v45 n64 实际能一直跑稳定. 那就说明 v46 的"pool exhausted"
推断本身就走错了树. n64 UI 功能错乱 = wrong float args 算出 wrong UI
布局; 0..534 全量挂 = 同一 bug 走到更深的 FP 路径触发 vtable 错位.)

# 真因

VM 解释器的 `VOp::NativeCall` 只把 `regs[0..8]` 透传给 host:
  - LinuxHost.native_call 用 `transmute::<_, F8>` 调 callee
  - F8 是个普通 `extern "C" fn(u64, u64, ..., u64)`, Rust ABI 只搬 GPR
  - 整个调用过程 hardware V0..V7 从未被显式装载!

效果:
  - SIGTRAP 触发那一刻 hardware V0..V7 = caller 传给被保护函数的 float args
  - VM 在内部 fregs[] 里做 FAdd/FMul/SCvtF 各种 FP 运算 (软件层)
  - VM 走到 BLR x8 → NativeCall → callee 看到的是 SIGTRAP 那一刻的
    stale hardware V0..V7, 完全不是 VM 算出来的结果

ImGui / Vulkan 大量用 v0..v7 传 float / ImVec2 / ImVec4 / 矩阵元素.
拿到 stale FP arg → 算出错误 size / offset → vtable lookup 错位 →
跑一段时间 (堆积出某个特定调用链) → SEGV at heap-PC.

n64 子集 UI "错乱" + 不挂: 0..63 region 里 FP-heavy 调用链不够深, 错
得到的 float 值还能落进合法地址区间, UI 看着花但不会撞墙.
全量 0..534: FP-heavy 路径打开, 一两秒就死.

# 修复 (v47)

`crates/vmp-stub/src/linux.rs` 加 `call_with_fp` 蹦床 (inline asm):
  - ldp d0, d1, [fpr_ptr]; ldp d2, d3, ... ; ldp d6, d7, ...
  - inlateout("x0".."x7") = gpr[0..8]
  - blr target
  - fmov x_ret, d0  → 把 FP 返回值带回

`crates/vmp-interpreter/src/lib.rs` VOp::NativeCall 改走 native_call_fp,
同时传 GPR + FREG; 返回时写回 regs[0] + fregs[0] 低 64 位.

`crates/vmp-stub/src/entry.rs` NestedDispatchHost.native_call_fp 透传
fpr_args 给 resolve_to_region 的递归路径 (跨保护函数互调也保 FP arg).

# 包

47_full.hardened: standard 534 region 全量包, 单文件可双击.
libqvmp_runtime.so: 配套 .so, 必须更新.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (md5 必须对上)
  2. 47_full.hardened → 任意位置
  3. MT 双击

# 预期

n64 之前 UI 功能错乱的地方应该都正常了 — 因为 float arg 不再是 stale.
0..534 全量启动 → ImGui 正常出 UI, 长跑不挂.

# MD5

  47_full.hardened    90250f0467e19dd619267e6fa4d82917
  libqvmp_runtime.so  6a0cc1702079f464af810f171b89587f

# 排查方向

如果还挂:
  - 检查 sigsegv handler 打出来的 x0..x7 是否仍带"sign-bit 0x8000..." 的
    异常值: 是 → 这条 FP 路径没覆盖 (比如 NEON Q-reg 128bit 传参)
  - 出现 Eb2:E:E1:... (NoRegion) → 又是 cli cascade-drop 漏过滤
  - 出现 Eb3 (pool exhausted) → 真的递归超 200 层, 极不寻常
