qvmp_test.zip — v35 嵌套 BRK 修复：BLR 到 trampoline 改走 VM 内调度
=====================================================================

v34 反馈 (重大进展):
  region 124 全过, x0 = 0x...58e3 ✓ junk 寄存器冲突修对了
  malloc/free thunk 跑了一大堆轮
  region 8/9/12/25/3/13/6/2/105 等等都跑通
  最后 dispatching region=127 + 单个 BLR → Trap (exit 133)

ROOT CAUSE:
  region 127 的 BLR x2 target=0x57e914b058
    load_bias = 0x57e8fb8000 (从 region 124 1st BLR x0 反推)
    target - load_bias = 0x193058
  这个地址不是 PLT thunk, 是**另一个被保护 region 的 trampoline 入口**.
  VM 把它 transmute 成 fn_ptr 然后跳过去, trampoline 第二条指令是 BRK
  → 触发嵌套 SIGTRAP. 但 install_sigtrap_handler 没设 SA_NODEFER, 内核
  把 SIGTRAP mask 掉, "信号在被 mask 时再次产生" 默认动作 = 终止进程
  (signal 5 = exit 133).

修两层:
1. **NestedDispatchHost.native_call (crates/vmp-stub/src/entry.rs)**
   target 进来时先用 `load_bias + region.patch_addr` 反查所有 534 个
   region. 命中就走 vm_call_region_fp 在 VM 内部递归调度, 避免出 VM
   再回 VM, 顺带省两次 signal 上下文切换.
2. **install_sigtrap_handler (crates/vmp-soruntime/src/lib.rs)**
   sa_flags 加 SA_NODEFER, 当 fallback 防御. 万一上面查找漏了什么
   边缘情况也能再次进 handler 而不是被 mask 掉.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (md5 变了, 必须更新)
  2. 35_trampoline.hardened → 任意位置
  3. MT 双击

预期: region 127 的 BLR 命中其它 trampoline 时, log 会显示嵌套
"dispatching region=X" 而不是 trap. 后续应该跑得更远 — 这次的 fix
跟 v34 类似是系统性的, 任何函数指针指向被保护 region 的场景都受益.

MD5:
  35_trampoline.hardened  7e12b735c4fcdc3a33012025d8eb3473
  libqvmp_runtime.so      10ce7424ba730fc89588171286ad7bf9
