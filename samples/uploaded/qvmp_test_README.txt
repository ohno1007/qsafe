qvmp_test.zip — v26 真正 dispatch（用上 v25 找到的正确 ucontext 偏移）
======================================================================

v25 的 dump 给出了答案：

  uc[184] = regs[0]            （我之前猜 176，差 8 字节）
  uc[312] = regs[16] = 19       ← 真实 region_id，不是 BRK imm16 解出来的 87
  uc[424] = regs[30] = LR
  uc[432] = sp
  uc[440] = pc                  ← 跟 si_addr 完全一致
  uc[456] = __reserved 起点

`patcher.rs` 里 BRK imm16 = 0x5156 | (region_id & 0xFF) 用的是 OR，
所以多个 region_id 会撞到同一个 imm16。region 19 (0x13) 跟 region 87 (0x57)
都解出 0x57 → 这是 v25 看到 "expected x16=87 但实际是 19" 的原因。
现在 handler 直接信 x16（由 mov x16, #region_id 写入的全值），不再用
imm16 去算 region_id。

这版改动：
  1. UC_REGS_OFFSET 176 → 184
  2. UC_PC_OFFSET   432 → 440
  3. UC_RESERVED_OFFSET 448 → 456
  4. 砍掉 v25 的 dump 代码 + 早退 SIG_DFL
  5. handler 真的走到 dispatch_vm_fp，写回 x0/d0 + PC := LR

期望日志（按顺序）：
  [qvmp] qvmp_runtime: rodata decrypted in place
  [qvmp] qvmp_runtime: blob loaded, SIGTRAP handler installed
  [qvmp] qvmp_runtime: dispatching region=19
  [qvmp] qvmp_runtime: VM returned region=19
  [qvmp] qvmp_runtime: dispatching region=<next>
  ...
  <ImGui 窗口应该出来>

如果挂了：
  - "dispatching region=N" 之后没 "VM returned" → 第 N 个 region 在 VM 里
    SEGV 或越界，把 N 报回来。
  - "VM ERROR for region=N" → VM 自己抛错，把 N 报回来。
  - 完全没 dispatching → handler 没识别成 QVMP BRK，把日志全贴。
  - error 134 stack corruption → bionic canary，回报启动点。

MD5:
  26_dispatch.hardened   5b587b82d1fe3f37a6f4b0501794db3e
  libqvmp_runtime.so     177690030ed9401363d0fd228e380396
