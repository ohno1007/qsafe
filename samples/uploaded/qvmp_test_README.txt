qvmp_test.zip — diagnostic v14 (双重 hook: e_entry + _start[0])
=================================================================

v13 你看到 17_min99 也是 error 133. 即使 bootstrap 只是 `mov x0,#99; ret`,
进程还是 SIGTRAP 死. 说明 **e_entry hijack 在你的环境里没起作用** —
启动器没读 ELF header 的 e_entry, 直接跳到原 _start (0xfae00).

这版加了 belt+suspenders: 同时改两处.

  1. e_entry (ELF header offset 0x18) → 我们的 shim (0x370000)
  2. 原 _start (vaddr 0xfae00) 第一条指令 → B 0x370000 (跳到 shim)

不管启动器用 e_entry 还是直接跳 _start, 都会进我们的 shim.

原 _start[0] 是 BTI C (一个 NOP 类的"分支落点标记"), 跳过它不影响后续
_start 执行. shim 跑完 bootstrap 后会 `b _start+4` 继续原逻辑 (但这版
还是诊断模式 exit_group, 不走到 _start+4).

bootstrap 还是最小化的 `mov x0,#99; ret`. 期望:

  error 99   → ★ dual hook 起作用了, shim → bootstrap → exit_group 全通
  error 133  → 连双 hook 都没用, 说明启动器从更深层绕过去了
  其他       → 告诉我具体数字

直接 MT 管理器双击 18_min99_dual_hook.hardened, 看 "进程已结束 (error N)"
告诉我 N.

MD5: e04a73a6edf41fd708ebe5067db7de7b
