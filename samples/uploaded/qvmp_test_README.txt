qvmp_test.zip — diagnostic v13 (最小可能验证)
============================================

v12 你看到 Trap 133. 这意味着 bootstrap 中间崩了，没走到 shim 的 exit_group.
但 bootstrap 一开始就 mov x24=11, 应该至少返回 11. 没返回说明确实崩了.

为了排除"bootstrap本身就崩"，这次 bootstrap 干脆只剩两条指令:

  qvmp_bootstrap:
      mov x0, #99      ; 设置返回值 99
      ret              ; 返回

shim 跑完 bootstrap 后 exit_group(99)。

期望结果: MT 管理器对话框显示 "error 99"

如果你看到:
  error 99   → ★ shim + bootstrap call/return + exit_group 完全 OK，
              说明问题真的在 bootstrap 里 dlopen / 写 .cachelib 那部分代码
              里某条指令崩.
  error 133  → 即使最小 bootstrap 也崩了，那 e_entry shim 本身或
              bl/ret 调用机制在你这个环境下就有问题
  error 139  → SIGSEGV 在 shim/bootstrap 的入栈/出栈过程
  其他       → 信号触发的退出码,告诉我具体数字

直接 MT 管理器双击运行，看对话框里的 error 数字告诉我。

MD5: 45f5beb7210b630d39bfc196efdc8158
