qvmp_test.zip — diagnostic v16 (SIGTRAP handler install probe)
==============================================================

v15 = error 99 ✓ INIT_ARRAY[0] hijack 起作用, launcher 真的走 INIT_ARRAY.

下一步避开"在 INIT_ARRAY 里调 dlopen 触发栈金丝雀"的问题. 思路:

  1. INIT_ARRAY[0] wrapper 通过 raw rt_sigaction syscall 装一个最小
     SIGTRAP handler (没调 libc, 没 dlopen)
  2. wrapper 然后正常 tail-call 原 INIT_ARRAY[0] 函数
  3. 其他 INIT_ARRAY entries 跑下去, 总会有个调到保护函数 → BRK
  4. 我们的 SIGTRAP handler 接住, 处理

v16 是"测试 handler 安装路径能不能起作用"的诊断版. handler 不做正经
活, 接到 BRK 就 exit_group(200).

  bootstrap:
      在栈上 build sigaction 结构 (handler=&handler_exit_200, flags=SA_SIGINFO|RESTORER|RESTART)
      rt_sigaction(SIGTRAP, &sa, NULL, 8)
      ret with x0 = 99
  wrapper:
      bl bootstrap
      b orig_first_init  ; 这个会触发被保护函数的 trampoline → BRK
  handler:
      mov x0, #200
      SYS_exit_group
      svc #0

期望:

  error 200  → ★ raw syscall 装 SIGTRAP handler 成功, BRK 被我们接住.
              下一步在 handler 里 dlopen cdylib (signal context, 不在
              INIT_ARRAY 里, 应该避开金丝雀).
  error 133  → handler 没装上 (rt_sigaction syscall 失败) 或者没被调用.
              需要 debug rt_sigaction 参数.
  error 99   → wrapper 跑完 bootstrap, b orig_init 没触发 BRK?? 不可能,
              orig_init 已经 patched, 必定 BRK.
  其他       → 告诉我具体数字

直接 MT 管理器双击 20_sigtrap_install.hardened, 看 error N.

MD5: ece825bab204f8e33475578050542b16
