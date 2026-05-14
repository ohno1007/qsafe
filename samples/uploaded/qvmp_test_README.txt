qvmp_test.zip — diagnostic v17 (handler dlopens cdylib)
========================================================

v16 = error 200 ✓ raw rt_sigaction 装 SIGTRAP handler 成功. BRK 触发后
handler 接住, exit_group(200).

v17 让 handler 真的 dlopen cdylib, 在 signal handler context 里调
(不在 INIT_ARRAY 里), 看能不能绕开栈金丝雀问题.

流程:

  INIT_ARRAY[0] wrapper
   → bl bootstrap
       bootstrap:
         1. write /data/local/tmp/.cachelib (解密 + raw syscall write)
         2. rt_sigaction(SIGTRAP, our_handler)
         3. ret 99
   → b orig_first_init  (这个是 patched 的 → trampoline → BRK)
   → kernel 调用 our_handler
       handler:
         1. dlopen("/data/local/tmp/.cachelib", RTLD_NOW)
         2. cbz x0 → if NULL exit 202
         3. else exit 201
         (没用 sigreturn 回去, 因为我们没装完整 dispatch, 直接拿结果)

期望:

  error 201  → ★ dlopen 从 signal handler context 成功! cdylib 加载成功.
              下一步: handler 不 exit 而是返回 (走 sa_restorer → sigreturn),
              让 BRK 再次 fire 进 cdylib 装好的 SIGTRAP handler.
  error 202  → dlopen 返回 NULL. 可能 .so 写坏了 (decrypt 错) 或路径问题.
              下一步检查写入的 .so 是不是完整.
  error 134  → 栈金丝雀又触发. 即使在 signal handler 里 dlopen 也不行.
              得想别的办法 (比如 fork 子进程 dlopen).
  error 133  → handler 没被调用 (跟 v16 200 ≠ 133 矛盾, 不可能)
  其他       → 告诉我数字

直接 MT 管理器双击 21_handler_dlopen.hardened, 看 error N.

MD5: c84a0dd4c2dbc8bedb9f02c465142618
