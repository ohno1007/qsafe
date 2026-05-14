qvmp_test.zip — diagnostic v18 (handler dlopens "libc.so" — already loaded)
============================================================================

v17 = error 139 (SIGSEGV). 在 SIGTRAP handler 里 dlopen 我们的 cdylib 崩了.
不确定是 dlopen 调用本身崩, 还是 cdylib 的 qvmp_init (在 dlopen 内部跑的)
崩了.

v18 用 dlopen("libc.so") 测最简单情况: libc 已经加载, dlopen 只是
bump refcount, 不跑任何 init_array.

  bootstrap: 装 SIGTRAP handler, ret 99
  wrapper:   bl bootstrap; b orig_init → BRK
  handler:   dlopen("libc.so", RTLD_NOW)
             成功 → exit 203
             返回 NULL → exit 204

期望:

  error 203  → ★ dlopen from signal handler 路径成功. 那 v17 SEGV 就
              是 cdylib 的 qvmp_init 内部崩. 下一步需要 debug cdylib init.
  error 134  → 即使最简单 dlopen 也触发栈金丝雀. 整个 dlopen-from-handler
              方案不可行, 得换思路.
  error 139  → dlopen 自己崩了, 跟 cdylib 无关. 也得换思路.
  error 204  → dlopen 返回 NULL (即使是 libc.so) - 极端罕见
  其他       → 告诉我数字

MD5: 6b93d42fbbd0d3c2a796618781467b78
