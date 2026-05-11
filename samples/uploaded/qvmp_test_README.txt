qvmp_test.zip — diagnostic v15 (INIT_ARRAY[0] + exit_group)
============================================================

v14 双 hook 还是 error 133. 即 launcher 既不走 e_entry 也不走 _start[0].
最可能的解释: **launcher 把 binary 当 shared lib 用 dlopen 加载**, 这种
情况下 dlopen 只会跑 INIT_ARRAY, 不调用 _start / e_entry.

这次劫持 INIT_ARRAY[0] 的 R_AARCH64_RELATIVE 重定位, 让它指向我们的
wrapper. wrapper 内部:

  stp x29,x30,[sp,#-16]!
  bl bootstrap         ; bootstrap 还是 mov x0,#99; ret
  ldp x29,x30,[sp],#16
  mov x8, #93          ; SYS_exit
  svc #0               ; exit_group(x0) — x0 = 99 from bootstrap

期望:

  error 99   → ★ launcher 走 INIT_ARRAY! 我们终于找到正确的 hook 点.
              下一步换回 full bootstrap (但不调 dlopen during INIT_ARRAY,
              避免栈金丝雀问题) — install SIGTRAP handler via raw syscall,
              handler 自己负责后续 dlopen.
  error 133  → launcher 连 INIT_ARRAY 都不调... 那它在干啥? 直接读取并
              解码 binary 字节执行某个特定符号? 比如 main? __libc_init?
  其他       → 告诉我具体数字

直接 MT 管理器双击 19_init_array_99.hardened, 看 error N.

MD5: 8c49a99ac96c854e5f97e5c47978d751
