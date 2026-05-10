qvmp_test.zip — diagnostic v8 (dlopen-during-INIT_ARRAY narrow bisect)
=====================================================================

v7 结果:
  7_bootstrap_noop      Trap 133 (wrapper / hijack 都正常)
  8_bootstrap_dlopenonly  stack corruption detected (-fstack-protector) Aborted
                          → dlopen 在 INIT_ARRAY 上下文里调用就会触发栈保护

定位到根本问题: 在 main exec 的 INIT_ARRAY 期间调 dlopen() 导致 bionic
__stack_chk_fail. 可能是 dlopen 内部的栈使用方式跟我们这个 frame 不兼容。

新增两个变体进一步细分:

  9_dlopen_null.hardened
    bootstrap 调 dlopen(NULL, RTLD_NOW)。
    NULL path → 返回主可执行的 handle，理论上不可能失败。
    如果 9 也 abort → dlopen 调用本身在 INIT_ARRAY 里就有问题，跟 path 无关
    如果 9 正常 → 是路径不存在导致的栈问题

  10_dlopen_libc.hardened
    bootstrap 调 dlopen("libc.so", RTLD_NOW)。
    libc 已经加载，dlopen 应该只是增加引用计数。
    如果 10 正常 → 通过 dlopen 是 OK 的，只是某些路径状态会出问题
    如果 10 也 abort → 任何 dlopen 在 INIT_ARRAY 都会炸

可能的结果矩阵:

  9 abort & 10 abort → dlopen 在 INIT_ARRAY 上下文完全不能用，要换思路
                       (比如改 e_entry 让 bootstrap 在 INIT_ARRAY 之前跑)
  9 OK & 10 OK     → dlopen OK，是 .cachelib 路径状态搞坏栈
                     可以调整 path 或写法让 dlopen 找到合法 .so
  9 abort & 10 OK  → 特定状态，可定位 fix

跑 9 和 10，看哪个 abort 哪个 OK。

MD5:
  f1771a998df01db44c918f2517636d20  7_bootstrap_noop.hardened
  c8b51a47c07cfc920053f4b93837ddc4  8_bootstrap_dlopenonly.hardened
  9be275a99e85744e0c2292eb86b9ca51  9_dlopen_null.hardened
  b35c190f160859be90020e39df0e0fe6  10_dlopen_libc.hardened
