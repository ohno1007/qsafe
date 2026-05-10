qvmp_test.zip — diagnostic v10 (instrumented bootstrap)
========================================================

12 / 13 都给 Trap 133，说明 e_entry hijack 起到效果 (没再 abort 134)，
但 cdylib 也没装上 SIGTRAP handler — 中间某步默默失败了。

这次 bootstrap 改成会往 stderr 直接打字母进度，能看到走到哪一步:

  B  - 进 bootstrap
  O  - openat 成功 (拿到 fd)
  F  - openat 失败 (路径写不进去)
  W  - 整段 .so 解密+写完
  C  - 关闭 fd 完
  D  - 准备调 dlopen
  d  - dlopen 返回
  U  - unlinkat 完
  \n - bootstrap 结束

直接跑 14_full_debug.hardened，看终端会打出哪几个字母。

正常应该看到:
  BOWCDd...
  [qvmp] qvmp_runtime: rodata decrypted in place
  [qvmp] qvmp_runtime: blob loaded, SIGTRAP handler installed
  ... ImGui 起来 ...

可能挂的几种姿势:

  只看到 B          → bootstrap 进了但 openat 后第一句 cmp/blt 之前就炸
  BF\n              → openat 失败 (/data/local/tmp/.cachelib 写不进去)
  BO 然后死         → 解密/写循环里炸
  BOWC 然后死      → close 后到 dlopen 之间炸
  BOWCD 然后死     → dlopen 调用进去后没出来 (dlopen 内部 abort)
  BOWCDd 但没 [qvmp] → dlopen 返回了但 cdylib 没起 init (返回 NULL)
  BOWCDd[qvmp]...   → cdylib 起来了，看后面 GUI

把整段终端输出原样贴回来。最关键看那串字母。

MD5:
  796a10775be49f3e734a61ea8fe72177  14_full_debug.hardened
