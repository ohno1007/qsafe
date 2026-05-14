qvmp_test.zip — v21 handler entry tracing
==========================================

v20 没看到 "dispatching region=" 日志 → handler 要么没被调用，要么早期 return。
这版 handler 一进来就 log 一行无条件标记，并且每个 return 分支都加 log，
告诉我们 handler 是否被调用、走到哪个分支。

期望日志(顺序):

  [qvmp] qvmp_runtime: rodata decrypted in place
  [qvmp] qvmp_runtime: blob loaded, SIGTRAP handler installed
  -- 然后 main exec INIT_ARRAY 开始跑 --
  [qvmp] qvmp_runtime: SIGTRAP handler entered           ★ 第一个 BRK
  [qvmp] qvmp_runtime: PC inst=0x<指令字>               ★ 触发的指令
  [qvmp] qvmp_runtime: dispatching region=N             ★ 进入 dispatch
  [qvmp] qvmp_runtime: VM returned region=N             ★ dispatch 成功返回
  -- 后面 N 个类似的循环 --

可能的结果:

  情景 A — 看不到 "SIGTRAP handler entered"
           → handler 完全没被调用. SEGV 来源不是 BRK 而是其他原因
             (比如 cdylib 加载完后 main exec INIT_ARRAY 的 C++ static
              init 内部访问坏内存, 跟我们的修改有关).
  
  情景 B — 看到 entered + PC inst, 然后看到 "not a BRK" 或 "foreign BRK"
           → 触发的不是我们的 trampoline BRK. PC 上的指令 word 能告诉
             我们触发了什么. 然后 handler return, SIGTRAP 默认 kill (133).
             但你看到 139, 那这种情况 SEGV 应该来自后续.
  
  情景 C — 看到 entered + PC inst (是 0xd42a... BRK), 看到 dispatching
           然后 SEGV → 我们已经知道，dispatch_vm 内部崩, 需要更细 log
  
  情景 D — 看到 entered, 然后 SEGV (没看到 PC inst log)
           → handler 在读 PC 指令时崩 (PC 不可读)

只换 libqvmp_runtime.so, 不动 hardened. 跑完把整段 [qvmp] 日志贴回来.

MD5:
  23_dt_needed.hardened   38c462247de8c6810b8862608b638d3a
  libqvmp_runtime.so      2354b5f445773f17f5f026a57a392340
