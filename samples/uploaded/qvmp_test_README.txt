qvmp_test.zip — v27 修复 VM ERROR 死循环 + 打详细错误（DT_NEEDED 路径）
=========================================================================

v26 反馈：
  [qvmp] dispatching region=19
  [qvmp] VM ERROR for region=19    ← 重复无限次
  ...

两个 bug：
  1. v26 我 rewrite 用了 `--embed-runtime`（旧 bootstrap+dlopen，撞栈金丝雀）
     而不是 DT_NEEDED 路径。v27 改回 DT_NEEDED：可执行文件跟
     libqvmp_runtime.so 放同目录即可。
  2. handler 在 VM ERROR 时只 `return`，PC 没动，内核又触发同一 BRK →
     handler 又 return → 死循环。v27 改成 SIG_DFL + return：让内核以
     默认 SIGTRAP 处理把进程结束（exit 133），并把单次错误的详细 message
     带出来。

期望 v27 日志（按顺序）：
  [qvmp] rodata decrypted in place
  [qvmp] blob loaded, SIGTRAP handler installed
  [qvmp] dispatching region=19
  [qvmp] VM ERR region=19 err=Eb2:E:<具体原因>
  Trap (exit 133)

把上面的 `err=...` 那段完整粘回来 — 这才是真正诊断 region 19 失败的关键。
可能形态：
  - Eb2:E:Lift 失败 @ 0x... : ...    （lifter 没翻译出来）
  - Eb2:E:unknown opcode XXX          （interpreter 没实现某个 op）
  - Eb2:E:host bridge error: ...      （helper 调用失败）

部署：
  把 27_vm_err_log.hardened 和 libqvmp_runtime.so 放同一目录，
  双击 27_vm_err_log.hardened。

MD5:
  27_vm_err_log.hardened  02a83bcc699b4b54e28a77213bd8022c
  libqvmp_runtime.so      e5ed8ecefb06df456c8ddb18aea4552b
