qvmp_test.zip — v28 级联剔除含 Trap 的 region（resolve 后 cascade drop）
==========================================================================

v27 反馈：
  [qvmp] dispatching region=19
  [qvmp] VM ERR region=19 err=Eb2:E:E8
  Trap (exit 133)

`E8` = vmp-interpreter `VOp::Trap` 占位符。resolve 阶段遇到 BL 目标
既不在自己 region 内、也不是别的被保护函数入口（多半是 libc PLT），
就塞 VOp::Trap. region 19 里有这种指令 → 跑到那条就抛 E8.

`--skip-traps` 只过滤 lift 阶段不会动 resolve 阶段加的 Trap.

v28 修：在 protect 里 resolve 之后跑级联剔除循环 ——
  1. resolve 整张表
  2. 把 IR 里含 VOp::Trap 的 region 加入丢弃集
  3. 从 pristine IR 副本里去掉这些 region, 重新 resolve
  4. 直到没有 region 含 Trap

本次 binary:
  - 候选函数 3315
  - lift kept 867 (skipped_traps=2448)
  - cascade drop: 238 + 94 + 1 = 333 个 region 被踢
  - 最终保护 534 个 region (unresolved=0)
  - 被踢掉的 333 个函数原样跑 (没插跳板)

DT_NEEDED 还是绝对路径 `/data/local/tmp/libqvmp_runtime.so`.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/
  2. 28_no_traps.hardened → 任意位置
  3. MT 双击运行

期望:
  [qvmp] rodata decrypted in place
  [qvmp] blob loaded, SIGTRAP handler installed
  [qvmp] dispatching region=N
  (多次)
  <ImGui 窗口出来>

如果还挂:
  - 出现 VM ERR 把 err= 完整粘回来 (理论上不该再出 E8)
  - SEGV 把所有 dispatching region=N 的最后一个 N 粘回来

MD5:
  28_no_traps.hardened    d5772ccabd2becae7c1d9edc5f5eb71a
  libqvmp_runtime.so      e5ed8ecefb06df456c8ddb18aea4552b
