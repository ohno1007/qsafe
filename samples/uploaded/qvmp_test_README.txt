qvmp_test.zip — v36 单指令蹦床拦截 + SIGSEGV FP-chain backtrace
==================================================================

v35 反馈 (重大进展):
  region 124 70+ 个 BLR 全过 ✓
  malloc/free 大量轮 ✓
  region 8/9/12/25/3/13/6/2/105/127/183/161/178/396/233/326/344/151
    /401/353/145 等等都跑通
  最后 SEGV pc=addr=0x7BE2A02FA0 (exec fault, 跳到非执行内存)
  x30=0x556c0dcb80 在 load_bias 之下 → 某 .so 或链接器里

关于 v35 拦截没生效那条 BLR (target=0x55756bb058):
  vaddr 0x193058 不是任何 region 的 patch_addr.
  原 binary 那里是 `b 0x108278` 单指令蹦床 → 跳到 region 8 (malloc) 的
  trampoline. v35 拦截只匹配 `target == load_bias + patch_addr`,
  这种 thunk 漏掉了, 退回 native + 嵌套 SIGTRAP (靠 SA_NODEFER 撑过).

v36 改两处:

1. **NestedDispatchHost.native_call (crates/vmp-stub/src/entry.rs)**
   再加一层匹配: 如果 target 处是一条 ARM64 B imm26 指令 (单指令蹦床),
   解出真实目标后再跟 patch_addr 比对. 命中就直接 vm_call_region_fp
   绕开嵌套 signal. 减一次 signal 切换. 用 read_volatile 防止编译器
   假设 target 不可变.

2. **SIGSEGV handler FP-chain (crates/vmp-soruntime/src/lib.rs)**
   AAPCS64 每个函数 prologue 存 [fp+0]=prev_fp, [fp+8]=saved_lr.
   挂前手动走 12 层 fp chain, 每层打:
     [qvmp] frame[N] lr=<vaddr>
   能让你 (我) 顺着 lr 反推调用栈, 在 main exe 里查谁调谁.
   (没 SA_NODEFER 在 SIGSEGV, 走到坏 fp 时 kernel 默认终结, 但前面几层
    通常够看出问题所在)

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (md5 变了, 必须更新)
  2. 36_thunk_backtrace.hardened → 任意位置
  3. MT 双击

预期:
  跟 v35 跑得一样远或更远. 挂的时候 SIGSEGV 后会多 12 行 frame[N] lr=...
  把整段 (从 dispatching region=145 之后) 粘回来, 我能对照 main exe
  的反汇编反推哪个原函数挂了, 进一步定位是 VM 返回值不对还是别的.

MD5:
  36_thunk_backtrace.hardened  7e12b735c4fcdc3a33012025d8eb3473
  libqvmp_runtime.so           84a9e3e7a7cf180deaa1785e1994920b
