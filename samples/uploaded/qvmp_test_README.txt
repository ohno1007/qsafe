qvmp_test.zip — v41 全量 standard：去掉 signal handler 路径上所有 malloc
=========================================================================

v40 三个完全不重叠的 region 子集都挂同位置 → bug 跟具体哪个 region
被保护无关, 是机制层面的问题.

ROOT CAUSE (终于):

  dispatch_vm_fp 在 SIGTRAP handler 里被反复调用. 每次都:
    let mut vm_stack: Vec<u64> = vec![0u64; 64*1024 / 8];   ← 64KB malloc
    let mut tmp = self.bytecode.to_vec();                    ← bytecode malloc
    let mut state.stack: Vec<u64> = Vec::with_capacity(256); ← push/pop vec

  POSIX 明确说 **malloc/free 是 async-signal-unsafe**. bionic malloc
  内部有 mutex. 主线程 malloc 中途被 SIGTRAP 打断, handler 再调
  malloc → 同 mutex 重入 → 死锁或堆元数据损坏. 跑几百几千次 SIGTRAP
  后整个进程堆状态都乱了, 后续任何分配/free 都可能蹦.

  这跟"哪个 region 被保护"完全无关, 只跟"VM dispatch 总次数"有关.
  解释了为什么 v37/v38/v40 三种完全不同 region 集合都挂在大致相同
  位置 —— 都是堆累积破坏到某个 ImGui/Vulkan 内部分配触发.

v41 修复 (crates/vmp-stub/src/entry.rs + crates/vmp-interpreter/src/state.rs):

1. **mmap 池替代 Vec<u64>**: qvmp_init 第一次 dispatch 时 mmap 1MB
   匿名内存, 用原子 bump-down allocator 给每次 dispatch 切 64KB VM
   stack + 16KB bytecode scratch. 退出时恢复指针. **完全不走 malloc**.

2. **VmState.stack 改固定数组**: `[u64; 256]` + `stack_len: usize`,
   不再 Vec<u64>. push/pop 走数组索引.

3. **Interpreter 加 run_with_scratch(bc_scratch: &mut [u8])**:
   调用方提供字节码解密用的 scratch buffer (从 mmap 池切的), 不再
   `self.bytecode.to_vec()`.

整个 SIGTRAP handler → dispatch_vm_fp → Interpreter 路径上现在
**零 malloc/free**. 字节码 / VM 栈 / state 栈全部 signal-safe.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (**.so 必须更新**)
  2. 41_no_malloc.hardened → 任意位置
  3. MT 双击

预期: 出 ImGui UI. 这是修了真正的 root cause, 应该一次性通过.
如果还挂, 把日志全粘 — 那就是另一个机制层 bug (signal stack 大小,
SA_NODEFER 副作用等), 我继续修.

MD5:
  41_no_malloc.hardened  7e12b735c4fcdc3a33012025d8eb3473
  libqvmp_runtime.so     4c519682c10a8a7abd71086b7e2c9dbd  (必须更新)
