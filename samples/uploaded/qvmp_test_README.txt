qvmp_test.zip — v43 干掉 std::sync::Once + libc clock_gettime, 重开诊断
========================================================================

v42 全量 standard alloc-free 还挂. 再 audit 剩下两个 signal-unsafe 源:

1. **`std::sync::Once::call_once`** 在 dispatch_vm_fp 头. Once 内部用 futex
   做同步. 如果主线程刚开始 Once init 时 SIGTRAP 进入我们的 handler,
   handler 调 dispatch_vm_fp → Once.call_once 看到 Initializing 状态 →
   等 futex → **永远等不到 (主线程被中断了)** → 死锁或时序异常.

2. **`std::time::Instant::now()`** 在 LinuxHost::new(). bionic clock_gettime
   走 vDSO, 可能 touch TLS, signal-handler 不安全.

v43 修:

- 新增 `pub fn preload_data_segments(blob, host)` in vmp-stub::entry, 把
  map_data 循环从 dispatch_vm_fp 提到 qvmp_init 阶段 (主线程, 非 signal
  context). 删掉 dispatch_vm_fp + dispatch_vm 里的 `std::sync::Once`.
- LinuxHost 结构体删掉 `start: Instant` 字段, new() 完全无 syscall.
- syscall handler 里删掉 `eprintln!` (sys_exit 路径上的耗时报告).

cdylib qvmp_init 现在的初始化顺序:
  1. dl_iterate_phdr 找 QVMP magic
  2. 解密 rodata
  3. 解密 payload, unpack blob → BLOB.set
  4. **preload_data_segments(blob, host)** ← 新增, 主线程上 mmap data segs
  5. install_sigtrap_handler / install_sigsegv_logger

dispatch_vm_fp 现在的开头:
  - 直接 blob.regions.get(region_id) → 拿 bytecode
  - 不调任何 Once, 不分配任何 Instant
  - 纯 atomic alloc_frame + Interpreter 跑

整个 SIGTRAP→dispatch_vm_fp 路径**零 Once / 零 Instant / 零 alloc / 零
mutex / 零 libc**.

打开 --log on 看挂之前跑到哪一步. 如果还挂, 报告告诉我:
  - 最后一行 [qvmp] 是 "dispatching region=N" 还是别的
  - 总共出现了多少行 [qvmp] dispatching (估算 SIGTRAP 触发次数)

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (.so 必须更新)
  2. 43_no_once.hardened → 任意位置
  3. MT 双击, 粘日志

MD5:
  43_no_once.hardened  7e12b735c4fcdc3a33012025d8eb3473
  libqvmp_runtime.so   81df25950068f792cb254f1934458b20  (必须更新)
