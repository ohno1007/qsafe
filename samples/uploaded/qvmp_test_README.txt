qvmp_test.zip — v42 全量 standard, signal handler 路径完全 alloc-free
======================================================================

v41 还挂同位置说明 malloc 修了但还有别的 signal-unsafe 调用. 仔细 audit
SIGTRAP handler 完整调用链, 找到三个额外的 alloc/mutex 重入源:

1. **LinuxHost::refresh_exec_ranges** 调 `std::fs::read_to_string("/proc/self/maps")`
   每次 SIGTRAP handler 都 new 一个 LinuxHost, cache 是空的, 第一次
   native_call 触发 refresh → 分配 String + Vec<(u64,u64)>. 走 bionic malloc.

2. **__android_log_write** (在 log_msg 里). 内部走 logger socket + mutex.
   主线程在 logger mutex 里时我们 SIGTRAP, 重入死锁/堆乱.

3. **libc::write** 走 bionic libc wrapper, 接触 errno TLS / 其他状态.
   POSIX 说 write(2) signal-safe, 但 bionic 的 libc 层 wrapper 不一定.

4. **`Error::vm(format!(...))`** 在 interpreter NativeCall 错误包装路径
   分配 String — 即使是错误路径也算 signal context 内 alloc.

v42 全部清掉:

- 直接 `svc #0` syscall 调 sys_write(64), 绕过 bionic libc. 加在
  vmp-soruntime::raw_write + vmp-interpreter::syscall_write 两处.
- log_msg 不再调 __android_log_write, 只用 raw_write.
- LinuxHost::native_call 删掉 /proc/self/maps 校验. 保留最小合法性检
  查 (target != 0, 对齐, 不在低地址).
- LinuxHost 结构体不再带 exec_ranges 字段.
- interpreter NativeCall map_err format! 改成原始错误透传.

整个 SIGTRAP→dispatch_vm_fp→Interpreter→LinuxHost 路径上现在
**零 malloc, 零 mutex 接触, 零 libc 状态调用**. 纯 syscall + memory ops.

外加: **rewrite 用 --log off** 完全关掉 log_msg 路径, 确保零干扰.
(注意: 这次没诊断日志, 出 UI 就好, 不出再开 --log on 加 diagnostic)

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (**.so 必须更新**)
  2. 42_signal_safe.hardened → 任意位置
  3. MT 双击

预期: 出 ImGui UI. 如果还挂 (没有日志, 但会 SIGSEGV 终止), 我再开 log
+ 加 instrumentation 找最后一个 signal-unsafe 调用.

MD5:
  42_signal_safe.hardened  86470b0ed1909678406668add64c2792
  libqvmp_runtime.so       4856bfa58c27b48cf408caf754ef830a  (必须更新)
