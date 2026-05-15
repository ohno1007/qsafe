qvmp_test.zip — v46 真·root cause 修复: VM 池容量 + cascade filter
====================================================================

v45 二分实验直接定位到两个真 bug:

1. **n8 / n16 报 "Eb2:E:E1:19"**:
   `E1` = `StubError::NoRegion(0x19=25)`. QVMP_REGION_RANGE 限制 0..16
   时, region 25 不在保护集里, 但 IR 里某条 `CallRegion(25)` 仍然存在
   —— 之前的 cascade-drop 是在 RANGE 过滤**之前**做的, 后过滤的没再
   resolve 一次. 这是 cli 流程 bug, 不是 VM 问题.

2. **n32 / n64 报 "Eb3:VM frame pool exhausted (recursion too deep?)"**:
   这是 **v37-v44 全量挂的真正 root cause**! 之前 SIGSEGV 是因为
   `format!` 在错误路径分配 String → bionic malloc 锁 → 进程崩.
   现在错误路径不走 alloc 了, error 信息能干净打出来 → Eb3 暴露真相.

   1MB mmap 池 / 每 frame 80KB = 12 层嵌套. ImGui/C++ 容器算法
   (vector::resize, std::sort, 字符串拼接) 嵌套调用 20-30 层正常.
   一旦超过 12 层 → "pool exhausted" 错误 → SIG_DFL → exit 133.

   之前每次都是不同的 SEGV register pattern 但都同一类原因: VM 在
   嵌套链中途返回错误, caller 拿到非法值后挂.

v46 修两处:

- **`crates/vmp-stub/src/entry.rs`**: POOL_SIZE 1MB → **16MB**.
  每 frame 80KB → ~200 层递归. ImGui/Vulkan 任何路径都够.
- **`crates/vmp-cli/src/main.rs`**: cascade-drop 循环里融合 leaf/fp/
  range 过滤 + Trap 检查, 一起跑到 fixpoint. 这样 RANGE 限制后的
  CallRegion 残留也会被 cascade 自然剔除.

v46_full.hardened 是**全量 standard 534 region** 包. 应该一次出 UI.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (**.so 必须更新**)
  2. 46_full.hardened → 任意位置
  3. MT 双击

预期: ImGui 起来, 长时间运行不挂.

MD5:
  46_full.hardened    7e12b735c4fcdc3a33012025d8eb3473
  libqvmp_runtime.so  4838bccdf652757ab5012d5acba5b014  (必须更新)
