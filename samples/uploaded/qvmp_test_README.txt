target_app v52: 真正的 SIGILL 修复 — 新 LOAD 段位置算错
======================================================

# v51 现场 (你贴的 dump)

```
SIGSEGV sig=4 (SIGILL)
SIGSEGV pc=0x5CD68C4000          → vaddr 0xC4000
*没有 [qvmp] handler entry log*
```

跟 v50 一模一样的 PC 偏移 (0xC4000), 说明不是随机崩, 是确定性 BLR 到
错误地址.

# v52 真因

v51 我猜是 BTI, 实际验证之后这个 binary 没有 GNU_PROPERTY BTI note,
只是源码里有 `bti c` / `paciasp` 装饰指令但**链接器没把段标 PROT_BTI**.
所以 BTI 修不修都不是关键路径.

真正的 bug 在 **rewriter 的新 LOAD 段位置算错**:

```rust
// elf_writer.rs
let (new_vaddr_base, _) = next_load_vaddr(&loaded.raw)?;  // = 0x70000
let new_segment_off = new_vaddr_base as usize;             // = 0x70000
while out.len() < new_segment_off {
    out.push(0);
}
// 这里假定 out.len() < 0x70000, 然后 append 跳板就 file_off == vaddr
```

但 **原 binary 文件大小是 0xA4BA0** (远大于 0x70000) — 因为末尾有
`.debug_loc / .debug_abbrev / .debug_str / .debug_line / section header
table` 等**不加载到内存但占文件**的内容.

所以 `out.len() < 0x70000` 直接为 FALSE, while 循环啥都不干, trampolines
被 append 到 file_off **0xA4BA0** — 而 LOAD program header 仍说 "vaddr
0x70000 = file_off 0x70000, 大小 0xC4000".

结果: dynamic linker 把 file_off 0x70000 .. 0x134000 映射成 RX, 但
**前 0x34BA0 字节是 debug section 残留** (debug_info bytes, 不是代码).
我们的 `B trampoline=0x70000+N*16` 跳过去落到 debug bytes, CPU 当指令
解 → 总会出 SIGILL.

vaddr 0xC4000 之所以每次都一样, 是因为它正是 binary 里某个特定 region
的 patch 目标 (`new_vaddr_base + idx*16 = 0x70000 + 0x54000 = 0xC4000`,
也就是 region 13530, 但因为 patch_addr 的具体函数 vaddr 决定了 B 偏移,
B 编码 imm26 模糊化的结果还是落在 0xC4000 附近).

实际上每个被保护函数的 `B trampoline` 都跳到 [0x70000, 0x70000 + 30*16)
里的某个偏移. 那段在 hardened binary 里**全是 debug 字节**, 当指令解
都会挂.

# 修复

`crates/vmp-rewriter/src/elf_writer.rs`:

```rust
let aligned_file_end = ((out.len() as u64) + mask) & !mask;
let new_vaddr_base = next_load_vaddr_val.max(aligned_file_end);
```

new_vaddr_base 同时满足两个约束:
1. **≥ next_load_vaddr** (不撞原有 LOAD 的 vaddr 区间)
2. **≥ ceil(file_size, page_align)** (不撞原文件已有内容)

对这个 binary 来说: max(0x70000, ceil(0xA4BA0, 0x4000)) = max(0x70000,
0xA8000) = **0xA8000**.

验证: rewrite 后 readelf 显示
  LOAD 0x0a8000 0xa8000 0xa8000 0x090000 0x090000 R E 0x4000
第一条 trampoline (`mov x16, #0; brk #0x5156`) file_off = **0xa8000** ✓
新 LOAD vaddr == file_off ✓
不再有 stale debug bytes 被映射成代码 ✓

# 覆盖率 (没动)

依然 30 region / 24%.

# 部署

跟 v51 一样, 两文件:
1. libqvmp_runtime.so → /data/local/tmp/  (跟 v51 同一份 .so 也行)
2. target_app.hardened → 任意位置

# 期望

启动看到 3 行 [qvmp] log, license 验签时**应该会看到 handler entry #1**
之类的, 然后 dispatching region=N. 如果还挂请把日志贴回来.

# MD5

  target_app.hardened   0ea6804dbbf9f26847ee58d89156b89b
  libqvmp_runtime.so    0e808c013384da0de622e89b5a768e18  (同 v50/v51)

# 教训

之前在 host 上跑 fpdemo_glibc 试不出这个 bug, 因为 fpdemo 没 debug
info, file_size < new_vaddr_base, while 循环正常 padding. 真实带调试
符号的 binary 才暴露问题. SIGILL 的具体 PC (0xC4000) 也跟具体 binary
的 debug 内容相关 — 那一段字节恰好不是合法 ARM64 指令.
