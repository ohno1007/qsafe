target_app v51: BTI 修复 ← 这才是 SIGILL 真因
=================================================

# v50 现场 (你贴的 dump)

```
SIGSEGV sig=4               ← 实际是 SIGILL (=signal 4) 复用 SIGSEGV handler
SIGSEGV pc=411445248000     = 0x5FCC0C4000 → vaddr 0xC4000 (在我们新段里)
LR (x30)=411444819496       = 0x5FCC05B628 → vaddr 0x5B628 (原 .text)
frame[0] lr=411444808444    = 0x5FCC058AFC → vaddr 0x58AFC (原 .text)
frame[1] lr=530492386660    = libc.so (vaddr 不同 lib)
*没有任何 [qvmp] handler entry / dispatching log*
```

# 真因

二进制启用了 **ARMv8.5 BTI (Branch Target Identification)**:

```
$ objdump -d target_app
0000000000003ccc <_start>:
    3ccc: bti     j                    ← BTI 守门
    3cd0: mov     x29, #0x0
...
0000000000003ce0 <_start_main>:
    3ce0: paciasp                      ← PAC + BTI
    3ce4: sub     sp, sp, #0x40
```

BTI 规则: 所有**间接调用** (BLR Xn / BR Xn) 落地点的首条指令必须是
  `bti c` (call landing)
  `bti j` (jump landing)
  `bti jc` (both)
  `paciasp` / `pacibsp` (PAC 隐含 BTI-jc)

否则硬件触发 **Branch Target Exception** → kernel 转 SIGILL.

我们的 v50 patch 把每个被保护函数入口的第一条指令**覆盖成裸 `B trampoline`**.
`B` 不是 BTI 指令. 任何走 BLR / 函数指针调用进来的 caller 一落地就 SIGILL.

这解释了:
- "没有 handler entry log" — 因为根本没机会执行到 trampoline 的 BRK,
  BLR 第一拍就被 BTI 拦了
- PC = 0xC4000 在我们新段里 — 那是 caller 的 BLR target 经过 patch
  以后, 落地异常时 PC 仍指向落地点, 而落地点就是 patched 函数入口对应
  的 trampoline 区域附近
- 在我之前帮你测试的 fpdemo 上没复现, 是因为 fpdemo 是普通编译, 没开 BTI

# v51 修复

`crates/vmp-rewriter/src/elf_writer.rs`:

1. 加 `detect_bti_protection`: 扫前 16KB .text, 看到任何 `bti c/j/jc` /
   `paciasp` / `pacibsp` 就判定整段开了 BTI.
2. patch 时 BTI-enabled 二进制改写 **2 条指令 (8 字节)**:
     +0: `bti jc` (0xD50324DF) — 允许 BLR + BR 双向落地
     +4: `B trampoline`
3. 非 BTI 二进制保持原来的 1 条 `B trampoline`.

VM 侧 lift 时 `bti` / `paciasp` 系列已经被识别为 HINT → Nop, 所以原函数
的前 2 条指令在 VM 内仍然按 nop 执行. 语义不变.

# 覆盖率 (没动)

| | v50 | v51 |
|---|---|---|
| Lift 成功 | 88 | 88 |
| 最终 VMP | 30 | 30 |
| 占比 | 24% | 24% |

(同一份 lift, 只改了 patch 方式)

# 部署

1. `libqvmp_runtime.so` → `/data/local/tmp/`  (跟 v50 同一份, md5 不变也行)
2. `target_app.hardened` → 任意位置, MT 双击

# 期望

- 启动 3 行 [qvmp] log 跟以前一样
- 这次跑到 license 验证应该会看到 `handler entry #1..#N` 和
  `dispatching region=N` 因为 SHA-512 compress 在签名验证早期就被叫
- 如果 *现在* 还挂, 请把日志贴回来 — 关键看:
  * 有没有 `handler entry`? (有 → BTI 修对了, 后面是别的问题)
  * 如果还 SIGILL, 看 pc 是什么 (排除还有其他 anti-tamper)

# MD5

  target_app (原始)       2fd4c6b903fa93c041056f35750fc4e0
  target_app.hardened     564043063556f468dc7c5966c265acd4
  libqvmp_runtime.so      0e808c013384da0de622e89b5a768e18  (同 v50)
