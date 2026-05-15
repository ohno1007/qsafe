target_app v50: SIGILL handler + lifter 大扩 + 24% 覆盖
=============================================================

# 上次现场 (v49)

```
[qvmp] qvmp_init: enter
[qvmp] qvmp_runtime: rodata decrypted in place
[qvmp] qvmp_runtime: blob loaded, SIGTRAP+SIGSEGV handlers installed
请输入卡密：11
==> 接口地址 : https://api.qsafehub.com
[1] 服务端身份 ✓（已验签）
Illegal instruction
[进程已结束 (error 132) - 按回车关闭]
```

关键观察:
- **完全没有 `handler entry #N` 日志** → v49 protect 的 21 个函数走的
  路径根本没被命中 (license 验证用的不是我们 protect 的那批 Keccak).
- `Illegal instruction` (signal 4, exit 132) = SIGILL — 不是我们的 BRK
  分发路径 (那个会是 SIGTRAP / SIGSEGV).
- 最可能: app 自身有 anti-tamper 检查, 检测到 .text 被改 (我们注入了
  21 个 trampoline 改了原函数入口), 主动 `udf #0` 自爆.
- 或者: 某个我们 protect 的函数返回时把状态搞坏, 主程序之后跑到野指针,
  PC 落在全零内存上 → `udf #0` → SIGILL.

# v50 改动

## 1. SIGILL handler (新增)

`crates/vmp-soruntime/src/lib.rs`: SIGILL 跟 SIGSEGV 共用同一个寄存器
dump handler. 下次再挂会看到:

```
[qvmp] qvmp_runtime: SIGSEGV sig=4  ← 实际是 SIGILL (sig=4 复用同一 handler)
[qvmp] qvmp_runtime: SIGSEGV pc=...
[qvmp] qvmp_runtime: x0=... x1=... ...
[qvmp] qvmp_runtime: frame[0] lr=...
```

PC + frame chain 就能定位是 anti-tamper 还是 VM 状态污染.

## 2. 加密前 32 次 handler entry 全打日志 (而不是 power-of-2 节流)

帮排查首批 region 触发, 看是否真的有"我们 protect 的函数被叫到了".

## 3. 大幅扩展 ARM64 lifter

加了一票之前 skip 掉的指令族:

| 指令族 | 之前 | 现在 |
|--------|------|------|
| ADC / SBC / ADCS / SBCS | skip | ✓ (用 CSel+Carry-flag 实现) |
| EXTR (一般形) | skip (仅 ROR) | ✓ (拼 LShr+Shl+Or) |
| BFM 一般形 (BFI/UBFX/SBFX) | skip | ✓ |
| BIC / EON / ORN (shift+NOT) | skip | ✓ |
| ADD/SUB 扩展寄存器 (UXTB/SXTW 等) | skip | ✓ |
| CCMP / CCMN (条件比较) | skip | ✓ (近似) |
| SMULH / UMULH (128 位乘高位) | skip | ✓ (Knuth 拆 4×32) |
| LDR/STR 9-bit 带符号扩展 (LDRSB/LDRSW 等) | skip | ✓ |
| FP LDP/STP (含 Q-form 128-bit) | skip | ✓ |
| dp-1src (CLZ/RBIT/REV/REV16/REV32) | skip | ✓ 加新 VOps |
| NEON 位运算 (EOR/AND/ORR/BIC vector) | skip | ✓ 加 VEor/VAnd/VOr/VNot/VBic |
| SHA3 (EOR3 / BCAX / RAX1 / XAR) | skip | ✓ 分解到 VEor/VBic/VRorD |

5 个新 GPR VOp (Clz/Rbit/Rev/Rev16/Rev32), 8 个新 FREG VOp (VEor/VAnd/
VOr/VNot/VBic/VShlD/VLShrD/VRorD).

## 4. blob 版本和 ISA 容量

- handler_duplication paranoid: 4 → 3 (因为新增 VOps 后容量被吃掉)
- 1-byte opcode 上限从 220 提到 254 (= 255-1)
- 65 VOps × 3 variants = 195 ≤ 254 ✓
- 每个 region 仍是**独立 IsaSpec** (v2 blob); 21 region × 3 variants ×
  65 VOps ≈ 4100 (region-idx, opcode) 独立组合

# 覆盖率

| 阶段 | v47/49 | **v50** |
|------|--------|---------|
| ELF 函数 | 125 | 125 |
| Lift 成功 | 51 | **88** ↑ |
| Skip-traps drop | 74 | 37 ↓ |
| 级联剔除 | 30 | 58 |
| **最终 VMP** | 21 (16.8%) | **30 (24%)** |

instruction-level skip 从 6132 降到 1488. 剩下 1488 全是 NEON 高级
SIMD (DUP element, INS, UMOV, vector ADD/SUB, vector shift-imm 等).

入口函数从 `KeccakF1600_StatePermute` 变成 `qsh__sha512_compress` —
现在被保护的函数集合包含了 SHA-512 / SHA-3 / Kyber KEM 主路径多个核心.

要冲 99% 需要把整个 NEON ISA 都铺一遍 (上百个 sub-encoding). 我先把
现在这版给你测一下, 排查 SIGILL 真因, 同时我会继续推 NEON.

# 部署 (跟 v49 一样)

1. `libqvmp_runtime.so` → `/data/local/tmp/`
2. `target_app.hardened` → 任意位置, MT 双击 / `chmod +x && ./`

# 期望

- 启动看到 `[qvmp] qvmp_init: enter` 等三行 (.so 加载 OK)
- 这次 protect 集变化大, **应该会看到 `handler entry #1..#N`** 因为
  SHA-512 compress 是 license 验签的早期热点
- 如果再 SIGILL → 现在 handler 会 dump pc / x0..x30 / frame chain,
  贴日志回来我就能定位

# MD5

  target_app (原始)       2fd4c6b903fa93c041056f35750fc4e0
  target_app.hardened     1541d04baa3fd458e52c8533514ffdd0
  libqvmp_runtime.so      0e808c013384da0de622e89b5a768e18
