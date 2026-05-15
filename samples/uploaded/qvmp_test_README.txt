target_app 加固结果
==========================

# 改动 (v2 blob)

**每个被保护函数一台不同的 VM** — 不再共享一份 IsaSpec.
opcode 排列 / 寄存器置换 / 加密 key / 立即数旋转, 全部一region一份.
拆解 funcA 的 dispatch table 套不到 funcB. seed 派生:
  spec_seed = cfg.seed * splitmix + region_idx * splitmix + func.vaddr
同 seed + 同二进制 ⇒ 可复现.

# 覆盖率 (paranoid level)

| 阶段 | 数量 | 说明 |
|------|------|------|
| ELF 函数符号 | 125 | 全部候选 |
| Lift 成功 | 51 | NEON / atomics 复杂指令 lifter 暂未覆盖 |
| skip_traps drop | 74 | 含未支持指令 → 留原生 |
| cascade drop | 30 | 引用了 dropped region 的级联剔除 |
| **最终 VMP** | **21** | **16.8% 函数被虚拟化** |

被保护的几个关键函数 (从 entry 看):
  KeccakF1600_StatePermute, mlkem_kdf, sha3 系列, ...
即核心加密热点.

剩下 84% 是因为这是 Kyber/Keccak 量子安全密码学库, 大量用 NEON
向量指令 (`v0.16b`, `tbl`, `xar`, `bcax` 等), 这些我们的 ARM64
lifter 还没覆盖. 想拉高覆盖率得给 lifter 加 NEON 指令支持.

# 单文件 ELF 现状

**这个 target_app 没法做单文件包** — 它的 PLT 里没有 `dlopen` import.
bootstrap stub 需要 dlopen 调用嵌入式 .so, 没 PLT 表里现成的 dlopen
就必须做 ELF 大手术 (新增 .dynsym / .dynstr / .rela.plt / .plt /
.got.plt 条目). 这工作量我先不展开.

所以这次仍走**两文件** DT_NEEDED 部署. Android 的 dynamic linker
在 main exec 跑起来前会自动 dlopen DT_NEEDED 引用, 等价效果.

# 部署

  1. `libqvmp_runtime.so` → `/data/local/tmp/` (md5 必须对)
  2. `target_app.hardened` → 任意位置, MT 双击 / `chmod +x && ./`

# 单元测试

`cargo test -p vmp-stub`: 10/12 通过.
失败的 2 个是 fixture-pinned (要某 Windows NDK 的二进制在
0x204234 / 0x20419c 这种硬编 vaddr) - 跟我的改动无关, main 分支
也挂.

# MD5

  target_app (原始)      2fd4c6b903fa93c041056f35750fc4e0
  target_app.hardened    5e3d2eb0f5a1d33247083acb0b83f3c4
  libqvmp_runtime.so     e3f007bb57764cfbe37c493fbda7736f

# 后续改进方向

1. **lift NEON 指令** → 覆盖率到 60-80%
2. **dlopen PLT 注入** → 真正的单文件 ELF (即使原 binary 没 dlopen)
3. handler_duplication=4 + 21 个独立 IsaSpec = 21 × 4 × 52 ≈ 4400 个
   独立 (opcode, region) 组合 — 静态反编译要分别学每个 region 的
   dispatch table

# 期望

device 上跑 target_app.hardened, 应该看到:
  [qvmp] qvmp_init: enter
  [qvmp] qvmp_runtime: blob loaded, SIGTRAP+SIGSEGV handlers installed
  [qvmp] qvmp_runtime: handler entry #1
  [qvmp] qvmp_runtime: dispatching region=N  (N 是真正首先调用的被保护函数)
  ...
