qvmp_test.zip — v34 junk 寄存器跟 lifter SCRATCH 冲突修复
============================================================

v33 反馈:
  dispatching region=124
  BLR x20 ... x0=0x5c4a2debf9  ← 1st (load_bias + 0x26bf9 ✓)
  BLR x20 ... x0=0x5c4a2d3228  ← 2nd (load_bias + 0x1b228 ✓)
  BLR x20 ... x0=0x5c4a2d5000  ← 3rd 应该是 +0x1d8e3, 但只有 +0x1d000
  VM returned region=124
  ... 后续 region 调 malloc/free 几轮 ...
  SIGSEGV pc=0 (空函数指针)

复现成功！本地 sim 改用 standard preset (junk=25%, duplication=2) 后
跟 device 一样, 第 3 个 BLR x0 差 0x8e3.

ROOT CAUSE:
  arm64 lifter 把 `add x0, x0, #0x8e3` 展开成两条 IR:
    [N]   MovI SCRATCH=0x8e3        (lifter scratch V32)
    [N+1] Add  x0, x0, SCRATCH

  codegen 在每条 IR 前以 25% 概率插 junk. junk kind 4 是
    Xor SC1, SC1, SC1               (SC1 = V32, 跟 lifter SCRATCH 同号!)
  插到 [N] 和 [N+1] 之间, 把 SCRATCH 清零 → Add x0 += 0 → 立即数蒸发.

  另一个 latent bug: junk kind 4/5 (Xor/Tst, Cmp) 改 NZCV, 插到
  Tst+BCond 之间会让 CBZ 误判.

修 (crates/vmp-codegen/src/junk.rs):
  - SC1: 32→60, SC2: 33→61   (lifter 只到 V32/33/34, V62=load_bias,
    V63=XZR, V60/61 没人碰)
  - 删掉 kind 4 (Xor self → 0; Tst SC1) 和 kind 5 (Cmp SC1)
    —— Tst/Cmp 都改 flags, 在 IR 边界插入不安全
  - 留 4 种 safe junk: Junk / Nop / Obfuscate / "MovI SC2=0; Add SC1+=SC2"

本地 sim 跑 region 124 用 standard preset: 第 3 个 BLR x0=0x5c4a2d58e3 ✓.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (跟 v33 同份)
  2. 34_junk_safe.hardened → 任意位置
  3. MT 双击

预期: region 124 之后该跑的 region 都能跑过, 不再出现 "立即数蒸发" 类
的灵异 bug. ImGui 应该能起来 (这一类是会扩散到整个 VM 执行的系统性
问题, 修完通常能放行大量原本"莫名其妙"的 crash).

MD5:
  34_junk_safe.hardened  7e12b735c4fcdc3a33012025d8eb3473
  libqvmp_runtime.so     ae803cacd1d87aaa0eb1be3687e3ad41  (同 v32/v33)
