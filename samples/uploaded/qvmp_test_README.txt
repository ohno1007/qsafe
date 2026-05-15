target_app v56: 单函数二分
================================

# v55 反馈

- A (light, all 30 region) → ✗ 失败
- B (paranoid, exclude ge_add + fe51_invert) → ✓ 成功

⇒ bug 在 `qsh__ge_add` 或 `qsh__fe51_invert` 的 lift 路径上.
(已经 unit-test 过 UMULH/EXTR/UBFX 都对, 应该是某条更冷门的指令.)

# v56: 单独 protect 每一个看挂哪个

## C) only_geadd.hardened
- `--level light --only qsh__ge_add`
- 仅 protect Ed25519 点加, 其余全裸跑
- 失败 → ge_add 里某条指令 lift 错

MD5: `890cda582a8dff7d8bfb74b57df50ce6`

## D) only_invert.hardened
- `--level light --only qsh__fe51_invert`
- 仅 protect 域元素求逆, 其余全裸跑
- 失败 → fe51_invert 里某条指令 lift 错

MD5: `11746f3de2e046c1dcc872a45fd7d18e`

# 部署

`libqvmp_runtime.so` 不变 (still v54).

测两个, 把哪个**成功**哪个**失败**告诉我. 可能两个都失败.

# 测试方式

1. cp only_geadd.hardened ; ./ → 跑到 license 验证, 看是否 ✓
2. cp only_invert.hardened ; ./ → 跑到 license 验证, 看是否 ✓

# MD5

  libqvmp_runtime.so          303006ff0de3a0f0451017c8662cc9ee (跟 v54 同, 不用换)
  only_geadd.hardened         890cda582a8dff7d8bfb74b57df50ce6
  only_invert.hardened        11746f3de2e046c1dcc872a45fd7d18e
