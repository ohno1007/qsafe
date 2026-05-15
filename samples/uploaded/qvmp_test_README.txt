target_app v54: 修签名验证错 (LDRS 符号扩展 + W32 Ror/ASR)
==============================================================

# v53 现场 — VM 全流程跑起来

```
region 0  → 22 次干净返回 ✓
region 1  → 1000+ 次干净返回 ✓ (= sha512_compress 之类)
region 2  → 1 次干净返回 ✓
[1] 服务端身份验签失败 ec=-25（MITM 风险，已退出）
```

VM 全程跑完 — 流程通了, 但**算出来的结果跟 native 不一致**, 最后一步
ECDSA / 后量子签名校验过不去.

# 真因: 我之前扩 lifter 时埋了俩 silent bug

## Bug 1: LDR-signed-extend 退化为 zero-extend

v50 我把 LDR/STR 9-bit 的 mask 从锁死 STR-only 放开:
```diff
- if (raw >> 21) & 0x1FF == 0b111000_000  // 强制 opc=00 = STR
+ if (raw >> 24) & 0x3F == 0b111000 && (raw >> 21) & 1 == 0
```

放开之后 opc=00/01/10/11 都进来. 但我**只把 opc==0 当 Store, 其它一律
当 Load**, 把 opc=10 (LDRSW/LDRSH/LDRSB to X) 和 opc=11 (LDRS to W)
当成零扩展 Load. 真正的 LDRS 需要做符号扩展, 不做的话:

  原 W = 0xFFFF (signed -1 as int16) → 应当扩展为 0xFFFFFFFFFFFFFFFF
  我们 emit 出来的: 0x000000000000FFFF (零扩展)

差 17 个 bit. Kyber 签名验证里大量 LDRSW 加载有符号多项式系数, 加载错
→ 多项式运算偏差 → 签名验签失败.

修: 加 `emit_load_sign_extend` 帮手, opc 高位是 1 (signed) 时在 Load
之后追加 `Shl + AShr` 做符号扩展. 三个 LDR 子族都加上.

## Bug 2: W32 Ror / AShr 走 64-bit 路径

之前 Ror 实现:
```rust
VOp::Ror => self.alu(instr, |a, b| a.rotate_right((b & 63) as u32)),
```

`a` 经过 width 掩码后高 32 位 = 0, 然后调 `u64.rotate_right` — 这是
64 位旋转, 不是 32 位.

例子: W32 a=1 (bit 0 set), 右旋 1 位:
  正确: 0x80000000 (bit 0 → bit 31)
  我们: u64 旋转 → 0x8000_0000_0000_0000, 掩到 32 位 = 0 (WRONG)

AShr 类似: 把 W32 当作 i64 算术右移, sign bit 看错位 (i64 sign 在 bit
63 而不是 bit 31).

修: Ror/AShr handler 都加 `match instr.width` 显式区分 W32 vs W64.

# 改了哪些文件

- `crates/vmp-arch/src/arm64/decode.rs`:
  + `emit_load_sign_extend` 新函数
  + 三个 LDR/STR family (unsigned-imm / 9-bit unscaled-pre-post / 寄存器偏移) 调用
- `crates/vmp-interpreter/src/lib.rs`:
  + VOp::Ror handler — width-aware
  + VOp::AShr handler — width-aware

# 覆盖率 (没动)

30 region / 24%.

# 部署

1. **覆盖** /data/local/tmp/libqvmp_runtime.so ← md5 必须对新的
2. **覆盖** target_app.hardened ← md5 也变了 (因为 lifter 输出变了)
3. MT 重启

# MD5

  target_app.hardened   7c756dcd893c5937bdf8ea6f8b8eee25   ← 更新
  libqvmp_runtime.so    303006ff0de3a0f0451017c8662cc9ee   ← 更新
