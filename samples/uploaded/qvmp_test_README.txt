target_app v55: 两个二分定位包
=====================================

# v54 还失败的原因

我猜了 LDRS + W32 Ror/AShr 但没修对症, 说明 bug 在别处. 给你两个包帮二分:

## protected 函数列表

```
[ 0] qsh__sha512_compress    ← SHA-512, 30 次调用
[ 1] qsh__ge_add             ← Ed25519 点加法, 1000+ 次
[ 2] qsh__fe51_invert        ← 51-bit 域元素求逆, 1 次
[ 3] qsh_base64_encode
[ 4] KeccakF1600_StatePermute (sha3 内核)
[ 5] shake128_squeezeblocks
[ 6] sha3_512
[ 7..18] PQCLEAN_MLKEM768_CLEAN_* (Kyber 后量子)
[19..29] shake/sha3 系列
```

# 这次给你两个包

## A) `target_app_light.hardened`  (最简单的 protect 路径)

- `--level light`: handler_duplication=1 (无 variant), junk_density=0 (无垃圾指令),
  encrypt_bytecode=false (字节码不加密)
- 全 30 个 region 仍然 protect
- 走的是 lifter+interpreter 最干净的路径
- 如果**这个还失败** → bug 在基础 lifter/interpreter (我新加的某条 VOp 算错)
- 如果**这个成功** → bug 在 paranoid 的 junk insertion / variant assignment

MD5: `24266ac5ecfd249f3ac1f974ff8b525b`

## B) `target_app_nogeadd.hardened`  (paranoid 但跳过 Ed25519)

- `--level paranoid`
- `--exclude qsh__ge_add --exclude qsh__fe51_invert`
- 跳过 Ed25519 的点加 + 域求逆
- 剩下 28 个 region 仍走 paranoid 路径
- 如果**这个成功** → bug 在 ge_add / fe51_invert 这两个函数的 lift
- 如果**这个也失败** → bug 在 sha512_compress 或其他函数

MD5: `0efaac7626c602058a3ee549779ca840`

# 怎么测

1. `libqvmp_runtime.so` 不变 (跟 v54 同), 不用换
2. 先测 A, 看是否验签成功
3. 再测 B, 看是否验签成功
4. 把两个结果都贴回来 — 即使两个都失败, 看日志里 region 序号能再缩小

# 部署

  cp libqvmp_runtime.so /data/local/tmp/ (已经放过可跳过)

  cp target_app_light.hardened <某处>
  chmod +x; ./ 或 MT 双击
  → 看是不是验签 ✓

  cp target_app_nogeadd.hardened <某处>
  chmod +x; ./ 或 MT 双击
  → 看是不是验签 ✓

# MD5 总表

  libqvmp_runtime.so              303006ff0de3a0f0451017c8662cc9ee  (v54 同)
  target_app_light.hardened       24266ac5ecfd249f3ac1f974ff8b525b
  target_app_nogeadd.hardened     0efaac7626c602058a3ee549779ca840
