target_app v53: scratch 缓冲扩容
==================================

# v52 现场 — 巨大进展!

```
[qvmp] qvmp_init: enter
[qvmp] qvmp_runtime: blob loaded, SIGTRAP+SIGSEGV handlers installed
[qvmp] qvmp_runtime: handler entry #1
[qvmp] qvmp_runtime: dispatching region=0
[qvmp] qvmp_runtime: VM returned region=0     ← ✓ region 0 跑完
... 重复 22 次 ...
请输入卡密：11
==> 接口地址 : https://api.qsafehub.com
... 8 次 region 0 dispatch + return ...
[qvmp] qvmp_runtime: handler entry #23
[qvmp] qvmp_runtime: dispatching region=1     ← 切到 region 1
[qvmp] qvmp_runtime: VM ERR region=1 err=Eb3:region 1 bytecode 57620 bytes exceeds BC_SCRATCH_BYTES 16384
Trap
```

**Rewriter 修对了** — handler entry 一路打到 #23, region 0 跑了 22 次
干净返回. License 验签真的进了我们 VMP 路径.

# v53 修复

region 1 的 bytecode 是 57,620 字节, 但 VM 的解密 scratch 缓冲只有 16KB.
量子密码学函数 (Keccak/SHA-3 family) 用 NEON 重展开 + paranoid level
junk_density=25% + 3 个 handler variants, 一个函数 lift 出来字节码涨到
几十甚至 100+KB.

inspect 看了一下当前 blob 最大的 region:

```
region    bc_len
[8]       139,421  ← 最大
[1]        57,620  ← 这次崩的
[*]         3,954
[*]         3,006
```

`crates/vmp-stub/src/entry.rs` 改两处:

```rust
const POOL_SIZE: usize        = 32 * 1024 * 1024;  // 16MB → 32MB
const BC_SCRATCH_BYTES: usize = 256 * 1024;        // 16KB → 256KB
```

每 frame = 64KB stack + 256KB scratch = 320KB. 32MB pool / 320KB = 100
层递归 headroom. 当前最大 region 139KB 远低于 256KB 上限.

# 只需更新 .so

这次不需要重新加固 binary — bug 在 runtime .so 里的常量配置. hardened
binary 本身没动 (md5 跟 v52 一样).

# 部署

1. **覆盖** `/data/local/tmp/libqvmp_runtime.so` ← **md5 必须对上新的**
2. target_app.hardened 不用换 (md5 跟 v52 一样, 可跳过)
3. MT 重新打开

# 期望

handler entry 应该一路往上数, 看到 region 1 dispatching 后能正常
returned. 验签流程要更深入, 估计能跑到 `[2]` 服务端验证之后甚至完成
整个 license 检查.

# MD5

  target_app.hardened   0ea6804dbbf9f26847ee58d89156b89b   ← 跟 v52 同
  libqvmp_runtime.so    ae029ebd6284a887232077fec057672c   ← **必须更新**
