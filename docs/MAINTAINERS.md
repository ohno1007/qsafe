# 接手手册

写给下一位维护者。读完知道：
- 改任何东西要碰哪些 crate
- 加新东西的标准做法（VOp / 架构 / anti-* / 平台）
- 容易踩的坑
- 调试时该看什么

---

## 0. 先做这几件事

```bash
git clone <repo>
cd qsafe
cargo build --workspace --release       # 30 秒
QVMP_DISABLE_CTOR=1 cargo test --workspace --lib --tests   # 应该 21 项全过
bash samples/realworld/harden_so.sh /usr/lib/x86_64-linux-gnu/libz.so.1   # 任何 .so 走一遍 pipeline
```

**绝对不要** 跑 `cargo test --workspace` 不带 `QVMP_DISABLE_CTOR=1`——`vmp-runtime`
的 `.init_array` ctor 会在测试 runner 里跑反 * 检查、装 SIGTRAP handler，污染所有
后续测试。

---

## 1. 修改一个东西的"反射弧"

### 加一条 VOp（语义指令）

**5 个文件**必改：

| 文件 | 改什么 |
|---|---|
| `vmp-isa/src/opcode.rs` | enum `VOp` 加一项 + 编号；`from_u16` 加 match arm；`all()` 加项；`debug_name` 加 match arm |
| `vmp-isa/src/encoding.rs` | `Instr::layout()` 加 match arm，决定有哪些字段 |
| `vmp-interpreter/src/lib.rs` | `Interpreter::run` 主 match 加 handler |
| `vmp-arch/src/<arch>/decode.rs` | lifter 对应原指令的解码路径产出新 VOp |
| `vmp-isa/src/random.rs` | 检查 cap：`total_variants ≤ 254` —— 当前 74×3 = 222，留 32 余量 |

加完跑：
```bash
cargo build --workspace            # 编译过即字段对了
cargo test -p vmp-isa --lib        # ISA pack/unpack roundtrip 测试
cargo test -p vmp-stub --release   # 端到端
```

### 加一个新架构 lifter

例如 `riscv64`：

1. 在 `vmp-core/src/arch.rs::Arch` 加 `RiscV64`
2. 创建 `vmp-arch/src/riscv64.rs`，实现 `Lifter` trait：
   ```rust
   impl Lifter for RiscV64Lifter {
       fn arch_name(&self) -> &'static str { "riscv64" }
       fn lift(&mut self, code: &[u8], base: u64) -> Result<LiftedFunction> { ... }
   }
   ```
3. `vmp-arch/Cargo.toml` 加 feature `riscv64 = []`
4. `vmp-arch/src/lib.rs::make_lifter_opts` 加 cfg(feature) 路径
5. `vmp-loader/src/elf.rs::parse` 把 `e_machine` 的 EM_RISCV 映射到 `Arch::RiscV64`
6. `vmp-cli` 不需要改（自动通过 `Arch` enum 走）

### 加一个新 anti-* 模块

例如反 root（检测 magisk）：

1. `vmp-protect/src/anti_root.rs`：
   ```rust
   #[cfg(any(target_os = "linux", target_os = "android"))]
   pub fn detect() -> Vec<&'static str> {
       let mut out = Vec::new();
       if std::path::Path::new("/system/app/Magisk").exists() { out.push("magisk_app"); }
       // ...
       out
   }
   #[cfg(not(any(target_os = "linux", target_os = "android")))]
   pub fn detect() -> Vec<&'static str> { Vec::new() }
   ```
2. `vmp-protect/src/lib.rs`：
   - 加 `pub mod anti_root;`
   - `ProtectFlags` bitflag 加一位 `ANTI_ROOT = 1 << 16`（注意：当前 16 位都用了，
     可能要改成 u64）
   - `parse_keywords` 加 `"anti_root" => ProtectFlags::ANTI_ROOT`
   - `Verdict` 加字段 `pub root_detected: bool`
   - `run_checks` 加路径
3. 不需要改 runtime / rewriter；env var 直接识别

### 加一个新 magic blob

例如 QFOO：

1. 设计字节布局（参考 [docs/ARCHITECTURE.md#magic-blobs](ARCHITECTURE.md#magic-blobs)）
2. `vmp-rewriter/src/armor.rs` 加 `append_qfoo(elf, ...)` 函数，**8 字节对齐**
3. `vmp-runtime/src/scan.rs` 加扫描函数 `find_qfoo() -> Option<...>`，从模块的
   PT_LOAD 段尾部反扫（rewriter 写在末尾追加 segment）
4. 在 `qvmp_runtime_init` 里调
5. `vmp-cli` 加 flag 控制 rewriter 阶段是否启用

### 加一个 ProtectLevel

`vmp-core/src/config.rs::ProtectLevel`。例如要加 `Insane`：

1. enum 加一项
2. `from_level` 加 match arm
3. `vmp-cli` 的 clap `Level` enum 加项
4. 注意：`handler_duplication` 不能让 `total_variants > 254`（cap 在 random.rs）

---

## 2. 容易踩的坑

### A. `.init_array` ctor 在测试里乱跑

`vmp-runtime` 是 `crate-type = ["rlib", "cdylib"]`。链接成测试 binary 时
ctor 仍然触发，`qvmp_runtime_init` 会跑反 * 检查 + 装 SIGTRAP handler。

**解决**：跑测试前 `export QVMP_DISABLE_CTOR=1`。`crates/vmp-runtime/tests/integration.rs`
里也兜底 `std::env::set_var("QVMP_DISABLE_CTOR", "1")`，但有些场景仍然要外部设。

### B. ChaCha20 RNG 顺序敏感

`IsaRandomizer::build` 里的 RNG 调用顺序决定 ISA 指纹。**改顺序 = blob 不兼容**。
若加新随机化项，**追加到末尾**而不是中间。

### C. branch 修复要做两遍

`CodeGen::encode` 在第一遍 emit 时 branch 的 imm 占位为 0，记录所有 branch 的字节
偏移；第二遍按 IR 索引 → byte 偏移回填。**junk 插入也只在第一遍做**，否则字节偏移变。

如果以后加新的"插入式" pass（往 IR 里塞东西），要么放在 resolve_program 之前
（IR 索引还是绝对地址），要么自己 remap branch 索引（参考 `expand_arith`）。

### D. PIE 地址 < 4GB 启发式

`RebasedLinuxHost::rebase_if_relative` 用 4GB 阈值区分"模块内 PIE 相对"和"绝对地址"。
极少数情况会误判（比如 mmap 给的低 4GB 区域 + 应用真的存自己的指针），那时
load/store 会读错地址。**真正干净的方案**是 lifter PIE-aware 标记 ADRP-derived 地址。

### E. ELF rewrite 的 PHDR 重排

`add_load_phdr` 把整个 phdr 表复制到文件末尾、改 `e_phoff`。**任何依赖 phdr 在
固定位置的工具都会失败**（罕见但存在；Android 较老的 linker bug）。如果用户报怪
错可以查这。

### F. SIGSEGV / SIGTRAP handler 不能用 std::sync::Mutex

handler 是 async-signal-safe 上下文，**绝对不能 Mutex::lock()**——会死锁。
`page_crypto.rs` 用了 `Mutex` 是 known bug，目前靠 SA_NODEFER 兜底（IN_HANDLER
计数器）。Phase 9+ 应改成 lock-free。

### G. opcode 0 不在 ISA 池

`IsaRandomizer::build` 的 `pool: Vec<u8> = (1..=255).collect()` —— **opcode 0 永远不
分配**。如果 cap 还要加大，可以改成 `(0..=255)` 多 1 个槽位，但要保证 `op_reverse[0]`
能正确处理（当前默认 `None`）。

### H. dispatch_vm 的 NestedDispatchHost 递归

`VOp::CallRegion` 通过 `host.vm_call_region_fp` 触发递归 `dispatch_vm`。**每层递归
都开 64KB VM 栈 + 跑 ChaCha 解密**。深递归（>30 层）会爆 host 栈。商用 SDK 调用图
深度通常 <10 层，安全；超出后要改成迭代式 dispatch。

### I. expand_arith 用 V36..V39，不是 V32..V35

`vmp-codegen/src/transform.rs` 用 TMP1=V36, TMP2=V37, TMP3=V38, TMP4=V39。
**lifter scratch 用 V32..V35**。如果 transform 也用 V32..V35 会和 lifter
scratch 冲突，`expand_arith` 跑完结果就错。

---

## 3. 调试技巧

### 看一个特定函数的 IR

```bash
# 抠出函数字节
python3 -c "
with open('lib.so','rb') as f: bs=f.read()
import sys; sys.stdout.buffer.write(bs[0xfae00:0xfae00+0x100])
" > /tmp/fn.bin
xxd -p /tmp/fn.bin | tr -d '\n'

# lift 看 IR
./target/release/vmp lift --hex <hex> --base 0xfae00
```

### 看一个 region 在 blob 里长什么样

```bash
./target/release/vmp inspect /tmp/lib.qvmp
# 看 [N] patch_addr=... bc_off=... bc_len=...
# bytecode_pool 是字节流（已加密；解密 IV salt = region_id）
```

### 看跳板字节是否写对了

```python
import struct
with open('orig.so','rb') as f: orig=f.read()
with open('vmp.so','rb') as f: vmp=f.read()
for va in [0xfae14, 0xfae6c]:  # 函数入口
    a, b = struct.unpack('<I', orig[va:va+4])[0], struct.unpack('<I', vmp[va:va+4])[0]
    print(f'@0x{va:x}: {a:#010x} → {b:#010x}')
    if (b >> 26) == 0b000101:  # B imm26
        delta = (b & 0x03ffffff) << 2
        if delta & (1<<27): delta -= (1<<28)
        print(f'   B target = 0x{va + delta:x}')
```

### 设备上跑崩，看 region

logcat 里的 PC 在 0x2ab000+ 段（新 PT_LOAD trampoline 段）。
`region_id = (pc - new_segment_vaddr) / 16`。然后查 protect.log 第 region_id 行。

### 抠出受保护函数的字节码（Reverse）

加固后的 .so 末尾有 QVMP magic + payload；payload 经过 ELF-header-derived xor。
要分析时：
```bash
# 找 QVMP 偏移
grep -aob QVMP lib-vmp.so | head -1
# 拿 payload_len（QVMP 后 4 字节）
# 用 vmp-rewriter::armor::derive_payload_key + apply_payload_keystream 解密
# 然后 vmp_stub::unpack_blob 还原 StubBlob
```

写一个小 helper bin 在 `crates/vmp-cli/src/bin/extract.rs` 即可。

---

## 4. 命名 / 风格约定

| 约定 | 例子 |
|---|---|
| 公开 API 中文文档注释 | `/// 把 IR 序列编码成字节流。` |
| 内部辅助函数英文 + 简短 | `fn build_brk_trampoline(...)` |
| 错误码用短串 | `Error::vm("E:no-region")` 而不是描述性长串（避免暴露语义到 .rodata） |
| anti-* 模块函数返回 `&'static str` evidence | `out.push("frida_in_maps")` |
| 测试名带 arch 前缀 | `arm64_factorial_loop` |
| Phase 计数 | commit message 起头 `Phase N:` |

`#[cfg(any(target_os = "linux", target_os = "android"))]` 是默认条件；新增需要
平台特化的功能都按这个 gate。

---

## 5. 性能 / 体积调优

### 体积

- `Cargo.toml` `[profile.release]` 已开 `opt-level = "z"`、`lto = "fat"`、
  `strip = "symbols"`、`panic = "abort"`、`overflow-checks = false`、`codegen-units = 1`
- vmp-runtime cdylib `--no-default-features` 关 env_logger（节省 ~200KB）

### 性能

- 解释器主循环用 `match` 而非 vtable —— rustc LLVM 会优化成 jump table
- handler-table dispatch 是命中率最高的 hot path；不要往里加分支
- `NativeExec` 路径每次都 cache flush；如果要更快可以维护 thunk 缓存（同一 raw_instr
  patch 一次重用）—— 当前每次都 patch（200ns vs 50ns，差 4×）

---

## 6. 提 PR 时

- 跑 `cargo build --workspace --release`，**0 警告**
- 跑 `QVMP_DISABLE_CTOR=1 cargo test --workspace --lib --tests`，**21 项全过**
- 跑 `bash samples/realworld/harden_so.sh /usr/lib/x86_64-linux-gnu/libz.so.1`，
  pipeline 不能崩（regions 数因 x86_64 lifter 限制可能小，但不应 panic）
- commit message 中文 + Phase 编号 + 列改动清单
- 大改动同步更新 `docs/ARCHITECTURE.md` / `docs/ROADMAP.md`

---

## 7. 紧急联系

代码看不懂时，先读：
1. `docs/ARCHITECTURE.md`（本目录）
2. `crates/vmp-isa/src/opcode.rs`（核心 enum 一定要熟）
3. `crates/vmp-stub/src/entry.rs`（dispatch_vm 入口）
4. `crates/vmp-arch/src/arm64/decode.rs`（lifter 主体）

历史决策记录在 `CHANGELOG.md` 各 Phase 的 commit message 里。
