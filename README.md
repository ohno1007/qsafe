# Qsafe VMP

ARM64 优先、模块化的 Rust VMP（Virtual Machine Protection）加壳器骨架。

设计目标：**适配大、兼容广、模块化**，便于后续扩展到 Windows / x86_64 / Mach-O；
保护方式为「自实现虚拟机 + 每次构建随机化指令集 + 解释器模拟运行」，
显著抬升静态分析、动态分析、逆向工程的成本。

> ⚠️ 当前是工程骨架（端到端可跑通）。生产化还需要补完 ARM64 完整指令覆盖、
> 写回宿主二进制（patch + 嵌入 stub）以及目标 OS 上的运行时 stub 适配 —— README 末尾
> 列出了「可继续扩展的清单」。

---

## Workspace 结构

```
vm/
├── Cargo.toml                     # workspace
├── rust-toolchain.toml
└── crates/
    ├── vmp-core         # 通用类型、错误、Arch/OS/ObjectFormat、ProtectConfig
    ├── vmp-isa          # 语义指令集 VOp + 物理 ISA 随机化（IsaSpec）
    ├── vmp-codegen      # IR → 字节码 编码器，垃圾指令、流加密
    ├── vmp-interpreter  # 解释器（handler-table dispatch、HostBridge）
    ├── vmp-arch         # 架构无关 Lifter trait + ARM64 子集 + x86_64 占位
    ├── vmp-loader       # ELF / PE 解析（基于 goblin），抽函数符号 + 代码段
    ├── vmp-protect      # 反调试、反 VM、完整性策略
    ├── vmp-stub         # 运行时 stub blob 格式 + dispatch_vm 入口
    └── vmp-cli          # 一键 CLI：vmp protect / lift / run / inspect
```

每一层都通过 trait/数据结构解耦，添加新架构 / 新 OS / 新对象格式时只需扩展对应
crate，不改动其他模块。

---

## 核心保护机制

### 1. 自实现虚拟机
- **寄存器架构**：32 个 64-bit 通用寄存器 + NZCV 标志 + 栈
- **指令集**：约 33 条语义指令（数据传输 / ALU / 比较 / 控制流 / VM 切换 / 系统调用 / 反分析）
- **解释器**：handler-table dispatch，可嵌入到目标二进制的运行时 stub 中

### 2. 随机指令集
- 每次构建按 `seed` 重新生成 `IsaSpec`：
  - 1-byte **opcode 编号随机**（256 空间内打乱）
  - **寄存器编号置换**（V0..V31 在编码层完全打乱）
  - **多态 handler**：同一语义可有 N 份不同 opcode（`handler_duplication`）
  - **立即数旋转 + XOR**（`imm_rol`、`stream_key` 派生）
  - **跳转偏移 XOR**（`branch_xor`）
- 同 seed 可复现构建，便于调试。

### 3. 字节码流加密
- 32 字节 key + 16 字节 IV，喂入 ChaCha 派生 keystream，整段字节码 XOR
- 解释器与 codegen 共享同一 `IsaSpec`，运行时一次性解密整段
- 与 ISA 随机化叠加 → 字节码静态熵高、模式特征几乎为 0

### 4. 垃圾指令 / 不透明谓词
- `VOp::Junk / Nop / Obfuscate` 在解释器中是安全 noop，但反编译器必须解析
- 密度由 `ProtectLevel` 决定（standard 25%、heavy/paranoid 更多）

### 5. 反调试 / 反 VM（策略层）
- 已铺好策略：Linux ptrace/PrSetDumpable、Windows IsDebuggerPresent / NtQIP、macOS PT_DENY_ATTACH 等
- stub 在运行时按 OS 实际执行（接口已定义）

### 6. Lift → IR → Encode 流水线
```
ELF/PE  ──vmp-loader──>  CodeRegion + Symbol
                              │
                              ▼
                      vmp-arch::Lifter
                              │  IR (Vec<Instr>)
                              ▼
                       vmp-codegen
                              │  字节码（含随机变体 + 垃圾指令 + 流加密）
                              ▼
                        vmp-stub::StubBlob  →  *.qvmp
```

---

## 使用

```bash
# 编译
cargo build --release

# 直接 lift 一段 ARM64 hex 看 IR
./target/release/vmp lift --hex 40058052c0035fd6 --base 4096
# lifted 2 IR (2 输入 / 跳过 0)
#   [0000] Instr { op: MovI, rd: 0, ... imm: 42 }
#   [0001] Instr { op: Ret, ... }

# 一键保护 ELF/PE，输出 .qvmp 包
./target/release/vmp protect ./hello.elf -o hello.qvmp --level heavy

# 模拟执行 .qvmp 第一个 region
./target/release/vmp run hello.qvmp --region 0 --arg 10 --arg 32

# 查看 .qvmp 元信息
./target/release/vmp inspect hello.qvmp
```

CLI 提供 4 个保护强度：`light` / `standard` / `heavy` / `paranoid`，分别对应
不同的 ISA 变体数、垃圾指令密度、加密 / 反调试 / 反 VM 开关。

---

## 端到端测试

`crates/vmp-stub/tests/end_to_end.rs` 验证 lift→encode→pack→unpack→interpret 完整闭环：

```
cargo test -p vmp-stub --release
# test arm64_mov_imm_ret_returns_42 ... ok
# test arm64_add_xn_xm_returns_sum  ... ok
```

---

## 扩展指引

### 新增架构（如 x86_64）
1. 在 `vmp-arch/src/x86_64.rs` 实现 `Lifter` trait（建议接 `iced-x86`）。
2. 在 `vmp-arch/src/lib.rs::make_lifter` 中注册。
3. `vmp-core::Arch` 已经预留枚举值。

### 新增对象格式（如 Mach-O）
- `vmp-loader/src/lib.rs` 已通过 goblin 识别；新增 `match Object::Mach(_)` 分支并实现 `parse` 即可。

### 新增保护策略
- 在 `vmp-protect` 下加文件，定义策略枚举。
- 在 `vmp-stub::entry` 的 `dispatch_vm` 路径中加运行时分发。

### 把字节码真正写回宿主二进制
当前 CLI 只产出 `.qvmp`。完整 packer 还要：
- 把 stub 静态库（基于 `vmp-interpreter` 的 `no_std` 构建）链接到目标二进制
- 在每个 `patch_addr` 写跳板（ARM64 = `LDR + BR`，x86_64 = `MOV + JMP`）
- 修复重定位、PLT/GOT、栈展开信息（`.eh_frame` / `.pdata`）

这部分是工程量最大的步骤，但骨架已经把数据（`StubBlob.regions`）准备好，
`patch_addr` / `patch_len` / `bc_offset` 字段一对一可对接到任意 packer 后端。

### ARM64 指令补完
`crates/vmp-arch/src/arm64/decode.rs` 当前覆盖：
- 数据处理（立即数 / 寄存器）：ADD/SUB/AND/ORR/EOR (含 ANDS、CMP 别名)
- Move-wide：MOVZ / MOVN / MOVK
- Load/Store：LDR/STR (immediate offset, byte/half/word/dword)
- 跳转：B / BL / B.cond / RET / BR / BLR
- NOP

未覆盖的指令会发射 `VOp::Trap` 并写入 `LiftReport.notes`，由上层决定跳过该函数
还是混合模式（unsupported 段保持原生执行）。补完时按 ARMv8 手册的 op0 大类逐步加表即可，
不影响其他 crate。

---

## 当前状态（实际跑通）

最终交付的二进制：

```
E:\Qsafe\vm\target\aarch64-linux-android\release\vmp-runtime    277 KB
```

样例 `samples/multifn/multifn.c`（5 个全局函数：`_start` / `sum_of_squares` / `write_int` / `syscall1` / `syscall3`）经 `vmp protect` → `vmp-runtime` 包装后，在一加 Ace 5 Pro Android 设备上运行：

```
原版:    385  退出码 129
VMP版:   385  退出码 129     ← 输出/退出码完全一致
```

**保护内容**：
- 5 个函数 / 93 条 ARM64 native 指令 → 157 条 VM IR
- 4 处跨函数 BL（_start→sum_of_squares、_start→write_int、_start→syscall1、write_int→syscall3）自动转 `VOp::CallRegion`，运行时由 `NestedDispatchHost` 递归 dispatch_vm
- **每个 region 独立 IV salt 加密**：master IV ⊕ region_id 派生 effective IV，单独逆向某 region 不能复用到其他 region
- 25% 概率插入 Junk/Nop/Obfuscate 字节（branch 偏移在 codegen 二遍 fixup，不会错位）
- 每个 VOp 有 2 份多态 handler 变体（`handler_duplication=2`），同语义不同 opcode

**P0/P1 加固**：
- `VOp` / `Cond` / `Width` / `Instr` 都用手动 `Debug` 实现：release 模式下只显示 `v<hex>` 形式的数字，**`.rodata` 不含 "MovR"/"BCond"/"CallRegion"/"Syscall" 等指令助记符**
- `log` crate `release_max_level_warn` feature：`trace!/debug!/info!` 在 release 编译为 noop，字符串字面量随同 dead-code-eliminate
- `env_logger` 用 `cfg(debug_assertions)` 隔离，release 完全不 link（不拖入 regex/anstream 等大块字符串）
- 错误消息用 `E1`..`E9` / `Eb1`..`Eb3` 短代码，不暴露语义
- release profile：`opt-level="z" / lto="fat" / strip="symbols" / panic="abort" / overflow-checks=false`
- 体积演进：**1095 KB → 277 KB（约 1/4）**

**.rodata 验证**（最终残留）：
```
crates\vmp-runtime\src\main.rs    ← Rust std panic_handler 的 file!() 嵌入，要消除需 no_std
QVMP                              ← blob magic header（设计内）
```
所有 VM 内部语义字符串（指令名、错误描述、调试日志）已经全部不在 binary 里。

## 测试矩阵

11 条本地 `cargo test`：

```
arm64_mov_imm_ret_returns_42         一条 mov+ret 基线
arm64_add_xn_xm_returns_sum          ADD reg
arm64_factorial_loop                 cmp/b.cond/mul 循环
arm64_cbz_negate_when_negative       TBZ + neg
arm64_adrp_emits_absolute_address    ADRP 绝对地址
arm64_real_sumsq_returns_385         真实 NDK 编译的 sumsq.text
arm64_simulate_cli_protect_path      CLI 完整 lift+codegen 流程
arm64_real_sumsq_via_packed_blob     从 .qvmp 文件 unpack→dispatch
arm64_multifn_sum_of_squares         multifn 单 region
arm64_multifn_full_protect_path      多函数完整链路（_start→...→syscall）
isaspec_pack_unpack_roundtrip        ISA spec 序列化对称性
```

## Phase 3 完成内容

### 3a. ARM64 SIMD/FP/atomics 子集

VM 状态机加 `fregs: [u128; 32]`（NEON V0..V31）。VOp 新增 15 个：

| 类别 | 指令 |
|---|---|
| FP load/store | `FLoad` / `FStore` (S/D，含 unsigned offset + pre/post 索引) |
| FP move | `FMovR` / `FMovFromGpr` / `FMovToGpr` / FMOV imm（VFPExpandImm 严格实现） |
| FP arithmetic | `FAdd` / `FSub` / `FMul` / `FDiv` (S 32-bit / D 64-bit) |
| FP compare | `FCmp`（NaN unordered → N=0,Z=0,C=1,V=1，与 ARM ARM 一致） |
| FP↔Int | `FCvtZS`（截断 toward zero） / `SCvtF`（signed→FP） |
| Atomics | `AtomicAdd` / `AtomicSwap` / `AtomicCas`（VM 单线程顺序执行天然原子） |
| Memory barrier | `Barrier` （DMB/DSB/ISB 在单线程 VM 下 noop） |
| LDXR/STXR | 在单线程 VM 下退化为普通 load/store + 写状态码 0 |

ARM64 lifter 对应识别 native 指令：
- `MOVI Dd, #0`（NEON 立即数清零）
- `LDR/STR S/D` (immediate, unsigned offset / unscaled / pre / post-index)
- `FMOV Sd/Dd, #imm` / `FMOV Sd, Sn` / `FMOV Sd, Wn` / `FMOV Wd, Sn`（双向 FP↔GPR）
- `FADD/FSUB/FMUL/FDIV S/D`
- `FCMP S/D`
- `FCVTZS Wd/Xd, Dn/Sn` / `SCVTF Dd/Sd, Wn/Xn`
- LSE atomics: `LDADDAL` / `SWPAL`，CAS family
- `LDXR/LDAXR` / `STXR/STLXR`
- `DMB ISH` / `DSB ISH` / `ISB`

**端到端验证**（`samples/fpdemo/fpdemo.c` 真实 NDK 编译 → vmp protect → 0 跳过 / 0 unresolved）：

```c
// scale(60.0, 2.0, 3.0) = 60 * 2 / 3 = 40.0
double scale(double v, double a, double b) { return (v * a) / b; }
```

本地测试 `arm64_fpdemo_scale_returns_40` 通过：FP scalar FMUL/FDIV 路径完整。

NEON 向量算术（如 `add v0.4s, v1.4s, v2.4s`）暂未实现，留扩展点。

### 3b. ELF / SO / AR 重写

新 crate `vmp-rewriter`，新增 CLI 子命令：
- `vmp rewrite <input> <blob.qvmp> -o <output>` —— 修改 ELF / .so 嵌入 blob + 写函数入口跳板
- `vmp ar-list <archive.a>` —— 列 .a 静态库内 .o 成员

**vmp-loader 增强**：识别二进制类型 `BinaryKind { Executable, SharedObject, StaticArchive, Other }`。
- ELF (ET_EXEC / ET_DYN) 透明支持
- AR(.a) 解析归档头、GNU 长名表、逐个 .o 抽函数符号

**rewrite 输出 ELF 结构**（实测 `multifn`）：

```
新增 LOAD segment @ vaddr=0x205000 (紧贴原 .text 后 PIE 范围内)
  ├── trampoline[0..N-1]: 每个 16-byte
  │     mov  x16, #region_id
  │     brk  #0x5156|low8(region_id)    ← magic 'QV' + region_id
  │     nop
  │     b    .                          ← 兜底
  └── magic "QVMP" + len:u32 + 完整 stub_blob

原 .text 各 region.patch_addr 写：
  b    <对应 trampoline 虚拟地址>        ← 4 字节 ARM B-imm26（±128MB 内）
```

实测 `multifn-rewritten` ELF：
- 原 5 个函数入口字节都被改成 `B 0x205040` 等
- 新 LOAD segment 0x205000 加上去（readelf 可见）
- 跳板字节正确：`10 00 80 d2 c0 2a 2a d4 1f 20 03 d5 00 00 00 14`（mov x16,#0; brk 0x5156; nop; b .）
- 嵌入 blob magic "QVMP" + 1696 字节字节码

### 3c. APK 加壳路径

详见 [docs/APK_PACKING.md](docs/APK_PACKING.md)。

简短版：
1. unzip APK，对 `lib/arm64-v8a/*.so` 跑 `vmp protect` + `vmp rewrite`
2. 把改后的 .so 写回 APK
3. 在 APK 里附一个 `libqvmp_runtime.so`（vmp-runtime 改 cdylib + 注册 SIGTRAP handler）
4. SIGTRAP handler 在 BRK 触发时读 region_id（从 X16 或 BRK imm16）→ 调 dispatch_vm
5. 重新签名 + zipalign

运行时 dispatcher（cdylib）骨架已在 APK_PACKING.md 详细描述；当前未产出实际
`libqvmp_runtime.so`，但所有材料都齐了：vmp-stub 提供 `dispatch_vm` API，
LinuxHost 实现完整，rewriter 写的跳板格式确定。

### 3 留作 Phase 4 的部分

- **NEON 向量算术**：lifter 当前对 `add v0.4s, ...` 等 SIMD 向量指令标 Trap
- **运行时 dispatcher cdylib**：APK_PACKING.md 提供完整设计，需写 ~200 行 Rust + 系统编程（mmap 扫描、SIGTRAP handler、context 操纵）
- **ARMv7 (armeabi-v7a)**：32-bit ARM lifter
- **x86_64 lifter**：vmp-arch::x86_64 当前仅是 stub
- **DEX 加壳**：超出本项目范围（属于 Java 字节码加壳工具领域）

## Phase 4 完成内容

### 4a. cdylib 运行时（libqvmp_runtime）

`vmp-runtime` 现在同时输出 `bin` 与 `cdylib`（`crate-type = ["rlib", "cdylib"]`）。
模块结构：

| 文件 | 作用 |
|---|---|
| `vmp-runtime/src/lib.rs` | `JNI_OnLoad` / `__attribute__((constructor))` / `DllMain` 入口；公开 C ABI `qvmp_dispatch` |
| `vmp-runtime/src/scan.rs` | `dl_iterate_phdr` 扫已加载 .so，找 `QVMP` magic 并用 ELF header 派生 key 解密 payload |
| `vmp-runtime/src/sig.rs` | aarch64 Linux/Android SIGTRAP handler；从 ucontext 解析 X0..X29 / PC，调 dispatch_vm 后写回 X0、设 PC=LR |
| `vmp-runtime/src/resolver.rs` | imports.tbl 解析（hash → dlsym）+ region → blob 路由 |

`vmp-rewriter::armor::derive_payload_key` / `apply_payload_keystream` 抽出来，
runtime 与 rewriter 共享同一加密函数，单元测试覆盖 pack/unpack 对称。

### 4b. 算术混淆膨胀（expand_arith）

新模块 `vmp-codegen::transform`：
- `Add Rd, Ra, Rb` → `Neg t, Rb ; Sub Rd, Ra, t`
- `Sub Rd, Ra, Rb` → `Not t, Rb ; Add t, t, 1 ; Add Rd, Ra, t`（二补码恒等）
- `MovI rd, K` → `MovI tmp, K1 ; MovI rd, K2 ; Xor rd, rd, tmp`，`K1 ⊕ K2 = K`，K1/K2 RNG 决定

CLI `vmp protect --level heavy/paranoid` 自动启用；保持跳转目标语义（remap IR 索引）。

### 4c. NEON 向量算术

VOp 新增 `VAdd / VSub / VMul`（整数向量逐 lane）：
- 编码：r3w + lane 数量字节（lane size 由 `width` 决定）
- 解释器：`vec_op` 闭包逐 lane 计算，剩余高位保留
- ARM64 lifter 识别 Advanced SIMD three-same `ADD/SUB/MUL`（含 D / Q 8B/16B/4H/8H/2S/4S/2D）

### 4d. 导入表 hash 化（hash_dynsym_imports + imports.tbl）

新模块 `vmp-rewriter::imports`：
- `djb2_hash64` 算法（runtime 与 rewriter 共享）
- ELF `.dynsym` 中的 STT_FUNC + UND 符号 → hash → 8 字节 hex 替换 `.dynstr` 字节
- 保留关键 bootstrap 符号（`__libc_start_main` 等）原名，否则进程起不来
- 副产 `imports.tbl`（`QIMP` magic）写到 ELF 末尾，runtime 启动时调 `dlsym` 解析

### 4e. .a 静态库 / Windows PE / APK packer

| 模块 | 作用 |
|---|---|
| `vmp-rewriter::ar_rewriter` | 把 stub blob 作为额外 archive 成员追加，链接器后续合入产出 .so/.exe |
| `vmp-rewriter::pe_writer` | PE / PE32+ 加壳：追加 `.qvmp` section（含跳板表 + blob）；写 NumberOfSections / SizeOfImage |
| `vmp-rewriter::apk` | APK 解包目录扫描 `lib/<abi>/*.so`；按 ABI 分类调 rewrite_elf；runtime 路径计算 |

CLI 新增子命令：`vmp static-rewrite` / `vmp pe-rewrite` / `vmp apk-list`。

### 4f. ARMv7 / x86_64 lifter MVP

| 模块 | 范围 |
|---|---|
| `vmp-arch::arm32` | ARM 模式 32-bit 定长：MOV/ADD/SUB/CMP（imm + reg）/ LDR/STR / B/BL/Bcc。Thumb 模式留 Phase 5 |
| `vmp-arch::x86_64` | REX.W MOV r64,imm64 / RET / PUSH/POP / CALL/JMP rel32 / NOP。生产路径建议接 `iced-x86` |

两套 lifter 都通过 `vmp_arch::make_lifter(Arch)` 工厂注册，lift→encode→interpret 链路通用。

## Phase 4 工具链

| crate | 行数 | 作用 |
|---|---|---|
| `vmp-runtime` | ~600 | bin（外壳 + 嵌入 blob）+ cdylib（libqvmp_runtime.so，JNI/SIGTRAP/扫 PT_LOAD/dlsym 解析） |
| `vmp-rewriter` | ~900 | ELF/PE/AR rewrite + armor + imports.tbl + APK 编排 |
| `vmp-codegen` | ~500 | + transform.rs（expand_arith pass） |
| `vmp-arch` | ~1500 | + arm32 / x86_64 MVP |
| `vmp-isa` | ~700 | + VAdd/VSub/VMul + lane 字段编码 |

## 工具链一览

| crate | 行数 | 作用 |
|---|---|---|
| `vmp-core` | ~200 | 通用类型 / Arch / Error / ProtectConfig |
| `vmp-isa` | ~600 | VOp（51 个语义指令） / 编码 / IsaRandomizer |
| `vmp-codegen` | ~250 | IR→字节码 / 全局 branch resolve / 流加密 |
| `vmp-interpreter` | ~450 | VM 主循环 / FP / atomic / handler dispatch |
| `vmp-arch` | ~900 | ARM64 lifter（GPR + FP + atomic + LSE）；x86_64 stub |
| `vmp-loader` | ~280 | ELF / PE / AR 识别与解析 |
| `vmp-protect` | ~80 | 反调试 / 反 VM 策略层 |
| `vmp-stub` | ~470 | StubBlob 序列化 / dispatch_vm / NestedDispatchHost / LinuxHost |
| `vmp-runtime` | ~170 | aarch64-android 外壳：嵌入 blob + Linux syscall bridge |
| `vmp-rewriter` | ~280 | ELF in-place 重写：追加 LOAD segment + 跳板 + entry patch |
| `vmp-cli` | ~330 | `protect` / `lift` / `run` / `inspect` / `rewrite` / `ar-list` |

## 安全声明

VMP 类技术的核心价值在于**抬高分析成本**，而非提供密码学级别的不可破解保证。
本项目同样适用此原则：用于商业产品防破解、CTF 挑战、教学演示是合适的；
**不适合**用作敏感密钥/算法的最终防线 —— 真正的秘密应当放在受信硬件 / 服务器侧。
