# Qsafe VMP

ARM64 优先、模块化的 Rust **VMP（Virtual Machine Protection）加壳器**。

把目标二进制里的函数翻译成自定义虚拟机字节码，在原 ELF / PE / .a / APK 中嵌入
解释器 + 反分析层，**抬高静态分析、动态调试、dump、hook、注入的成本**。

> **定位**：抬高分析成本，不是密码学级不可破解。适合商业反破解 / CTF 挑战 / 教学；
> 不适合作为密钥的唯一防线。

---

## 快速上手（30 秒）

```bash
# 1. 构建工具链
cargo build --release -p vmp-cli

# 2. 加固一个 arm64 .so / 可执行文件
bash samples/realworld/harden_so.sh path/to/your.so --level heavy
# 输出 /tmp/qvmp-harden.XXX/your-vmp.so + protect.log + rewrite.log

# 3. （在你本地 NDK 机器上）交叉编译运行时
export NDK=/path/to/android-ndk-r26d
rustup target add aarch64-linux-android
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android35-clang
cargo build --release -p vmp-runtime --target aarch64-linux-android --no-default-features

# 4. 推到 Android 设备运行
adb push target/aarch64-linux-android/release/libqvmp_runtime.so /data/local/tmp/
adb push your-vmp.so /data/local/tmp/
adb shell "
    cd /data/local/tmp
    LD_PRELOAD=./libqvmp_runtime.so ./your-vmp.so
"
```

实测真实 Android 二进制（[`samples/realworld/out/imgui/`](samples/realworld/out/imgui/)）：
**3,314 / 3,315 函数 VMP 保护（99.97%），体积 2.7 MB → 7.9 MB**。

---

## 文档导航

| 文档 | 给谁看 | 内容 |
|---|---|---|
| 本文 | 所有用户 | 起步、CLI、项目结构、加固成品演示 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 想懂技术 / 改 lifter / 加新架构 | lift→encode→interpret 全链路、Magic blob 格式、ISA |
| [docs/MAINTAINERS.md](docs/MAINTAINERS.md) | 接手维护的下一位 | 在哪加 VOp / 加架构 / 加 anti-* / 常见坑 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 决定下一步做什么 | Phase 9+ 计划 + 已知限制 |
| [docs/APK_PACKING.md](docs/APK_PACKING.md) | APK 加壳 | unzip → batch protect → repack → apksigner |
| [CHANGELOG.md](CHANGELOG.md) | 想看进化历史 | Phase 1–8 完成的事 |

---

## 项目结构

```
qsafe/
├── crates/
│   ├── vmp-core         # 通用类型: Arch / Os / ObjectFormat / ProtectConfig / Error
│   ├── vmp-isa          # 语义指令集 VOp + 物理 ISA 随机化（IsaSpec）
│   ├── vmp-codegen      # IR → 字节码（编码 + 流加密 + junk + arith expand）
│   ├── vmp-interpreter  # VM 主循环 + handler-table dispatch + HostBridge trait
│   ├── vmp-arch         # ARM64 / ARMv7 / Thumb / x86_64 lifter
│   ├── vmp-loader       # ELF / PE / AR 解析 + .eh_frame_hdr 函数挖掘
│   ├── vmp-protect      # 反 debug / dump / hook / IDA / inject / VM / emulator + HW BP + 完整性
│   ├── vmp-stub         # StubBlob 格式 + dispatch_vm + LinuxHost（含 RWX thunk）
│   ├── vmp-rewriter     # ELF / PE / AR rewrite + armor + page-crypto + APK 编排
│   ├── vmp-runtime      # cdylib libqvmp_runtime.so（JNI_OnLoad + SIGTRAP / SIGSEGV handler）
│   └── vmp-cli          # `vmp protect / rewrite / lift / run / inspect / ar-list / static-rewrite / pe-rewrite / apk-list`
├── samples/
│   ├── multifn/         # 多函数 NDK 编译 demo
│   ├── fpdemo/          # FP 标量 demo
│   ├── sumsq/           # ARM64 sumsq
│   └── realworld/
│       ├── realworld.c  # 真实 SDK 风格 demo（加密内核 + NEON + syscall + license）
│       ├── harden_so.sh # 单 .so 加固脚本（所有用户测试入口）
│       ├── build_apk.sh # 端到端 APK pipeline
│       └── out/imgui/   # 真实加固成品 + 日志（git tracked）
└── docs/                # 维护者深度文档
```

数据流（高层）：

```
ELF / .so / .a / PE  ──vmp-loader──▶  CodeRegion + Symbol
                                          │
                                          ▼
                                   vmp-arch::lift            ┐
                                          │                  │ Lift 阶段
                                          ▼                  │
                                   IR (Vec<vmp_isa::Instr>)  ┘
                                          │
                                          ▼
                                vmp-codegen::resolve_program (IR 索引化)
                                          │
                                          ▼
                                vmp-codegen::expand_arith    (混淆膨胀)
                                          │
                                          ▼
                                vmp-codegen::CodeGen::encode
                                  - 随机变体 + junk + 流加密 + per-region IV salt
                                          │
                                          ▼
                                  vmp-stub::pack_blob         ┐
                                          │                   │ Pack 阶段
                                          ▼                   │
                              StubBlob (ISA + 字节码 + region) ┘
                                          │
                                          ▼
              vmp-rewriter (ELF/PE/AR 嵌入 + armor + 跳板 + magic blob)
                                          │
                                          ▼
                                   加固后二进制
                                          │
                                          ▼ ←── 在 Android / Linux 真机
                              libqvmp_runtime.so 加载
                                  - JNI_OnLoad / .init_array
                                  - 反 * 检查
                                  - SIGTRAP handler 接管 BRK 跳板
                                  - dispatch_vm → 解释器（含 hybrid native_exec 兜底）
```

---

## CLI 参考

```bash
vmp protect <input> -o <blob.qvmp> [--level light|standard|heavy|paranoid] \
                                   [--seed N] \
                                   [--only func1 --only func2] \
                                   [--exclude func3] \
                                   [--skip-trap-pct 30] \
                                   [--no-hybrid]

vmp rewrite <input> <blob.qvmp> -o <output.so> \
                                [--strip-names | --no-strip-names] \
                                [--xor-payload | --no-xor-payload]

vmp lift --hex <bytes> [--base 0x1000] [--arch arm64|x86_64]
vmp run <blob.qvmp> [--region N] [--arg V0 --arg V1 ...]
vmp inspect <blob.qvmp>

vmp ar-list <archive.a>                           # 列 .a 静态库成员
vmp static-rewrite <archive.a> <blob.qvmp> -o <new.a>

vmp pe-rewrite <input.exe> <blob.qvmp> -o <out.exe> [--x18-isolation]

vmp apk-list <apk_unpacked_dir>
```

`harden_so.sh` 是**实战推荐入口**——一条命令跑完 protect + rewrite + 诊断报告，
绝大多数情况不需要直接调底层 CLI。

---

## 加固层级（4 档）

| Level | seed | encrypt | junk | dup | anti_debug | anti_vm | hybrid |
|---|---|---|---|---|---|---|---|
| `light` | 固定 | ❌ | ❌ | 1 | ❌ | ❌ | ✅ |
| `standard` | 固定 | ✅ | ✅ 25% | 2 | ❌ | ❌ | ✅ |
| `heavy` | 固定 | ✅ | ✅ 25% | 3 | ✅ | ❌ | ✅ |
| `paranoid` | 固定 | ✅ | ✅ 25% | 3 | ✅ | ✅ | ✅ |

`heavy` 是商用 SDK 推荐档。

---

## Magic blob（嵌入到二进制末尾的元数据）

加固后的 ELF 在末尾追加多个 magic 块；运行时由 cdylib 扫描识别。

| Magic | 内容 | 写入条件 |
|---|---|---|
| `QVMP` | StubBlob：ISA 规范 + 字节码池 + region 表 + data segments | 总是 |
| `QIMP` | imports.tbl：djb2 hash → 原始符号名 | `--hash-imports`（默认关） |
| `QHSH` | post-rewrite SHA-256 of `.text`（runtime 启动校验） | `append_integrity_hash`（默认关） |
| `QPGT` | 页表：每页 vaddr + 8 字节 XOR key（runtime mprotect PROT_NONE 按页 lazy decrypt） | `apply_page_crypto`（默认关） |

详细字节布局见 [docs/ARCHITECTURE.md#magic-blobs](docs/ARCHITECTURE.md#magic-blobs)。

---

## 反分析层（运行时）

`libqvmp_runtime.so` 在 `JNI_OnLoad` / `.init_array` ctor 触发时跑。每项独立模块，
通过 `ProtectFlags` bitflag 单独开关。

| 模块 | 检测路径 | 默认开 |
|---|---|---|
| `anti_debug::ptrace_traceme_self_test` | `ptrace(PTRACE_TRACEME)` 自检 | ✅ |
| `anti_debug::tracer_pid` | `/proc/self/status:TracerPid` | ✅ |
| `anti_debug::prctl_set_undumpable` | `prctl(PR_SET_DUMPABLE, 0)` | ✅ |
| `anti_debug::timing_anomaly` | **CNTVCT_EL0** 直读虚拟计时器（aarch64） | ✅ |
| `anti_dump::proc_self_mem_open_count` | `/proc/self/fd` 扫 mem 句柄 | ✅ |
| `anti_hook::plt_got_modified` | 匿名可执行段（Frida trampoline 池） | ✅ |
| `anti_hook::inline_hook_in_libc` | dlsym 首字节 B/BL/LDR-literal 签名 | ✅ |
| `anti_ida::detect` | `linux_server64` / `android_x64_stub` / `IDA_HOME` env / proc 扫 | ✅ |
| `anti_inject::frida_in_maps` | `libfrida-agent` / `gum-js-loop` / 27042 端口 | ✅ |
| `anti_inject::xposed_in_maps` | `xposed` / `LSPosed` / `EdXposed` | ✅ |
| `anti_inject::substrate_in_maps` | `libsubstrate.so` / `MSHookFunction` | ✅ |
| `anti_vm::detect_vm` | `/proc/cpuinfo` hypervisor / DMI vendor | ✅ |
| `anti_emulator::detect` | `ro.kernel.qemu` / `/dev/qemu_pipe` / goldfish / Nox / droid4x | ✅ |
| `anti_unpack::verify_text_hash` | `dl_iterate_phdr` 算 SHA-256 比对 QHSH | ⚠️ 需 `append_integrity_hash` |
| `hwbp::count_set` | TracerPid + ptrace 自检（启发式） | ✅ |
| `hwbp::occupy_all` | fork helper + `ptrace SETREGSET NT_ARM_HW_BREAK` 写满 4 个 BCR.E=1 | `paranoid` |

环境变量配置：
```bash
QVMP_FLAGS=anti_debug+anti_hook+anti_inject+anti_emulator   # 关键字
QVMP_FLAGS=paranoid                                          # 全开 + HWBP 占坑
QVMP_FLAGS=none                                              # 全关
QVMP_RESPONSE=corrupt   # 默认：返回 0xDEADC0DE + syscall 噪声干扰
QVMP_RESPONSE=silent    # 仅 log
QVMP_RESPONSE=abort     # libc abort()
QVMP_RESPONSE=crash_random   # 写 0xDEADBEEF 假造 SIGSEGV，看起来像普通 bug
QVMP_DISABLE_CTOR=1     # 测试 / 集成场景：跳过 .init_array 自动 init
```

---

## Hybrid 混合执行

VMP lifter 不可能一开始就覆盖 ARM64 全集 1500+ 条指令。**Hybrid mode**（默认开）
解决了"lifter 漏指令导致函数被弃保护"的问题：

- lifter 遇到不认识的指令 → emit `VOp::NativeExec(raw_4_bytes)`（不再 emit Trap）
- 运行时由 `HostBridge::native_exec` 在一个 RWX thunk 页里：
  1. 把 VM 的 X0..X30 / NZCV 拷到真实 ARM 寄存器
  2. 跑那一条原 ARM 指令
  3. 把更新后的寄存器拷回 VM 状态

整个函数依然在 VM 内执行，BRK 跳板 / 字节码加密都不变。**等价于 "VM 内嵌 native island"**，让任何 ARM64 二进制都能 99%+ 函数保护。

性能：每条 NativeExec ≈ 100-200 ns。imgui 二进制 33,904 条 NativeExec 累计约 5 ms 总开销。

详见 [docs/ARCHITECTURE.md#hybrid-mode](docs/ARCHITECTURE.md#hybrid-mode)。

---

## 当前能力 / 限制速查

### ✅ 已支持

- ARM64 大多数 GPR / FP / NEON 整数 + FP / atomic / LSE / 控制流 / 间接跳转 / 完整性 hash
- ARMv7 ARM 模式 + Thumb T1 子集
- x86_64 prologue/epilogue 子集（MOV/ADD/SUB/CMP/Jcc/PUSH/POP/CALL/JMP）
- ELF rewrite（含追加 PT_LOAD + 写跳板 + armor + magic blob）
- AR (.a) rewrite、PE32/PE32+ rewrite（追加 .qvmp section）
- APK 编排层（解包目录扫描 + 批量 rewrite）
- 反分析 9 大模块 + 16 位 ProtectFlags
- 按页加解密 runtime 链路（rewriter side 还在 Phase 9）
- HW BP fork helper 占坑
- Hybrid 兜底 → 99%+ 函数保护
- stripped 二进制 .eh_frame_hdr 函数挖掘

### ⚠️ 已知限制

- NEON V0..V31 不被 hybrid thunk 保存恢复（Phase 9）
- ARMv7 Thumb T2 32-bit 指令未实现
- x86_64 完整指令集（接 `iced-x86` 待 Phase 9）
- `.eh_frame` unwind 表跳板感知（异常展开）
- BTI 跳板自动启用（已实现 `build_brk_trampoline_bti`，未默认接到 rewriter）
- macOS / iOS 加固

详细见 [docs/ROADMAP.md](docs/ROADMAP.md)。

---

## 开发 / 测试

```bash
cargo build --workspace            # dev build
cargo build --workspace --release  # release（开 LTO + opt-level=z）
QVMP_DISABLE_CTOR=1 cargo test --workspace --lib --tests
```

测试覆盖：
- 21 项 lib + 集成测试通过（host x86_64）
- 6 项 sample-依赖测试需 NDK 交叉编译产物（`samples/multifn/multifn`、`fpdemo` 等，已 gitignore）

CI 不需要 NDK 即可跑全部 lib + 集成测试。

---

## 安全声明

VMP 抬高分析成本，不是密码学级保护。**敏感密钥 / 关键算法应放在受信硬件 / 服务器侧**，不要靠 VMP 单层兜底。本项目适合：

- 商业 SDK 反破解 / 反调试
- 反作弊 anti-cheat（结合 server-side 校验）
- CTF 挑战题
- 教学：理解 VMP / 解释器 / 二进制改写

License: MIT OR Apache-2.0。
