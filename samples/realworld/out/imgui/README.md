# AndroidSurfaceImguiEnhanced — 加固成品

由 `samples/realworld/harden_so.sh` 对原文件加固生成。

## 文件

| 文件 | 用途 |
|---|---|
| `AndroidSurfaceImguiEnhanced-vmp` | 加固后的 ARM64 PIE 可执行（7.7MB，原 2.7MB） |
| `protect.log` | vmp protect 阶段日志（每个函数 lift / skip 详情） |
| `rewrite.log` | vmp rewrite 阶段日志 |

## 跑法

加固后的二进制需要 cdylib 运行时 `libqvmp_runtime.so` 接管 BRK trap（VMP
跳板用 `BRK #0x5156|region_id` 触发 SIGTRAP）。在你的本地机器上：

```bash
# 1. 设置 NDK 路径
export NDK=/path/to/android-ndk-r26d

# 2. 交叉编译 cdylib 运行时
cd <qsafe-workspace>
rustup target add aarch64-linux-android
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android35-clang
cargo build --release -p vmp-runtime --target aarch64-linux-android --no-default-features

# 3. 推到设备
adb push target/aarch64-linux-android/release/libqvmp_runtime.so /data/local/tmp/
adb push samples/realworld/out/imgui/AndroidSurfaceImguiEnhanced-vmp /data/local/tmp/

# 4. 运行（开 anti-* 检查 + corrupt 响应）
adb shell "
    cd /data/local/tmp
    chmod +x AndroidSurfaceImguiEnhanced-vmp
    QVMP_FLAGS=anti_debug+anti_hook+anti_inject+anti_emulator+hwbp \
    QVMP_RESPONSE=corrupt \
    LD_PRELOAD=./libqvmp_runtime.so \
        ./AndroidSurfaceImguiEnhanced-vmp
"

# 如果崩，看 logcat 与 tombstones：
adb logcat -d | tail -100
adb shell "ls -la /data/tombstones/ | tail -3"
```

## 加固指标（hybrid mode v2）

```
原始:           2,714,304 字节
加固:           7,918,184 字节  (+192%)
函数发现:       3,315 个（来自 .eh_frame_hdr 挖掘，因二进制 stripped）
VMP 保护:       3,314 个 (99.97%)  ← hybrid mode 让 lift 不认识的指令也进 VM
跳过保护:       1 个（.eh_frame_hdr 边界异常导致 lift 越界）
hybrid 指令:    33,904 条原 ARM 指令走 RWX thunk 通道（VM 内嵌 native island）
字节码池:       5,145,297 字节（含 per-region IV salt 加密）
新 segment:     vaddr 0x2ab000  size 5,201,920
跳板偏移:       0 BranchTooFar 错误
段名剥离:       .shstrtab 260 字节清零
Payload:        用 ELF header 派生 key 二次 keystream 加密
ELF 类型:       DYN (PIE) ARM64 — 与原文件一致，readelf 验证通过
```

## Hybrid mode 工作原理

lifter 遇到自己不认识的指令（NEON DUP/SHL imm 子集、TBL、CRC32、AES/SHA 等）
不再 Trap，而是 emit `VOp::NativeExec(raw_4_bytes)`。运行时由 cdylib 的
`HostBridge::native_exec` 把 VM 状态拷到真实 ARM 寄存器，在 RWX thunk 内跑那一条
原指令，再拷回。整个函数仍在 VM 内执行，BRK 跳板不变。

性能影响：每条 NativeExec ≈ 100-200 ns（reg save/restore + cache flush + 1 inst）。
imgui 的 33,904 条 NativeExec 加起来 ≈ 5 ms 总开销（一次完整跑），可接受。

可关：`vmp protect ... --no-hybrid` 退化为旧的 skip-on-trap 行为。

## 已嵌入的 magic blob

| Magic | 内容 |
|---|---|
| `QVMP` | StubBlob（ISA 规范 + 字节码池 + region 表 + data segments） |
| `QIMP` | imports.tbl（djb2 hash → 原始名映射）— 当前为空，因 hash_imports=false |
| `QHSH` | 完整性 SHA-256（runtime 启动校验，被改一字节就失败） |
| `QPGT` | 页表（按页加解密元信息）— 当前未启用 page-crypto rewriter pass |

## 反 \* 检测项（运行时由 cdylib runtime 在 init 时跑）

ProtectFlags::DEFAULT_HEAVY 默认启用：
- ANTI_DEBUG_PTRACE / TRACER_PID / PRCTL_DUMP / TIMING (CNTVCT_EL0)
- ANTI_DUMP_PROC_MEM
- ANTI_HOOK_PLT / ANTI_HOOK_INLINE
- ANTI_IDA / ANTI_UNPACK_INTEGRITY
- ANTI_VM / ANTI_EMULATOR
- ANTI_INJECT_FRIDA / XPOSED / SUBSTRATE
- HWBP_DETECT

启用 paranoid 加上 HWBP_OCCUPY（fork helper + ptrace 写满 4 个硬件断点槽位）。
