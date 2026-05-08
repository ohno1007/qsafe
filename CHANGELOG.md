# Qsafe VMP — CHANGELOG

按 Phase 倒序。每条 commit 的详细说明可在 `git log` 看到 commit message。

---

## Phase 8 — Hybrid 混合执行（2026-05-08）

**核心**：`VOp::NativeExec(raw_u32)` —— lifter 不认识的指令默认转交宿主 RWX thunk
执行，VM 状态原地拷贝。让 ARM64 任何指令都能 100% 保护。

实测 imgui (AndroidSurfaceImguiEnhanced) 二进制：**95% (3155/3315) → 99.97%
(3314/3315)**，33,904 条原 ARM 指令走 hybrid 通道。

补 NEON 解码：DUP general / DUP element / SHL imm / USHR imm。

### 改动文件

- `vmp-isa/src/opcode.rs` — VOp 加 VDupG / VDupE / VShlI / NativeExec
- `vmp-isa/src/encoding.rs` — Layout 加对应分支
- `vmp-interpreter/src/lib.rs` — 4 个 handler；`broadcast_lane` helper
- `vmp-interpreter/src/state.rs` — `HostBridge::native_exec` 默认实现
- `vmp-stub/src/linux.rs` — LinuxHost::native_exec + thunk 模板 + SaveArea
- `vmp-arch/src/arm64/decode.rs` — DUP / SHL imm 解码 + lifter hybrid 兜底
- `vmp-arch/src/arm64/mod.rs` — `Arm64Lifter::hybrid: bool`
- `vmp-arch/src/lib.rs` — `make_lifter_opts(hybrid)`
- `vmp-cli/src/main.rs` — `--no-hybrid` flag

---

## Phase 7.1 — stripped ELF 函数挖掘（2026-05-08）

`.symtab` stripped 时从 `.eh_frame_hdr` 二进制搜索表恢复函数边界。imgui 二进制
从 0 函数 → 3315 函数。

### 改动文件

- `vmp-loader/src/elf.rs` — `mine_funcs_from_eh_frame_hdr`
- `vmp-loader/Cargo.toml` — 加 byteorder

---

## Phase 7 — 真实环境鲁棒性（2026-05-08）

CLI: `--skip-trap-pct N` 自动跳过 lift Trap 占比超阈值的函数。`harden_so.sh`
单 .so 加固脚本（5 stage：protect / rewrite / 体积+段名+sha256 对比 / inspect
blob / 已保护清单）。

按页加解密 rewriter 端配套：`armor::apply_page_crypto` + `QPGT` 写入 + runtime
`scan` 自动启用 `page_crypto`。

HW BP 占坑真实实现：fork helper + `PTRACE_SEIZE` + `SETREGSET(NT_ARM_HW_BREAK)`
写 4 个 BCR.E=1。

PIE 地址处理：`RebasedLinuxHost`（< 4GB 视作 PIE 相对加 dlpi_addr，否则视作绝对）。
威胁响应：`syscall_noise()`（mmap/munmap/getpid 噪声干扰 syscall trace）。

### 改动文件

- `vmp-cli/src/main.rs` — `--skip-trap-pct`
- `samples/realworld/harden_so.sh` — 新建
- `vmp-rewriter/src/armor.rs` — apply_page_crypto
- `vmp-rewriter/Cargo.toml` — rand / rand_chacha
- `vmp-runtime/src/scan.rs` — `enable_page_crypto_from_qpgt`
- `vmp-runtime/src/resolver.rs` — `RebasedLinuxHost` + `DISPATCH_LOCK`
- `vmp-runtime/src/policy.rs` — `syscall_noise`
- `vmp-protect/src/hwbp.rs` — fork + ptrace 真实占坑

---

## Phase 6 — 反 hook 关键路径硬化（2026-05-07）

VOp 新增 9 项：MulH（真高 64）、IndirectBr、VFAdd/VFSub/VFMul/VFDiv（NEON FP 向量）、
Rbit/Rev/Clz、FNeg/FAbs/FSqrt、Adc/Sbc、Ccmp。

ARM64 lifter 补完：BR/BLR → IndirectBr / LDR sign-extend / LDP-STP FP / NEON
three-same FP 解码 / Advanced SIMD modified imm / DP-1src 完整 / SMULH/UMULH 真高 64。

BTI 兼容跳板：`build_brk_trampoline_bti` 20 字节，首条 `BTI jc`。

Runtime 硬化：SIGSEGV handler 加 SA_NODEFER + IN_HANDLER 计数器；多线程 DISPATCH_LOCK；
QVMP_DISABLE_CTOR / QVMP_INIT_BYPASS env vars；scan / resolver 16MB cap。

Anti-debug：`mrs cntvct_el0`（aarch64 用户态可读虚拟计时器，规避 clock_gettime hook）。

Thumb T1 子集 + x86_64 扩展（MOV/ADD/SUB/AND/OR/XOR/CMP/Jcc/INC/DEC/JMP rel8/INT3）。

集成测试 5 项（`vmp-runtime/tests/integration.rs`）。

---

## Phase 5 — 反 \* 模块化（2026-05-07）

9 个独立 anti-\* 模块（每个一个 .rs 文件，零交叉依赖）：anti_debug / anti_dump /
anti_hook / anti_ida / anti_inject / anti_vm / anti_emulator / anti_unpack /
hwbp。`ProtectFlags` 16 位 bitflag + `QVMP_FLAGS` env var + `QVMP_RESPONSE` policy。

按页动态加解密 runtime 侧（vmp-runtime/page_crypto.rs）。

混淆增强：`expand_arith` 加不透明谓词。

ARM64 指令补完（实测 NDK clang 高频发射）：DP-1src RBIT/REV/CLZ、ADC/SBC、CCMP/CCMN、
FP 1-src FNEG/FABS/FSQRT、SMULH/UMULH、LSE atomics 完整、HINT 全集、PAC*/PRFM 归 Nop。

Windows x86 / x86_64 加壳：`pe_writer` 按 arch 分发跳板。

`samples/realworld/`：realworld.c + build_apk.sh 端到端。

修复：VOp 数 51 → 64 后超 ISA 池容量 → heavy/paranoid `dup` 4 → 3；ProtectionPlan
手写 Default；vmp-arch x86_64 feature 加入 default。

---

## Phase 4 — 多目标产出基础（2026-05-07）

imports 表 hash 化：djb2_hash64 + `.dynsym/.dynstr` 替换为 `h_xxxxxxxx` + QIMP
imports.tbl 写入 ELF 末尾；保留 `__libc_start_main` 等 bootstrap 符号。

VMP 算术混淆：`vmp-codegen::transform::expand_arith` —— Add/Sub/MovI 多步等价
展开（保跳转 IR 索引语义），CLI heavy/paranoid 自动启用。

NEON 整数向量算术：VAdd/VSub/VMul + lane 字段编码；ARM64 lifter 识别 Advanced
SIMD three-same（8B/16B/4H/8H/2S/4S/2D）。

cdylib 运行时：`vmp-runtime` 升级 `crate-type = ["rlib", "cdylib"]`，
`JNI_OnLoad` + `.init_array` ctor + `DllMain` + dl_iterate_phdr 扫描 + ucontext
解析 SIGTRAP handler。

`.a` 静态库：`ar_rewriter` 把 blob 作为额外成员追加。

Payload 解密共享：`derive_payload_key` / `apply_payload_keystream` 抽 pub。

ARMv7 lifter MOV/ADD/SUB/CMP/LDR/STR/B/BL/Bcc MVP；x86_64 lifter MOV imm64 / RET /
PUSH-POP / CALL/JMP / NOP MVP。

APK packer 编排层；Windows PE 加壳。

---

## Phase 1–3 — 雏形（早期）

- ARM64 lifter（GPR + FP + atomic + LSE）覆盖商用 SDK 常见模式
- 解释器（handler-table dispatch + HostBridge）
- StubBlob 格式 + dispatch_vm
- ELF in-place 重写（追加 PT_LOAD + 跳板 + entry patch）
- 反调试 / 反 VM / 完整性策略层（描述阶段）
- multifn 样例端到端验证（一加 Ace 5 Pro 真机跑通）

详见 git log 早期 commit。

---

## 关键 bug 修复历史

按时间倒序：

- **expand_arith pass remap IR 索引** —— 跳转目标语义保留（Phase 5）
- **imports.tbl bootstrap 符号 PRESERVE_NAMES** —— 避免 `__libc_start_main` 找不到（Phase 4）
- **payload 解密 key 派生 runtime / rewriter 同步** —— 抽公共函数（Phase 4）
- **decoy 序列 BCond 死循环** —— 移除（Phase 3）
- **vm_call_region_fp** —— 跨 region call 同时传 GPR + FP 寄存器（Phase 3）
- **data_segments** —— 原 ELF 非代码段 mmap 到原 vaddr（Phase 3）
- **SUBS imm 标志位顺序** —— 必须在 dst 写之前算 cmp（Phase 3）
- **FMOV imm VFPExpandImm 严格实现**（Phase 3）
- **branch byte-offset fixup junk-aware** —— 从 lifter 移到 codegen 第二遍（Phase 2）
- **多函数 / 跨 region BL → CallRegion + NestedDispatchHost**（Phase 2）
- **ADD/SUB shifted register imm6 移位字段**（Phase 2）
- **真 logical-imm 解码 (DecodeBitMasks 严格实现)**（Phase 2）
- **UMULL/UMADDL/SMADDL 32x32→64**（Phase 2）
- **LDR/STR pre/post-indexed 全形**（Phase 2）
- **CSEL family (CSEL/CSINC/CSINV/CSNEG)**（Phase 2）
- **LDADDAL / SWPAL / CASAL LSE atomics + LDXR/STXR + DMB/DSB/ISB**（Phase 2）
- **ADRP / ADR PC-rel**（Phase 2）
- **LDP/STP pair pre/post/offset**（Phase 2）
- **CBZ/CBNZ/TBZ/TBNZ**（Phase 2）
- **VM 真栈 (64KB Vec, V31 = top)**（Phase 1）
- **target_os = "android" 对应的 svc inline asm**（Phase 1）
- **Inline asm clobbers (x1..x18, NZCV)**（Phase 1）
- **X31 双重含义 (XZR vs SP) → V63 路由**（Phase 1）
