# 已完成（Phase 4）

## 高优先级（用户提过 + 已铺架构）

### 1. 直接调用改间接调用 / 导入表极简化 + 动态解析 ✅

- `vmp-rewriter::imports::djb2_hash64` —— 64-bit djb2 共享算法
- `vmp-rewriter::armor::hash_dynsym_imports` —— 完整实现：扫 .dynsym + .dynstr，
  替换 STT_FUNC + UND 符号名为 `h_xxxxxxxx`（16 字节 hex），保留 `__libc_start_main`
  等 bootstrap 符号
- `imports.tbl`（`QIMP` magic）写到 ELF 末尾，包含 hash → 原名映射
- runtime（`vmp-runtime/src/resolver.rs`）启动时扫已加载模块的 `QIMP` blob，
  对每条 `dlsym(RTLD_DEFAULT, name)` 解析 → 缓存 hash → 真实地址
- `qvmp_dispatch` C ABI 暴露给受保护代码做 hash → addr 查询

### 2. VMP 算术混淆（指令膨胀） ✅

新模块 `vmp-codegen::transform`，CLI `--level heavy/paranoid` 自动启用：
- `Add` → `Neg+Sub` 二步展开
- `Sub` → `Not+MovI(1)+Add+Add` 四步展开（二补码恒等）
- `MovI K` → `MovI K1 / MovI K2 / Xor`，`K1 ⊕ K2 = K`（K1/K2 RNG 决定）
- 每条变形保持跳转 IR 索引语义（remap 表保证 Br/BCond/Call 正确指向）

不透明谓词框架已铺，`opaque_predicate: true` 启用后插入永远 taken / 永远不 taken
的算术条件分支（留 Phase 5 完整实现）。

### 3. NEON 向量算术 ✅

- VOp 新增 `VAdd / VSub / VMul`（整数）
- `Instr` 加 `lane: u8` + `Layout::r3wl()`（width=lane size，lane=lane count）
- 解释器 `vec_op` 闭包逐 lane 计算
- ARM64 lifter 识别 `Advanced SIMD three same`（ADD/SUB/MUL）：8B/16B/4H/8H/2S/4S/2D

浮点向量（FAdd/FSub/FMul of 4S/2D 等）当前仍走标量 FP 路径，留 Phase 5 扩展。

## 中优先级 ✅

### 4. cdylib runtime（libqvmp_runtime.so） ✅

`vmp-runtime` 升级为 `crate-type = ["rlib", "cdylib"]`，输出
`libqvmp_runtime.so`（Linux/Android）/ `qvmp_runtime.dll`（Windows）：

- `JNI_OnLoad`（Android）/ `.init_array` ctor（Linux）/ `DllMain`（Windows）作入口
- `sig::install_sigtrap_handler` 注册 `SIGTRAP` `sigaction(SA_SIGINFO)`
- `scan::scan_loaded_modules` 调 `dl_iterate_phdr` 找所有已加载 .so 的 PT_LOAD 段，
  搜 `QVMP` magic，解密 payload，缓存 (region_id → blob) 表
- `sigtrap_handler`：从 ucontext 找 mcontext.pc（自适应 libc 偏移）→ 收集 X0..X7
  → `dispatch_region` → 写回 X0、设 PC = LR

aarch64 Linux/Android 完整路径；Windows / x86_64 入口骨架已铺。

### 5. .a 静态库重写 ✅

`vmp-rewriter::ar_rewriter`：
- 复用 `vmp-loader::ar::members` 解析
- 把整个 stub blob 作为新 ar 成员（`qvmp_blob.bin`）追加到 archive 末尾，保持
  System V / GNU 风格 60 字节 header 与偶数对齐
- CLI 子命令 `vmp static-rewrite`

逐 .o 内 lift（跨 .o 重定位）留 Phase 5 —— 当前路径让链接器把 blob 透明合入 .so/.exe。

### 6. payload 解密的 cdylib 实现 ✅

`vmp-rewriter::armor::derive_payload_key` / `apply_payload_keystream` 抽成 pub
函数，runtime `scan.rs::try_extract_qvmp` 用同一函数对 dump 出的 blob 字节解密，
再调 `vmp_stub::unpack_blob` 还原 StubBlob。

### 7. ARMv7 (armeabi-v7a) lifter ✅

`vmp-arch::arm32` MVP 子集：
- ARM 模式 32-bit 定长指令
- MOV/ADD/SUB/AND/ORR/EOR/CMP（imm + 简单 reg 形）
- LDR/STR（imm12 offset）
- B/BL/B.cond
- Thumb 模式留 Phase 5（指令长度变化、`ITT/ITTT` 块需要单独处理）

寄存器映射：R0..R12 → V0..V12，SP=V13，LR=V14，PC=V15。

## 低优先级 ✅

### 8. x86_64 lifter ✅

`vmp-arch::x86_64` MVP：
- REX.W MOV r64, imm64
- RET / PUSH r64 / POP r64
- CALL rel32 / JMP rel32 / NOP
- 寄存器映射：RAX=V0..R15=V15

完整覆盖建议接 `iced-x86`（feature `decoder` + `no_std` ~150KB），符合 README 的
扩展路径，当前路径不引入额外依赖即可保护已识别的 prologue/epilogue。

### 9. APK 加壳 wrapper 工具 ✅

`vmp-rewriter::apk` 编排层（不引入 zip 依赖，依赖 caller 用 `unzip`/`apksigner`）：
- `list_libs(apk_dir)` 扫描 `lib/{arm64-v8a,armeabi-v7a,x86_64}/*.so`
- `pack_one_lib(loaded, blob, opts, abi)` 对单个 .so 调 rewrite_elf
- `runtime_target_path(apk_dir, abi)` 计算 `libqvmp_runtime.so` 应放置的位置
- CLI 子命令 `vmp apk-list`

完整 APK pipeline（unzip → batch protect → zip → apksigner → zipalign）由用户脚本编排，详见 docs/APK_PACKING.md。

### 10. Windows PE 加壳 ✅

`vmp-rewriter::pe_writer`：
- 解 PE/PE32+ COFF/optional header（NumberOfSections / SizeOfImage / SectionAlignment）
- 追加新 `.qvmp` section（PT_LOAD 等价 + IMAGE_SCN_MEM_EXECUTE）
- 内含跳板表（每个 region 16 字节 BRK 跳板）+ blob 字节
- 修改 NumberOfSections + 重算 SizeOfImage
- ARM64 Windows X18 平台保留：`PeRewriteOptions::arm64_windows_x18_isolation` 旗标
  传到 lifter 路由层（Phase 5 把 X18 routing 完整接到 lifter）

CLI 子命令 `vmp pe-rewrite`。

## Cleanup 完成 ✅

- ✅ vmp-rewriter 的 `unused import StubRegion` warning 清掉
- ✅ vmp-codegen 的 `unused Cond` warning 清掉
- ✅ vmp-loader 的 `goblin Strtab.get` deprecated 改 `get_at`
- ✅ vmp-runtime sig.rs 的 function pointer cast warning 清掉
- ✅ vmp-loader/ar.rs `unused mut` warning 清掉
- 临时调试 log（`stage X` / `[map_data]` / `SYSCALL`）保持 `release_max_level_warn`
  锁回（已经在 release 模式 dead-code-eliminate）
- ✅ README 补 Phase 4 完成内容、TODO 完成项

## Phase 5 / 6 已完成

见 README **Phase 5 / 6 增强** 章节。要点：
- 反分析全部 9 模块（anti_debug/dump/hook/ida/inject/vm/emulator/unpack + hwbp）
- ProtectFlags bitflag + QVMP_FLAGS env var + QVMP_RESPONSE policy
- 按页加解密（runtime SIGSEGV handler + 递归保护）
- 多线程 dispatch 锁
- ARM64：MulH 真高 64 / IndirectBr / VFAdd-VFSub-VFMul-VFDiv / LDRSB-LDRSH-LDRSW
  / LDP-STP FP / BTI-jc trampoline / DP-1src RBIT-REV-CLZ / FNEG-FABS-FSQRT /
  ADC-SBC / CCMP / HINT 全集 / PAC* / PRFM
- x86_64 lifter 扩展（MOV/ADD/SUB/AND/OR/XOR/CMP/Jcc/INC/DEC）
- Thumb T1 子集
- 完整性 hash baking (QHSH magic) + runtime 自动加载
- CNTVCT_EL0 时序检测（避开 clock_gettime hook）
- cdylib runtime host 集成测试 5 项

## 仍留作 Phase 7 的部分

- expand_arith 的 opaque_predicate（永远 taken/不 taken 的算术条件分支）完整实现
- NEON 浮点向量算术（FADD/FSUB/FMUL of 4S/2D 等）
- ARMv7 Thumb 模式 lifter
- x86_64 完整 lifter（接 `iced-x86`）
- ARM64 Windows X18 平台保留寄存器路由（lifter 层）
- .a 静态库的逐 .o lift（跨 .o R_AARCH64_CALL26 重定位处理）
- cdylib runtime 在 SIGTRAP handler 中收集 FP/NEON 参数（D0..D7）

## 当前最新成品（截至 Phase 4）

```
受保护原 ELF (heavy + armor + expand_arith):
  E:\Qsafe\vm\samples\multifn\multifn-final              ~9 KB（膨胀后）
   - 5 函数 lift / 4 跨函数 BL → CallRegion
   - dup=4 多态 handler / junk 25% / 6 种 decoy 序列
   - per-region IV salt 加密 + ELF payload 二次加密
   - .shstrtab / .strtab 段名 / 符号名全部置 0
   - .dynsym imports（非 bootstrap 符号）替换为 hash 名 + imports.tbl
   - VMP 算术膨胀（Add/Sub/MovI 多步等价展开）
   - 末尾 PT_LOAD 0x205000 含跳板 + 加密 blob + QIMP imports.tbl

cdylib 运行时:
  E:\Qsafe\vm\target\aarch64-linux-android\release\libqvmp_runtime.so
   - JNI_OnLoad + SIGTRAP handler + dl_iterate_phdr 扫描 + dlsym 解析
   - 公开 C ABI `qvmp_dispatch(region_id, args, nargs)` 给非 BRK 路径用

外壳运行版 (vmp-runtime + heavy blob 嵌入):
  E:\Qsafe\vm\target\aarch64-linux-android\release\vmp-runtime  ~290 KB
```

## 当前已修复的关键 bug 列表（保留 Phase 1..3 历史）

- X31 双重含义 (XZR vs SP) → V63 路由
- VM 真栈 (64KB Vec, V31 = top)
- target_os = "android" 对应的 svc inline asm
- Inline asm clobbers (x1..x18, NZCV)
- branch byte-offset fixup junk-aware (从 lifter 移到 codegen 第二遍)
- 多函数 / 跨 region BL → CallRegion + NestedDispatchHost
- entry_region 字段
- ADD/SUB shifted register imm6 移位字段
- 真 logical-imm 解码 (DecodeBitMasks 严格实现)
- UMULL/UMADDL/SMADDL 32x32→64
- LDR/STR pre/post-indexed 全形
- LDR/STR (register offset) 各 opc
- ADRP / ADR PC-rel
- LDP/STP pair pre/post/offset
- CBZ/CBNZ/TBZ/TBNZ
- CSEL family (CSEL/CSINC/CSINV/CSNEG)
- LDADDAL / SWPAL / CASAL LSE atomics + LDXR/STXR + DMB/DSB/ISB
- FMOV imm (VFPExpandImm 严格实现) / FADD/FSUB/FMUL/FDIV S/D / FCMP / FCVTZS / SCVTF
- SUBS imm 标志位顺序（必须在 dst 写之前算 cmp）
- data_segments：原 ELF 非代码段 mmap 到原 vaddr (.rodata / .data / .bss)
- vm_call_region_fp：跨 region call 同时传 GPR + FP 寄存器
- decoy 序列 BCond 死循环（移除）
- expand_arith pass remap IR 索引（保跳转目标语义）
- imports.tbl bootstrap 符号 PRESERVE_NAMES（避免动态链接器找不到 `__libc_start_main`）
- payload 解密 key 派生 runtime / rewriter 同步（抽公共函数）
