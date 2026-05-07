# 明天代办

## 高优先级（用户提过 + 已铺架构）

### 1. 直接调用改间接调用 / 导入表极简化 + 动态解析
当前 ELF 重写后 `.dynsym` 仍有 import 名（PLT/GOT 静态绑定）。要做：
- 把所有 import 替换成 hash（例如 djb2 `name` → 8 字节）；保留 hash → 真实 dlsym 的运行时映射表
- 在 cdylib runtime（`libqvmp_runtime.so`）`JNI_OnLoad` / 构造函数里：
  - walk `link_map` 拿到所有已加载 .so
  - 对每个 .so 的 export 计算同样 hash → 建立全局表
- VMP 字节码中的所有 `NativeCall`（lifter 已经识别）改用 hash 间接调用：runtime 查表 → 真实 native 函数地址
- 入口：`vmp-rewriter::armor::hash_dynsym_imports`（当前 stub），需要：
  - 解析 .dynsym 找 STT_FUNC + UND
  - 把对应字符串覆盖为 hash 值（保持长度）
  - 生成一个 `imports.tbl` 描述给 runtime 用

### 2. VMP 算术混淆（指令膨胀）
当前 codegen 的 `emit_decoy_seq` 已加 6 种哑指令模式。明天扩展：
- **真指令变形**：把 `Add Rd, Ra, Rb` 改写成等价多步
  - `Sub Rd, Ra, Rb_neg` 配合 `Neg Rb_neg, Rb`
  - `Xor + And + Or` 模拟加法（位运算法则展开）
- **不透明谓词**：用永远 true/false 的算术表达式作分支条件
  - `(x*x + x) % 2 == 0` 这种 always-true（任意 int x）
- **常量打散**：`MovI rd, 0x12345678` → `MovI scratch, K1; MovI rd, K2; Xor rd, rd, scratch`
  其中 K1 ⊕ K2 = 0x12345678，K1 / K2 在 codegen 时随机
- 入口：新增 `vmp-codegen::transform::expand_arith` pass，插在 `resolve_program` 后、`encode` 前

### 3. NEON 向量算术
当前 lifter 对 `add v0.4s, v1.4s, v2.4s` / `fmul v0.2d, v1.2d, v2.2d` 等向量指令标 Trap。
- VOp 加 `VAdd / VSub / VMul / VLoadQ / VStoreQ`，width 字段编码 lane size + lane count
- 解释器用 u128 拆 lanes 计算
- ARM64 NEON encoding 在 ARMv8 ARM C7 章节，指令族 `Advanced SIMD three same`
- 优先级：商用 SDK 经常用 NEON 做加密/哈希，覆盖了才能保护这类库

## 中优先级（架构已铺好，工作量适中）

### 4. cdylib runtime（libqvmp_runtime.so）实现
- vmp-runtime 改 `crate-type = ["cdylib"]`
- `JNI_OnLoad` 作为入口：
  - 注册 SIGTRAP handler
  - 扫所有 PT_LOAD segment 找 `QVMP` magic 解析 blob 表
  - 对每个保护函数 vaddr 建立 PC → blob 映射
- SIGTRAP handler：
  - 从 `siginfo->si_addr` 读 BRK 地址
  - 读 `mov x16, #imm16` 拿 region_id
  - 收集 ucontext 寄存器 → 调 `vmp_stub::dispatch_vm_fp`
  - 把返回值写回 X0/D0
  - 设 PC 跳过 BRK 帧 + 原函数末尾（直接 ret）
- 这一步做完，`vmp rewrite` 输出的 ELF 才能**自包含运行**，不依赖外壳 vmp-runtime

### 5. .a 静态库重写
- `vmp-rewriter::ar_rewriter` 模块（新增）
- 流程：
  1. parse archive → 列 .o 成员
  2. 对每个 .o：lift → protect blob → rewrite .o
  3. 重新 pack archive（保持 ar 头格式 + 长名表）
- 输入 lib.a，输出 lib-vmp.a

### 6. payload 解密的 cdylib 实现
现在 `vmp rewrite --xor-payload` 生成的 ELF 里 payload 加密了，但还没 runtime 能解。需要在 cdylib（任务 4）里做：
- 进程加载时扫 ELF header → 派生 key
- 解密 payload → 缓存解码后的 StubBlob
- 后续 SIGTRAP 用解码后的 blob

### 7. ARMv7 (armeabi-v7a) lifter
APK 在低端机上仍跑 armeabi-v7a。基本指令集 32-bit ARM + Thumb。
- 新建 `vmp-arch::arm32` 模块
- ARM 指令集 32-bit 长度固定；Thumb 16/32-bit 混合
- 关键 lift：MOV/ADD/SUB/LDR/STR/B/BL/BX/CMP/CBZ
- 工程量约 800 行（比 ARM64 简单一些）

## 低优先级（独立大工程）

### 8. x86_64 lifter
`vmp-arch::x86_64` 当前是 stub。可变长指令更复杂；推荐接 `iced-x86` crate 做解码，VMP IR 沿用现有 VOp。

### 9. APK 加壳 wrapper 工具
- 输入: APK
- 流程: unzip → 对 `lib/arm64-v8a/*.so` 跑 protect+rewrite → zip 回 → 重签名
- 用 `zip` crate + apksigner 命令行
- 详见 [docs/APK_PACKING.md](docs/APK_PACKING.md)

### 10. Windows PE 加壳
- 重用 vmp-loader 的 PE 解析（已有）
- 写 vmp-rewriter PE 路径：append new section + 改 entry
- ARM64 Windows ABI 与 Linux 不同（X18 是平台保留），lifter 需调整 X18 routing
- 出 .exe 加壳工具

## 一些 cleanup

- vmp-rewriter 的 `unused import StubRegion` warning 清掉
- vmp-codegen 的 `unused Cond` warning 清掉
- vmp-loader 的 `goblin Strtab.get` deprecated 改 `get_at`
- runtime 一旦稳定，把临时调试 log（`stage X` / `[map_data]` / `SYSCALL ...`）全部用 `release_max_level_warn` 锁回
- README 补 Phase 4 完成内容、补 TODO 完成项

## 当前最新成品（截至本轮）

```
受保护原 ELF (heavy + armor):
  E:\Qsafe\vm\samples\multifn\multifn-final              8.5 KB
   - 5 函数 lift / 4 跨函数 BL → CallRegion
   - dup=4 多态 handler / junk 25% / 6 种 decoy 序列
   - per-region IV salt 加密 + ELF payload 二次加密
   - .shstrtab / .strtab 段名 / 符号名全部置 0
   - 末尾 PT_LOAD 0x205000 含 5 跳板 + 加密 blob

外壳运行版 (vmp-runtime + heavy blob 嵌入):
  E:\Qsafe\vm\target\aarch64-linux-android\release\vmp-runtime  ~290 KB
```

## 当前已修复的关键 bug 列表

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
