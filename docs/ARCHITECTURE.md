# Qsafe VMP — 架构 / 技术深度

读完本文你能：
- 理解从输入二进制到输出加固成品的每一步
- 知道每个 magic blob 字节布局
- 理解 VMP IR / ISA 随机化机制
- 理解 hybrid 模式怎么把"未知指令"塞回 native 跑
- 知道 anti-* 模块在哪、改它要碰什么

---

## 目录

1. [总体流水线](#总体流水线)
2. [vmp-isa：语义指令 + 物理 ISA 随机化](#vmp-isa)
3. [vmp-arch：lifter](#vmp-arch)
4. [vmp-codegen：IR → 字节码](#vmp-codegen)
5. [vmp-stub：StubBlob + dispatch_vm](#vmp-stub)
6. [vmp-rewriter：嵌入到 ELF / PE / AR](#vmp-rewriter)
7. [vmp-runtime：cdylib 接管运行时](#vmp-runtime)
8. [vmp-protect：反分析层](#vmp-protect)
9. [Magic blobs](#magic-blobs)
10. [Hybrid mode](#hybrid-mode)
11. [PIE 地址处理](#pie-地址处理)
12. [调试 / 排错](#调试--排错)

---

## 总体流水线

```
┌─────────────┐   ┌──────────┐   ┌──────────┐   ┌─────────┐   ┌──────┐
│   Input     │──▶│  Loader  │──▶│  Lifter  │──▶│ CodeGen │──▶│ Pack │
│ ELF/PE/.a   │   │ (parse)  │   │ (decode  │   │ (encode │   │ blob │
└─────────────┘   └──────────┘   │  to IR)  │   │  to bc) │   └──────┘
                                  └──────────┘   └─────────┘       │
                                                                    ▼
                                                              ┌─────────┐
                                                              │ Rewrite │
                                                              │ (embed  │
                                                              │  + 跳板)│
                                                              └─────────┘
                                                                    │
                                                                    ▼
                            ┌────────── 加固后二进制 ──────────┐
                            │  原 .text（每个保护函数入口写  │
                            │            B → trampoline）    │
                            │  + 新 PT_LOAD：跳板表 + blob   │
                            │  + magic blob: QVMP/QIMP/QHSH  │
                            └─────────────────────────────────┘
                                                                    │
                                                       Android 加载  ▼
                            ┌────────── libqvmp_runtime.so ──────────┐
                            │  JNI_OnLoad → init                     │
                            │  scan: dl_iterate_phdr 找 magic blobs │
                            │  resolver: dlsym 解 imports.tbl       │
                            │  sig: 注册 SIGTRAP handler             │
                            │  protect: 反 * 检测 + 响应             │
                            └────────────────────────────────────────┘
                                                                    │
                                              受保护函数被调用       ▼
                            ┌──────────── 原 .text 入口 ────────────┐
                            │  B → trampoline                        │
                            │       MOV X16, #region_id              │
                            │       BRK #0x5156|region_id_low8       │
                            │       NOP / B .                        │
                            └────────────────────────────────────────┘
                                                                    │
                                                BRK 触发 SIGTRAP    ▼
                            ┌──────────── sig::sigtrap_handler ─────┐
                            │  从 ucontext 取 X0..X7                 │
                            │  resolver::dispatch_region(region_id)  │
                            │      ↓                                 │
                            │  vmp_stub::dispatch_vm                 │
                            │      ↓                                 │
                            │  Interpreter::run（解释字节码）        │
                            │      ├─ 标准 VOp → 解释器内执行       │
                            │      └─ NativeExec → host RWX thunk    │
                            │                跑原 ARM 指令再回来     │
                            │  写回 X0 = 返回值                       │
                            │  PC = LR（原 caller 视为函数已返回）   │
                            └────────────────────────────────────────┘
```

---

## vmp-isa

定义 **语义指令集 `VOp`**（74 个，稳定）和 **物理编码 `IsaSpec`**（每次构建按 seed
随机化）。两者解耦让"语义"在 lift / interpret 之间稳定，"字节"则每次构建变样。

### VOp 列表（按编号分段）

| 编号 | 类别 | VOp |
|---|---|---|
| 0 | NOP | Nop |
| 1–6 | 数据传输 | MovR / MovI / Load / Store / Push / Pop |
| 10–24 | ALU | Add / Sub / Mul / UDiv / SDiv / And / Or / Xor / Shl / LShr / AShr / Ror / Neg / Not / CSel |
| 30–31 | 比较 | Cmp / Tst |
| 40–43 | 控制流 | Br / BCond / Call / Ret |
| 50–53 | VM/Host | NativeCall / VExit / VEnter / CallRegion |
| 60–61 | 系统 | Syscall / Trap |
| 70–71 | 反分析 | Junk / Obfuscate |
| 80–91 | FP 标量 | FLoad / FStore / FMovR / FMovFromGpr / FMovToGpr / FAdd / FSub / FMul / FDiv / FCmp / FCvtZS / SCvtF |
| 100–103 | Atomics | AtomicAdd / AtomicSwap / AtomicCas / Barrier |
| 110–112 | NEON 整数向量 | VAdd / VSub / VMul |
| 120–122 | 位运算扩展 | Rbit / Rev / Clz |
| 130–132 | FP 单源 | FNeg / FAbs / FSqrt |
| 140–141 | 带进位 | Adc / Sbc |
| 150 | 条件比较 | Ccmp |
| 160–161 | 高 64 + 间接 | MulH / IndirectBr |
| 170–173 | NEON FP 向量 | VFAdd / VFSub / VFMul / VFDiv |
| 180–182 | NEON 扩展 | VDupG / VDupE / VShlI |
| 200 | Hybrid | NativeExec |

### Instr 字段编码

每条 IR (`vmp_isa::Instr`) 9 个字段：`op / rd / rs / rt / width / cond / imm / variant / lane`。
不是所有字段都用——`Layout` 决定哪些字段写入字节流：

```rust
struct Layout {
    has_rd: bool,         // 1 byte
    has_rs: bool,         // 1 byte
    has_rt: bool,         // 1 byte
    has_width: bool,      // 1 byte（W8/W16/W32/W64）
    has_cond: bool,       // 1 byte（Cond enum 0..15）
    has_lane: bool,       // 1 byte（NEON lane count）
    imm_bytes: u8,        // 0 / 4 / 8 bytes
}
```

opcode 1 byte → 总长 1..16 字节。

### IsaSpec 随机化（每次构建）

`IsaRandomizer::new(seed, dup, encrypt).build()` 产出：
- `op_table: HashMap<VOp, OpEncoding>` —— 每个 VOp 对应 N 个物理 opcode 字节（多态变体）
- `op_reverse: [Option<(VOp, tweak)>; 256]` —— 解释器反查表
- `reg_perm / reg_unperm: [u8; 64]` —— V0..V63 寄存器编号置换
- `stream_key: [u8; 32]` / `stream_iv: [u8; 16]` —— 字节码流加密 key + IV
- `imm_rol: u32` —— 立即数旋转位
- `branch_xor: u32` —— 跳转偏移 XOR mask

**dup（多态 handler）**：同一语义有 N 个不同 opcode 字节。codegen 随机选一个；
解释器查表后还原到统一语义路径。Heavy/Paranoid `dup=3`，Standard `dup=2`，
Light `dup=1`。

**容量**：opcode 池 `1..=255` = 255 字节；74 VOp × 3 dup = 222，留 33 字节冗余。
任何新增 VOp 必须保证 `total_variants ≤ 254`，否则 `IsaRandomizer::build()` panic。

---

## vmp-arch

trait `Lifter::lift(code: &[u8], base: u64) -> LiftedFunction`，输出
`Vec<vmp_isa::Instr>` + `native_to_ir: Vec<usize>`（native PC 步长 4 → IR 索引）。

子模块：

- `arm64::Arm64Lifter` —— 主战场。`arm64/decode.rs` 按 op0 大类分发：
  - `decode_data_imm` —— ADD/SUB imm / MOVZ/MOVN/MOVK / SBFM/UBFM / BFM
  - `decode_branch` —— B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ/RET/BR/BLR
  - `decode_load_store` —— LDR/STR (imm/reg/literal/pre/post/LDP/STP) + LSE atomics + FP load/store
  - `decode_data_reg` —— ADD/SUB reg / Logical reg / DP-2src / DP-3src (MUL/MADDL/MULH) / CSEL family / DP-1src (RBIT/REV/CLZ) / ADC/SBC / CCMP
  - `decode_simd_fp` —— FMOV/FADD/...（标量）+ Advanced SIMD three-same (V/VF) + DUP/SHL imm
- `arm32::Arm32Lifter` —— ARM 模式 32-bit；MOV/ADD/SUB/CMP/LDR/STR/B/BL
- `thumb::ThumbLifter` —— T1 16-bit 子集；T2 32-bit 留 Phase 9
- `x86_64::X86_64Lifter` —— REX.W MOV/ADD/SUB/AND/OR/XOR/CMP/Jcc/PUSH/POP/CALL/JMP/INC/DEC/NOP/INT3/CDQE

### Hybrid mode

`Arm64Lifter::hybrid: bool`（默认 true）。decoder 返回 Err 时：
- `hybrid = true`：emit `VOp::NativeExec(raw_u32)`，让运行时跑原指令
- `hybrid = false`：emit `VOp::Trap`，命中即 VM 退出

CLI `--no-hybrid` 关闭 hybrid。

### Lifter scratch 寄存器

ARM64 X0..X30 → V0..V30；SP → V31；XZR → V63。**lifter scratch 用 V32..V35**，
不与 ARM64 寄存器冲突。**codegen transform pass 用 TMP1..TMP4 = V36..V39**。

---

## vmp-codegen

三个 pass，按顺序跑：

### Pass 1: `resolve_program(funcs: &mut [FunctionRegion]) -> ResolveReport`

把 lifter 输出的 IR 中分支 `imm` 字段（绝对虚拟地址）转成：
- 本 region 内分支 → IR 索引
- 跨 region 调用（BL <另一被保护函数入口>）→ `VOp::CallRegion`，`imm = 目标 region_id`
- 其它（落到非 4 字节对齐 / 不在保护范围内）→ `VOp::Trap`

### Pass 2: `expand_arith(ir: &mut Vec<Instr>, rng, opts)`

混淆膨胀（heavy/paranoid 启用）：
- `Add` → `Neg + Sub`（数学等价）
- `Sub` → `Not + MovI(1) + Add + Add`（二补码恒等）
- `MovI K` → `MovI K1 + MovI K2 + Xor`（K1 ⊕ K2 = K，K1/K2 RNG 决定）
- 不透明谓词：插入 `Mul + Add + Tst` 写标志位但不分支

每条变形维护 `old_index → new_index` 映射，重写所有 Br/BCond/Call 的 imm。

### Pass 3: `CodeGen::encode(ir) -> Vec<u8>`

- 逐 IR 编码，随机选 `variant`（dup 多态 handler）
- 25% 概率插入 junk 序列（6 种哑指令模式）
- 第二遍：根据真实 byte 偏移回填 branch fixup
- 最后：流加密整段（XOR with `effective_iv = stream_iv ^ region_id`）

### Per-region IV salt

不同 region 用不同 IV：`effective_iv[i] = stream_iv[i] ^ (region_id >> (i*8))`
for i ∈ 0..8。即便同一 master IV，不同 region 的 keystream 完全不同——单看一个
region 的字节码无法迁移到别的 region。

---

## vmp-stub

### StubBlob 结构

```rust
struct StubBlob {
    spec: IsaSpec,                  // 物理 ISA 规范
    regions: Vec<StubRegion>,       // 每个保护函数一项
    bytecode_pool: Vec<u8>,         // 所有 region 字节码连续存放（加密）
    entry_region: u32,              // 主入口 region 索引（不一定是 0）
    data_segments: Vec<DataSegment>,// 原 ELF .rodata / .data / .bss 拷贝
}

struct StubRegion {
    patch_addr: u64,                // 原 ELF 中的函数 vaddr
    patch_len: u32,                 // 函数字节数
    bc_offset: u32,                 // 在 bytecode_pool 中的偏移
    bc_len: u32,
}

struct DataSegment {
    vaddr: u64,                     // 原 ELF vaddr
    bytes: Vec<u8>,
    prot: u8,                       // 0x1=R 0x2=W 0x4=X
}
```

### 序列化格式

`pack_blob(&StubBlob) -> Vec<u8>`：

```
"QVMP"        4
version u16   2  (=1)
isa_len u32   4
isa_bytes     isa_len    (IsaSpec 自定义打包)
region_cnt u32  4
region[N]      N * (8+4+4+4)
pool_len u32   4
pool_bytes     pool_len   (字节码池)
entry_region u32  4
ds_count u32   4
data_segments[N]:
    vaddr u64   8
    len   u32   4
    prot  u8    1
    bytes  len
```

`vmp inspect <blob>` 可视化打印。

### dispatch_vm

入口：
```rust
fn dispatch_vm(
    blob: &StubBlob,
    region_id: usize,
    args: &[u64],          // X0..X7
    host: &mut dyn HostBridge,
) -> Result<u64>;
```

流程：
1. 第一次进入：把 `data_segments` 通过 `host.map_data()` 映射到 vaddr（mmap MAP_FIXED）
2. 取 region 的字节码，构造 `Interpreter`
3. 设 `state.regs[31] = stack_top`（VM 栈 64KB）
4. 把 args 写入 V0..V7
5. `interp.run()` —— handler-table dispatch 直到 VExit / Ret 顶层栈空
6. 返回 V0

### LinuxHost

`HostBridge` 实现，覆盖 5 个方法：
- `load(addr, w)` / `store(addr, v, w)` —— 直接 unsafe 解引用
- `native_call(target, args)` —— transmute 函数指针调
- `syscall(no, args)` —— inline asm `svc #0`（aarch64）/ `syscall`（x86_64）
- `map_data(vaddr, bytes, prot)` —— mmap MAP_FIXED + mprotect
- `native_exec(raw, gpr, fpr, nzcv)` —— **hybrid mode 的核心**，详见后文

---

## vmp-rewriter

### ELF rewrite 主流程

`rewrite_elf(loaded, blob, opts) -> (Vec<u8>, RewriteReport)`：

1. 把原 ELF 字节克隆到内存
2. 末尾对齐 0x1000，开始追加新 PT_LOAD segment：
   - 跳板表：每个 region 16 字节（`mov x16, #region_id; brk; nop; b .`）
   - "QVMP" + payload_len + pack_blob(blob)
3. 选新 segment 的 vaddr：找所有 PT_LOAD 中最大 `vaddr+memsz`，向上对齐 0x1000
4. 复制原 phdr 表到文件末尾（因为原位置紧跟 ELF header 没空间），追加新 PT_LOAD entry
5. 改 ELF header：`e_phoff` 指向新 phdr 位置，`e_phnum += 1`
6. 在每个 region 的 `patch_addr` 写一条 `B <trampoline_vaddr>`（imm26 偏移）

### Armor pass（rewrite 之后）

`apply_armor(elf, payload_offset, opts) -> ArmorReport`：

- `strip_symtab` —— `.strtab` 的可读字节置 0（除首字节 NULL）
- `strip_shstrtab` —— `.shstrtab` 同样
- `xor_payload` —— 用 ELF header[0..16] + e_entry + payload_offset 派生 32 字节 key，
  FNV-1a keystream XOR payload 字节
- `hash_imports` —— `.dynsym` 中 STT_FUNC + UND 符号名替换为 `h_xxxxxxxx`，
  原名写到 imports.tbl

`derive_payload_key` / `apply_payload_keystream` 是 pub 函数，runtime 端共享同一逻辑。

### `append_integrity_hash(elf) -> u64`

计算所有 PT_LOAD r-x 段（filesz + memsz 含 BSS 零填充）的 SHA-256，写到 ELF 末尾
QHSH magic 块。runtime `dl_iterate_phdr` 重算比对。

### `apply_page_crypto(elf, off, vaddr, size, seed) -> (qpgt_off, page_count)`

把追加的新 segment 按 4KB 页 XOR 加密（每页独立 8 字节 key），写 QPGT 表到 ELF 末尾。
runtime 加载时 mprotect PROT_NONE，SIGSEGV handler 命中时按页 lazy decrypt → R+X →
CPU 重跑指令。

### AR / PE / APK

- `ar_rewriter::rewrite_archive` —— 把 blob 作为新 ar 成员（`qvmp_blob.bin`）追加；
  保留 System V / GNU header + 偶数对齐
- `pe_writer::rewrite_pe` —— 追加 `.qvmp` section（PE32 / PE32+ 共用代码路径）；
  按 `loaded.arch` 分发跳板（ARM64 BRK / x86 INT3）
- `apk::list_libs / pack_one_lib / runtime_target_path` —— APK 解包目录扫描 +
  批量 rewrite 编排（不引 zip 依赖；用户自行 `unzip` / `apksigner`）

---

## vmp-runtime

cdylib + bin 双输出：`crate-type = ["rlib", "cdylib"]`。

### 入口

| 平台 | 入口 |
|---|---|
| Android | `JNI_OnLoad(JavaVM*, void*)` |
| Linux | `.init_array` ctor 自动触发 |
| Windows | `DllMain(hinst, DLL_PROCESS_ATTACH, _)` |
| C ABI | `qvmp_dispatch(region_id, args, nargs)` |

`qvmp_runtime_init`：
1. 安装 SIGTRAP handler
2. 扫所有已加载模块找 QVMP / QIMP / QPGT magic
3. 解 imports.tbl 中的 hash → dlsym 真实地址
4. 跑 `vmp_protect::run_checks(flags)`，命中威胁触发 `policy::on_threat`

### sig::sigtrap_handler（aarch64 only）

BRK 跳板触发 SIGTRAP 后：
1. 从 `info->si_addr` 拿 PC（即 BRK 指令地址）
2. 读 `pc-4` 的 `mov x16, #imm16` 拿 region_id
3. 启发式扫 ucontext 1024 字节找 `mcontext.pc == fault_addr` 的位置 → 反推 sigcontext
   起点（`mc_pc_off - 264`）
4. 从 sigcontext 取 X0..X7 GPR 参数
5. 调 `dispatch_region(region_id, &gpr)` → 拿返回值
6. 写回 X0；设 `pc = lr`（直接跳到 caller，等价 `ret`）

### resolver

- `IMPORT_TABLE: HashMap<u64, u64>` —— djb2 hash → 真实 dlsym 地址
- `THREAT_DETECTED: AtomicBool` —— 反 * 命中 → 后续 dispatch 返回 0xDEADC0DE
- `DISPATCH_LOCK: Mutex<()>` —— 多线程 caller 串行化（Android JNI 多线程并发安全）
- `RebasedLinuxHost` —— PIE 地址处理：`< 4GB` 的地址加 `dlpi_addr`

### page_crypto

- `enable_page_crypto(table)` —— mprotect PROT_NONE 所有页 + 装 SIGSEGV handler
- `sigsegv_handler` —— 页表查 vaddr → mprotect R+W → XOR 解密 → mprotect R+X
- 线程本地 `IN_HANDLER` 计数器 + `SA_NODEFER` 防递归 fault

---

## vmp-protect

每项独立 `.rs` 文件，零交叉依赖，可单独 cfg(target_os) gate。

`ProtectFlags` 16 位 bitflag → `from_env()` 读 `QVMP_FLAGS` env 关键字
（`anti_debug+anti_hook+...` / `paranoid` / `none`）。

`run_checks(flags, expected_hash) -> Verdict` 跑全部启用项，结论存 `Verdict`：

```rust
struct Verdict {
    debugger_attached: bool,
    debugger_evidence: Vec<&'static str>,
    dump_in_progress: bool,
    dump_evidence: Vec<&'static str>,
    hooks_present: bool,
    hook_evidence: Vec<&'static str>,
    ida_attached: bool,
    ida_evidence: Vec<&'static str>,
    vm_or_emulator: bool,
    vm_evidence: Vec<&'static str>,
    injection_present: bool,
    inject_evidence: Vec<&'static str>,
    hwbp_count: u32,
    integrity_failed: bool,
}
```

`policy::on_threat` 按 `QVMP_RESPONSE` env 决定：
- `silent` —— 仅 log
- `corrupt`（默认）—— 设 THREAT_DETECTED + 跑 `syscall_noise()`（mmap/munmap/getpid 噪声）
- `abort` —— libc abort
- `crash_random` —— 写 0xDEADBEEF 触发 SIGSEGV，看起来像普通 bug

---

## Magic blobs

加固后 ELF 末尾追加多个 magic 块。**8 字节对齐**。runtime 扫描时按 magic 字串识别。

### QVMP（必有）

```
"QVMP"        4
payload_len   4    (u32 LE)
pack_blob()   payload_len    （含可选 xor_payload 加密）
```

### QIMP（可选 — `--hash-imports`）

```
"QIMP"        4
version u16   2  (=1)
count u32     4
entry[count]:
    hash u64   8     (djb2 of original name)
    name_len u16  2
    name      name_len
```

### QHSH（可选 — `append_integrity_hash`）

```
"QHSH"        4
version u16   2  (=1)
sha256[32]    32
```

runtime 启动时 `dl_iterate_phdr` 重算 .text SHA-256，与 QHSH 比对。

### QPGT（可选 — `apply_page_crypto`）

```
"QPGT"        4
version u16   2  (=1)
count u32     4
entry[count]:
    vaddr u64  8     (4KB 对齐)
    key   u64  8     (8 字节 XOR keystream)
```

---

## Hybrid mode

### 设计目标

ARM64 全集 1500+ 指令，lifter 不可能一开始全覆盖。Hybrid mode 让 **lifter 漏的
指令也能保护**。

### 字节码层：VOp::NativeExec

```
opcode 1 byte
imm32  4 bytes  (raw ARM 指令字节)
```

总 5 字节。任何 4 字节 ARM64 指令都能塞进来。

### 解释器：

```rust
VOp::NativeExec => {
    let raw = instr.imm as u32;
    let mut gpr = [0u64; 31];
    for i in 0..31 { gpr[i] = self.state.regs[i]; }
    let mut fpr = self.state.fregs;
    let mut nzcv = pack_nzcv(&self.state.flags);
    self.host.native_exec(raw, &mut gpr, &mut fpr, &mut nzcv)?;
    // 拷回 VM state
}
```

### LinuxHost::native_exec（aarch64 only）

- lazy mmap 64KB RWX 页
- 安装 thunk 模板：

```asm
; x0 = &SaveArea
mov  x16, x0          ; 保存 SaveArea 指针到 x16（不会被 raw_instr clobber）
ldr  w17, [x16, #0x300]
msr  nzcv, x17
ldp  x0, x1, [x16, #0x00]
ldp  x2, x3, [x16, #0x10]
... (15 条 ldp 加载 X0..X29)
ldr  x30, [x16, #0xF0]

; ===== 偏移 0x180：RAW_INSTR 占位 =====
nop                   ; 调用方 patch raw_instr 进来

; 反向保存
mrs  x17, nzcv
str  w17, [x16, #0x300]
stp  x0, x1, [x16, #0x00]
... (15 条 stp 保存 X0..X29)
str  x30, [x16, #0xF0]
ret
```

- 每次调用前 patch raw_instr 进偏移 0x180，加 `dc cvau / ic ivau / dsb ish / isb`
  同步 D/I cache（自修改代码必须）
- 调用 thunk，X0 = &SaveArea；返回后 SaveArea 已含执行后状态

### 当前限制

- **NEON V0..V31 不在 thunk 中保存恢复**（Phase 9 todo）。imgui 实测受影响小，
  因为 NEON 多数已被 lifter 解码；少量走 hybrid 的非 NEON 指令不影响 V regs
- 不能跑 PC-relative load / branch / svc —— lifter 必须解码这些
- 不能改 SP（X31 不在 SaveArea，hybrid 不允许操作栈指针）

---

## PIE 地址处理

lifter 把"原 ELF vaddr"baked 进 blob（ADRP / LDR-literal / 全局变量访问）。
**cdylib 模式下** .so 加载在 `dlpi_addr` 起的随机位置 → host.load(0x12345) 读 garbage。

`RebasedLinuxHost`（在 `vmp-runtime/src/resolver.rs`）：

```rust
fn rebase_if_relative(addr: u64, base: u64) -> u64 {
    // < 4GB 视作模块内 PIE 相对（lifter 写出的 ADRP 结果）；否则视作绝对
    // 64-bit Linux ASLR 模块基址 ≥ 0x55_5555_5555 ≫ 原 ELF vaddr ≤ ~10MB
    if addr < 0x1_0000_0000 { base.wrapping_add(addr) } else { addr }
}
```

`map_data` 在 cdylib 模式变 noop —— 数据段已被 dl_open 映射。

**完整方案**（Phase 9+）：lifter 在 emit ADRP/LDR-literal 时插标记，让 codegen
emit 一条 `VOp::ModuleBase`（占位 8 字节 imm，runtime 替换成真实 dlpi_addr）。

---

## 调试 / 排错

### 加固后崩了

1. **看 logcat / tombstones**：`adb logcat -d | tail -200`、`/data/tombstones/`
2. **找触发的 region_id**：tombstone 的 PC 在 trampoline 段（0x2ab000+）落点 ÷ 16 = region_id；
   protect.log 第 region_id 行就是函数入口
3. **怀疑 lifter 漏指令**：临时改用 `--no-hybrid` + `--skip-trap-pct 50`，
   把高 Trap 函数都剥离，降低风险面
4. **怀疑 PIE 翻译错**：临时关 `--xor-payload` 让 blob 解析容易，看 `vmp inspect <blob>`

### 加固后某函数行为变了

1. `vmp protect --only <fn> -o /tmp/single.qvmp` 单函数 protect
2. `vmp lift --hex <bytes>` 看 IR 序列对不对
3. `vmp run /tmp/single.qvmp --region 0 --arg ...` 在 host 模拟跑，对比 native 行为

### 性能太慢

- 每条 VM 指令 ~50 ns；NativeExec ~150 ns
- 用 `--only` 只保护关键函数（license 校验 / 解密内核），其它保留 native
- 关 hybrid（`--no-hybrid`）：lift 漏的函数不保护反而更快

### 想知道某个 .so 的"加固上限"

```
bash samples/realworld/harden_so.sh path/to.so --level heavy 2>&1 | grep "保护完成"
```
显示 region 数 / 跳过数 / 字节码池大小。

---

## 接下来读什么

- 接手维护 → [docs/MAINTAINERS.md](MAINTAINERS.md)
- 决定下一步做什么 → [docs/ROADMAP.md](ROADMAP.md)
- 想看 APK 加壳完整流程 → [docs/APK_PACKING.md](APK_PACKING.md)
- 想了解 Phase 1–8 怎么走过来的 → [CHANGELOG.md](../CHANGELOG.md)
