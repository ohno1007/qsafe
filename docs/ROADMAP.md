# Roadmap

按"实战影响 / 工程量"排。✅ 已完成；🔄 进行中；📋 计划；❓ 调研中。

---

## P0 — 阻塞生产部署的事

| 项 | 状态 | 工程量 | 备注 |
|---|---|---|---|
| NDK aarch64-linux-android 端到端真机验证 | 📋 | 0.5d | 容器拉不到 NDK；用户本地跑 `samples/realworld/build_apk.sh` 一遍验证 |
| Hybrid thunk 加 V0..V31 寄存器保存恢复 | 📋 | 1d | 当前只保 GPR + NZCV。用 NEON 加密的 SDK 走 hybrid 时 V regs 会丢 |
| `.eh_frame` unwind 表跳板感知 | 📋 | 2d | 跳板覆盖原 .text 第 1 条指令，但 unwind FDE 仍指向原 prologue → 异常展开错位 |
| BTI rewriter 自动启用 | 📋 | 0.5d | `build_brk_trampoline_bti` 已实现但默认未用。Android 14 + BLR Xn 跳进跳板首条 `mov x16,#imm` 会 SIGILL |

---

## P1 — 强化保护强度

| 项 | 状态 | 工程量 | 备注 |
|---|---|---|---|
| Page-crypto rewriter 端配套（QPGT 写入） | ✅ Phase 7 | — | runtime 端就绪，rewriter `apply_page_crypto` 已存在；CLI flag 待加 |
| HW BP 占坑 fork helper 完整实现 | ✅ Phase 7 | — | `fork + ptrace SEIZE + SETREGSET NT_ARM_HW_BREAK` 已写 |
| Corrupt 响应深化（VM 级毒化） | 🔄 Phase 7 | 1d | 当前返回 0xDEADC0DE + syscall 噪声；可加 V0..V7 / flags 写 0xDEAD 模式让攻击者多走几跳才发现 |
| Anti-frida 加 `gum-rpc` 端口（27043）+ 扫 lib name 后缀 | 📋 | 0.2d | 当前只查 27042 + libfrida-agent；frida-gadget 模式漏 |
| Anti-debug 加 `prctl(PR_GET_DUMPABLE)` 反查（自查 dumpable 是否被攻击者重置） | 📋 | 0.1d | 互证机制，attacker 关 anti-debug 必须连这个一起关 |
| Integrity hash 自动嵌入（rewriter 默认开） | 📋 | 0.2d | 当前需手动 `append_integrity_hash`；改默认开 |

---

## P2 — 指令覆盖（实测命中率提升）

| 项 | 状态 | 工程量 | 备注 |
|---|---|---|---|
| ARM64 NEON LD1/ST1 多结构 | 📋 | 0.5d | `LD1 {V0.4S, V1.4S}, [X0]` 等。imgui 类应用频率中等 |
| ARM64 NEON TBL/TBX 表查找 | 📋 | 0.3d | shuffle / swizzle 用，加密哈希算法 |
| ARM64 NEON FCMEQ/FCMGT/FCMGE 向量比较 | 📋 | 0.3d | 物理引擎 / 渲染管线 |
| ARM64 NEON ABS/NEG 标量 SIMD 解码（hybrid 已兜底） | 📋 | 0.2d | 不是阻塞，但拆解后比 hybrid 快 5× |
| ARM64 CRC32 / CRC32C 指令族 | 📋 | 0.5d | 哈希算法 / TLS 校验 |
| ARM64 AES / SHA crypto 扩展 | ❓ | 1d | `AESE / AESD / SHA1H / SHA256H` 等 11 条；需要 lifter + 解释器双端实现 |
| ARM64 SVE / SVE2 | ❓ | 5d | 大 / 不紧急；现代 server / 高端 mobile 才有 |
| ARMv7 Thumb T2 32-bit 子集 | 📋 | 2d | Android 低端机仍跑 armeabi-v7a；当前 T1 子集不够 |
| x86_64 接 `iced-x86` | ❓ | 2d | 完整 x86_64 lifter；引依赖 ~150KB |

---

## P3 — 平台 / 格式扩展

| 项 | 状态 | 工程量 | 备注 |
|---|---|---|---|
| Mach-O 加固（macOS / iOS） | 📋 | 3d | vmp-loader 加 mach-o parse，rewriter 加 LC_SEGMENT 追加；codesign 兼容 |
| Windows ARM64 PE | 📋 | 2d | pe_writer 已有路径；需测 ARM64 + ARM64EC |
| iOS dyld_chained_fixups 兼容 | ❓ | 1d | iOS 13+ 用 chained fixups 替代 LC_DYSYMTAB |
| .a 静态库 .o 内 lift（跨 .o 重定位） | 📋 | 3d | 当前只追加 archive 成员；逐 .o lift 需要 `R_AARCH64_CALL26` 重定位处理 |
| DEX 加壳 | ❌ | — | 不在本项目范围；属于 Java 字节码加壳工具领域 |

---

## P4 — 长尾 / 调研

| 项 | 状态 | 工程量 | 备注 |
|---|---|---|---|
| 多线程 VmState 池（取代 DISPATCH_LOCK） | 📋 | 1.5d | 当前 `Mutex<()>` 串行化；高并发场景 (Android JNI 多线程) 性能瓶颈 |
| Lifter PIE-aware 标记（`VOp::ModuleBase`） | 📋 | 1d | 替代当前 4GB 启发式；ADRP 结果走专门 VOp |
| Threaded code / computed-goto interpreter | ❓ | 3d | 性能 50× 慢 → ~10× 慢；需 nightly Rust + LLVM tail call |
| WASM target（VM 跑在浏览器） | ❓ | — | 调研价值 |
| JIT cache（同 region 多次调用复用 IR 解码） | ❓ | 2d | 解释器现在每次重新解 ISA；缓存可省 20-30% 时间 |
| Anti-* 检测项的不透明编码（自身 binary 里也藏） | 📋 | 1d | 现在 anti_emulator 的字符串 "ro.kernel.qemu" 在 .rodata 暴露，attacker grep 一搜就知道我们查啥 |
| GitHub Actions CI | 📋 | 0.5d | host 端跑 21 项 unit + 集成测试 |

---

## 已知限制（接受 / 不修）

| 项 | 原因 |
|---|---|
| `vmp run` 模拟执行不支持 syscall | 设计：模拟环境无 OS；syscall 走 NullHost 返 0 |
| ELF rewrite 把整个 phdr 表挪到末尾 | 兼容性 trade-off；某些极旧 linker 会拒绝（但 Android 5+ 全过） |
| 对 ET_REL (.o relocatable) 不直接 protect | 需要 R_AARCH64_* 重定位处理；当前走 `ar_rewriter` 整库追加路径 |
| paranoid 还是 dup=3 不是 dup=8 | dup=8 × 74 VOp = 592 > 255 cap；paranoid 的强度由 anti_* 全开 + HWBP 占坑保证 |
| dlsym 解 imports 表需要保留 dlsym 自身原名 | bootstrap 死锁；PRESERVE_NAMES 列表里 |

---

## 历史 Phase（已完成）

详见 [CHANGELOG.md](../CHANGELOG.md)：

| Phase | 主题 | 关键交付 |
|---|---|---|
| 1–3 | ARM64 lifter + 解释器 + 基础 ELF rewrite | `vmp-isa / arch / interpreter / stub / rewriter` 雏形 |
| 4 | 多目标产出基础 | imports.tbl + arith expand + NEON int + cdylib runtime + .a / PE / APK 编排 + ARMv7 / x86_64 MVP |
| 5 | 反 * 模块化 + 按页加解密 | 9 个 anti-* 模块 + ProtectFlags + page_crypto runtime + 多线程锁 + ARM64 指令补完 |
| 6 | 反 hook 关键路径硬化 | MulH / IndirectBr / VFAdd 系列 / LDR sign-extend / LDP-STP FP / BTI trampoline / Thumb T1 / x86_64 扩展 / 集成测试 |
| 7 | 真实环境鲁棒性 | `--skip-trap-pct` / `harden_so.sh` / page-crypto rewriter / HW BP fork helper / corrupt 深化 / PIE 地址 / RebasedLinuxHost |
| 7.1 | stripped ELF 函数边界 | `.eh_frame_hdr` mining 让 stripped 二进制能保护 |
| 8 | Hybrid 混合执行 | `VOp::NativeExec` + RWX thunk + NEON DUP/SHL —— 99.97% 函数保护率 |

---

## 决策记录

### 为什么不接 `iced-x86`

引依赖 ~150KB，对 ARM64-first 项目体积影响大。当前 x86_64 MVP 子集足够 demo；
真要 ship Windows / Linux x86_64 加固再接，单独 feature flag。

### 为什么 hybrid mode 默认开

99% vs 95% 函数保护率的差异在反破解视角是质变的——攻击者再也找不到"未受保护的
函数列表"了。性能代价（每条 NativeExec ~150ns × 几万条）总开销几 ms 可忽略。

### 为什么 corrupt 是默认响应

`abort` 让攻击者立刻知道触发了反 *，下次就绕过；`silent` 没威慑；`crash_random`
看起来像 bug 但 dev 调试自己代码会迷惑。`corrupt`（返回错值 + syscall 噪声）
让攻击者**继续往下走**，等他发现"奇怪输出"时已经浪费了大量时间。
