# APK 加壳路径

本文描述如何把 Qsafe VMP 接到 Android APK 加壳流程上。Qsafe VMP 本身是**纯 native 层**的工具（处理 ARM64 ELF / .so / .a），APK 里需要 VMP 保护的目标主要是 `lib/arm64-v8a/*.so` 这些 native 库（含 NDK 编出的 JNI 库、商业 SDK 等）。

## 整体流程

```
APK (zip)
 ├── classes.dex          ← Java/Kotlin 字节码（不在 VMP 范围；要保护需用 DEX 加壳）
 ├── lib/arm64-v8a/
 │     └── liblol.so      ← VMP 处理目标
 ├── lib/armeabi-v7a/...  ← 32-bit ARM；需要 32-bit lifter (Phase 3 之后扩展)
 ├── lib/x86_64/...       ← 需要 x86_64 lifter (vmp-arch::x86_64 模块当前是 stub)
 ├── res/...
 ├── AndroidManifest.xml
 └── META-INF/...         ← 签名信息

加壳步骤:
1. 解 APK (= unzip)
2. 对每个 lib/<abi>/*.so 跑 vmp protect → .qvmp blob
3. 跑 vmp rewrite → 修改后的 .so（嵌 blob + 跳板）
4. 把修改后的 .so 写回 APK 同名位置
5. 删 META-INF/ 下旧签名
6. 用 apksigner / jarsigner 重新签名
7. zipalign 对齐
```

## 当前 Qsafe VMP 直接覆盖的部分

- ✅ `vmp protect <so>` 对 `arm64-v8a` 的 `.so` 输出 `.qvmp` blob
- ✅ `vmp rewrite <so> <blob> -o new.so` 把 blob 嵌入 .so + 修改函数入口写跳板
- ✅ `vmp ar-list <staticlib.a>` 列出静态库内 .o 成员（接 batch protect 准备）
- ⚠️ **运行时 dispatcher**：当前跳板用 `BRK #0x5156|region_id` 触发 SIGTRAP；
  生产环境需要在 APK 里附一个 LD_PRELOAD .so 注册 SIGTRAP handler，handler 读
  `siginfo->si_addr` 找到 region_id，调用嵌入的 dispatch_vm。这一步现有
  `vmp-runtime` 改造为 cdylib + 注入 `JNI_OnLoad` 即可（详见下节"运行时 dispatcher"）。
- ❌ **DEX 加壳**：classes.dex 的 Java 字节码不在 Qsafe VMP 处理范围。

## 运行时 dispatcher 设计要点

把 `vmp-runtime` 改造成 cdylib，在 APK 里以 `libqvmp_runtime.so` 形式分发：

```toml
# crates/vmp-runtime/Cargo.toml
[lib]
name = "qvmp_runtime"
crate-type = ["cdylib"]
```

`lib.rs` 里实现：

```rust
// 1) JNI_OnLoad: 注册 SIGTRAP handler；找到本进程已加载的所有 .so，
//    读各自 `.qvmp_payload` segment（vmp-rewriter 写的 magic = "QVMP"），
//    建立 vaddr → blob 的全局表
#[no_mangle]
pub extern "C" fn JNI_OnLoad(_vm: *mut c_void, _: *mut c_void) -> i32 {
    install_sigtrap_handler();
    scan_loaded_qvmp_payloads();
    // JNI_VERSION_1_6
    0x0001_0006
}

// 2) SIGTRAP handler: si_addr 指向 BRK 指令；读取 +4 偏移找到 mov x16,#region_id；
//    然后从对应 .so 的 blob 找到 region 字节码，跑 dispatch_vm，
//    把返回值写回原寄存器，跳过 BRK 指令继续执行
extern "C" fn sigtrap_handler(sig: i32, info: *mut siginfo_t, ctx: *mut c_void) {
    let pc = (*info).si_addr as u64;
    // 解 region_id：(pc - 4) 处是 mov x16, #imm（MOVZ X16），imm 在 bits 20:5
    let mov_inst = unsafe { *((pc - 4) as *const u32) };
    let region_id = ((mov_inst >> 5) & 0xFFFF) as u64;
    let blob = blob_for_pc(pc).expect("找不到 blob");
    let mut host = LinuxHost::new();
    let mut args = collect_args_from_ctx(ctx); // X0..X7
    let ret = vmp_stub::dispatch_vm(blob, region_id as usize, &args, &mut host).unwrap();
    set_x0_in_ctx(ctx, ret);
    advance_pc_past_brk_and_orig_func(ctx); // 直接 ret-from-handler 让原函数当作执行完
}
```

打包到 APK：
- `lib/arm64-v8a/libqvmp_runtime.so` —— Qsafe runtime
- `lib/arm64-v8a/<your_lib>.so` —— `vmp rewrite` 后的版本
- 修改 AndroidManifest.xml 让 `libqvmp_runtime.so` 优先加载（或在 Java 里
  `System.loadLibrary("qvmp_runtime")` 提前于业务库加载）

## 已知限制

- **PIE / ASLR**：Android 6+ 强制 PIE。我们的跳板用相对 B（imm26 ±128MB）
  跳到新 segment；新 segment 在 `vmp rewrite` 时紧贴原 .text，PIE 重定位不影响
  相对偏移。✅ 已验证。
- **Read-only .text**：Linux mmap PT_LOAD 段权限决定。原 .text 是 R+X。我们直接
  写文件字节，等于在装载之前修改，OS 加载后 .text 仍是 R+X，写跳板不需要 mprotect。
- **MTE / PAC**：Android 14+ 在某些 ABI 启用 PAC 指针签名；BRK 不影响，但跳到
  其它代码段时需要保证目标地址签名兼容（一般 BRK→handler 由 kernel 处理不涉及 PAC）。
- **签名校验**：很多商业 APK 在 native 层做 self-checksum；rewrite 改了 .text 后
  这些校验会失败。Phase 4 可以加一个 detector，提示用户 disable / 替换这些 check。

## 32-bit / x86 / 其它 ABI

`lib/armeabi-v7a/` 32-bit ARM：需要 32-bit lifter（Qsafe 当前没实现，等 Phase 4）。
`lib/x86_64/`：vmp-arch 中已预留 x86_64 lifter 接口，需补完成。
`lib/x86/`：同样，需要 32-bit x86 lifter。

短期建议：先只加固 arm64-v8a/.so（覆盖 95% 国内 Android 设备），其它 ABI 退化为
原 .so，APK 在低端机上仍可运行只是不被保护。

## DEX 加壳

DEX/Java 加壳是另外的领域（关键字：dex2dex、ProGuard、CodeGuard、Allatori 等）。
Qsafe VMP 不直接处理 DEX，但可以：
- JNI 入口函数走 VMP（`Java_*` 是 native 函数，是 VMP 的天然候选）
- DEX 加壳工具调用 Qsafe VMP 处理它们生成的 native 解码 stub
