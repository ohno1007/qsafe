qvmp_test.zip — diagnostic v9 (e_entry hijack instead of INIT_ARRAY)
====================================================================

v8 结果决定性: dlopen 在主 exec 的 INIT_ARRAY 上下文调用就 abort 134
"stack corruption detected"，跟参数无关。dlopen NULL / "libc.so" 都 abort。

定位到根本：bionic 在主 exec INIT_ARRAY 期间某些状态没准备好，dlopen
会触发栈金丝雀检测。要换个时机调 dlopen。

新方案: **e_entry 劫持**

  改 ELF header 的 e_entry，让 bootstrap 在 _start 之前跑。
  
  调用顺序:
    1. kernel exec → linker64
    2. linker maps 所有 .so 依赖 (libc/libdl/libEGL...)
    3. linker 跑 NEEDED libs 的 INIT_ARRAY (libc 初始化)
    4. linker 跳到 main exec 的 e_entry  ← 改成 我们的 shim
    5. shim: bl bootstrap (这里 dlopen 是安全的)
    6. shim: b orig_e_entry → _start
    7. _start → __libc_init → 跑主 exec INIT_ARRAY
    8. INIT_ARRAY 调到保护函数 → BRK → cdylib handler 接住

新增两个变体测试:

  12_e_entry.hardened
    e_entry hijack + 无 armor。
    bootstrap 跑 → dlopen cdylib (这次不在 INIT_ARRAY 里了，应该 OK)
    cdylib qvmp_init 试解密 payload (但因为 --xor-payload false
      → 实际上 payload 没加密，cdylib 异或得到乱码 → unpack 失败
      → BLOB 不设 → SIGTRAP handler 不装)
    然后 _start 跑 INIT_ARRAY 到保护函数 → BRK → 没 handler → Trap 133
    预期: Trap 133 (跟 4_onlytramp 一样) — 证明 e_entry hijack 正常，
          cdylib 也能成功 dlopen 出来 (没再 abort)

  13_full_e_entry.hardened
    e_entry hijack + 全 armor。
    bootstrap → dlopen cdylib → cdylib decrypts payload (这次真有加密)
      → unpack OK → 装 SIGTRAP handler
    _start 跑 INIT_ARRAY → 保护函数 → BRK → handler dispatch → 解释器跑
    → ImGui GUI 应该起来
    预期: 跑通 GUI

只跑这俩。挂了原样发输出 (特别是 [qvmp] log 行)。

MD5:
  1daf93c973f00fcbcf5302e324a924f9  12_e_entry.hardened
  d4438f542b885c3b26965d0081648466  13_full_e_entry.hardened
