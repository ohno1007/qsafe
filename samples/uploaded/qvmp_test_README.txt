qvmp_test.zip — v30 native_call 鲁棒化 + SIGSEGV 抓诊断
============================================================

v29 反馈:
  [qvmp] dispatching region=124
  Segmentation fault  ← 静默 SEGV

意思是 native_call 拿到了 target，但 target 指向不合法/未映射的代码区，
直接 jump 过去就 SEGV。"兼容写好点" 这一版做三层防御:

1. **native_call 校验 target** (crates/vmp-stub/src/linux.rs)
   - target == 0 → "空指针"
   - target & 3 != 0 → "未对齐"
   - target < 0x1000 → "落在低地址"
   - 不在 /proc/self/maps 任何 r-x 段内 → "不在可执行映射"
   首次 miss 时刷新一次 cache（应对 dlopen 之后新映射的库）。

2. **F8 全 8 参数** (之前最多 F6，丢了 args[6..8])
   ARM64 AAPCS64 整数参数 x0..x7，全传过去更兼容。

3. **interpreter 包装错误带 rd** (crates/vmp-interpreter/src/lib.rs)
   原来只报 "空指针"，现在打成 "BLR x16 target=0x...: <原因>"，
   一眼能知道哪条 BLR、用的哪个寄存器、寄存器里装的什么。

4. **cdylib 装 SIGSEGV/SIGBUS handler** (crates/vmp-soruntime/src/lib.rs)
   SEGV 不再静默。会先打 4 行:
     [qvmp] SIGSEGV sig=11
     [qvmp] SIGSEGV pc=<崩溃指令地址>
     [qvmp] SIGSEGV addr=<触发的内存地址>
     [qvmp] SIGSEGV lr=<返回地址>
   再 SIG_DFL + return 让内核终结 (exit 139)。
   这样不管 SEGV 是 VM 内部还是 native_call 跳到坏地址，都有迹可循。

DT_NEEDED: /data/local/tmp/libqvmp_runtime.so（同 v28/v29）
cascade drop: 同 v28（534/867 保护）

部署:
  1. libqvmp_runtime.so → /data/local/tmp/
  2. 30_segv_diag.hardened → 任意位置
  3. MT 双击

可能出现的几种结果（粘回来 + 上下文）:
  - VM ERR ... BLR xN target=0xXX: ... → 把整行粘。target 是 0 / 低地址 /
    未对齐 / 不在 exec 映射，提示 lifter 漏了前置的 ADRP/LDR 翻译。
  - SIGSEGV pc=0x... addr=0x... → pc 是崩溃 native 函数的指令；addr 是
    它访问的非法地址。把 4 行 SIGSEGV 全粘。
  - 出 ImGui → 万事大吉。

MD5:
  30_segv_diag.hardened  d5772ccabd2becae7c1d9edc5f5eb71a
  libqvmp_runtime.so     89e08e5da5253ecdf4bec8474e38172b
