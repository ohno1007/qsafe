qvmp_test.zip — v32 PIE ADRP/ADR/LDR-literal 加 load_bias 重定位
==================================================================

v31 抓到 root cause:
  region 124 在 0x190058，前几条:
    adrp x0, 0x26000        ← lifter 把 target 算成 ELF vaddr 0x26000
    add  x0, x0, #0xbf9     ← x0 = 0x26bf9
    blr  x20

  VM 算出 x0 = 0x26bf9 直接传给 BLR. 但 binary 是 PIE，
  运行时 ELF 加载在 dlpi_addr = 0x754xxxxxxx, 真实地址应该是
  dlpi_addr + 0x26bf9. native 函数把 0x26bf9 当字符串指针 deref → SEGV.

  这不是 region 124 一个的问题, 而是 lifter 对所有 PIE 二进制的 ADRP /
  ADR / LDR(literal) 都漏译了 load_bias 重定位.

v32 修:

1. vmp-arch/src/arm64/decode.rs
   - 新增 `LOAD_BIAS_REG = 62`
   - ADRP/ADR/LDR-literal 不再编成 `MovI rd, target`, 而是
       MovI SCRATCH, target           (vaddr offset)
       Add  rd, V62, SCRATCH          (rd = load_bias + offset)
     LDR-literal 多一条 Load.

2. vmp-interpreter/src/lib.rs
   - 新增 `pub static MAIN_EXEC_LOAD_BIAS: AtomicU64`
   - Interpreter::run() 起始 `state.regs[62] = MAIN_EXEC_LOAD_BIAS.load()`
   - CLI 模拟器路径 load_bias=0, 行为不变.

3. vmp-soruntime/src/lib.rs
   - qvmp_init 找到 QVMP magic 时, 把 dlpi_addr 写进 MAIN_EXEC_LOAD_BIAS.

字节码尺寸涨了一点 (195892 → 197799 bytes, +1%), 因为每条 ADRP 从 1 条
VOp 变成 2 条.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/
  2. 32_pie_reloc.hardened → 任意位置
  3. MT 双击

期望:
  [qvmp] rodata decrypted in place
  [qvmp] blob loaded, SIGTRAP+SIGSEGV handlers installed
  [qvmp] dispatching region=N (大量)
  [qvmp] vm: BLR xN target=0x... x0=0x754... x1=...      (高地址了，正常的指针)
  <ImGui 窗口>

如果还挂:
  - BLR x0 还是 0x26bf9 范围 → 我哪里写错了, 把日志粘回来
  - BLR x0 看着像高地址 (0x7...) 但还 SEGV → 别的 lifter gap, 把整段
    [qvmp] 日志 + SIGSEGV 4 行粘回来

MD5:
  32_pie_reloc.hardened  8735bfa405924d8db1ecd8169176b68a
  libqvmp_runtime.so     ae803cacd1d87aaa0eb1be3687e3ad41
