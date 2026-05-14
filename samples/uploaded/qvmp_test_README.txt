qvmp_test.zip — v29 修 NativeCall 读 regs[rd] 不是 imm
========================================================

v28 反馈:
  [qvmp] dispatching region=124
  [qvmp] VM ERR region=124 err=Eb2:E:LinuxHost.native_call: 空指针

bug 位置 crates/vmp-interpreter/src/lib.rs:175-182:
  arm64 decode 把 `BLR Rn` (间接函数调用) 编成
    `Instr { op: VOp::NativeCall, rd: Rn, ..Default::default() }`
  rd 写的是源寄存器号. 但 interpreter 读的是 instr.imm:
    let target_ptr = instr.imm as u64;    // = 0, 永远空
  应该读 self.state.regs[instr.rd as usize] —— 运行时寄存器里的函数指针.

v29 改:
  let target_ptr = self.state.regs[instr.rd as usize];

这个 bug 影响所有通过函数指针走的间接调用 (vtable, callback, function ptr
变量). ImGui / C++ 重 vtable 早晚撞.

DT_NEEDED 还是绝对 /data/local/tmp/libqvmp_runtime.so. cascade drop 还是
丢 333 个 region. 保护 534 个.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/
  2. 29_native_target.hardened → 任意位置
  3. MT 双击

期望:
  [qvmp] rodata decrypted in place
  [qvmp] blob loaded, SIGTRAP handler installed
  [qvmp] dispatching region=N (多次)
  <ImGui 窗口>

如果还挂:
  - VM ERR 把 err= 完整粘
  - SEGV 把最后一个 dispatching region=N 的 N 粘

MD5:
  29_native_target.hardened  d5772ccabd2becae7c1d9edc5f5eb71a
  libqvmp_runtime.so         7c85e6935709317e9472f869599de40f
