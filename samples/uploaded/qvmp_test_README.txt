qvmp_test.zip — diagnostic v6
=============================

文件名带数字前缀，方便定位。从 1 跑到 6。

挂的时候**整段终端输出原样发回来**，特别是有没有 [qvmp] 这种日志行。

文件 / 期望结果:

  1_original.bin            原版，能跑 (基线)
  2_onebyte.hardened        改 1 字节填充字节，能跑 (排除 hash 校验)
  3_notramp.hardened        加新 LOAD + PHDR id-map，**能跑** (你已确认)
  4_onlytramp.hardened      + 跳板写入，预期 Trap (133)
  5_embedonly.hardened      + embed runtime (无 armor)
  6_full.hardened           完整版

v6 修了什么:
  bootstrap stub 没 save/restore x21 x22 寄存器 (AAPCS64 callee-saved)。
  bootstrap 返回后这俩寄存器被搞乱，linker 后续 INIT_ARRAY 跑 C++ 静态
  初始化时直接 SEGV。修了 stack frame 大小 (32→48 字节)，把 x21/x22
  也存起来恢复。

  上一轮 5_embedonly / 6_full 都 SEGV 大概率就是这个 bug。

期望结果:
  1, 2, 3 → 都能跑 GUI
  4 → Trap 133 (无 handler 接 BRK)
  5 → 起 GUI 后第一次撞保护函数会触发 BRK，cdylib handler 接住 dispatch，
       理想情况 GUI 继续跑；如果 dispatch 路径有 bug 会 SEGV
  6 → 跟 5 类似，多了 armor 链

如果 5 还 SEGV → bootstrap/cdylib 还有别的 bug
如果 5 OK 6 SEGV → armor 路径触发 cdylib bug

MD5:
  1e33950ddd0f3ca282d638ba92b892ba  1_original.bin
  ff98505ec005b03664f03caf7e2882c6  2_onebyte.hardened
  92fca783ef3b1bfa17e59f4f45e57698  3_notramp.hardened
  51041fee2e9f20a1206369d9c78d43cb  4_onlytramp.hardened
  286b4a41e66bba541141fc941348632a  5_embedonly.hardened
  4d621c59a17a315661d3adb8dadedfe5  6_full.hardened
