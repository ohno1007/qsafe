qvmp_test.zip — diagnostic v3
=============================

最小化诊断集，5 个文件，按从最小修改到最大修改递增：

1. AndroidSurfaceImguiEnhanced
   原版，未改动 (你已确认能跑)

2. AndroidSurfaceImguiEnhanced.onebyte.hardened
   只在 .rela.plt / .rodata 之间的 8 字节 padding 里改 1 个字节 (0x16d7c: 0x00 → 0xff)
   ELF header / PHDR / sections 全部不动。文件大小不变 (2.6 MB)。
   这个文件的"内容"和原版 99.9999% 一样，只换 1 字节填充字节。

3. AndroidSurfaceImguiEnhanced.notramp.hardened
   加新 LOAD + 重定位 PHDR，但 .text 一字节不动。
   测 ELF 结构改动是否破坏。

4. AndroidSurfaceImguiEnhanced.onlytrampolines.hardened
   加新 LOAD + 重定位 PHDR + 写 867 个 4 字节跳板到 .text。
   测跳板写入是否破坏。

5. AndroidSurfaceImguiEnhanced.hardened
   完整版 (含 runtime + 全 armor)。

可能的诊断结果：

  onebyte 也挂        → 你那个启动器对原版做了某种 hash / 签名校验
                       任何字节改动都会被拒。需要换种方式启动。
  onebyte OK, notramp 挂 → ELF 结构改动 (PHDR/LOAD) 本身是凶手
  notramp OK, onlytrampolines 挂 → 跳板字节是凶手
  onlytrampolines OK    → 我之前修对了，是 armor 项的事

按从 1 → 5 顺序跑，告诉我哪个开始挂。

MD5:
  1e33950ddd0f3ca282d638ba92b892ba  AndroidSurfaceImguiEnhanced
  ff98505ec005b03664f03caf7e2882c6  AndroidSurfaceImguiEnhanced.onebyte.hardened
  32cf2adf429b1c81d025331e298d01b0  AndroidSurfaceImguiEnhanced.notramp.hardened
  58f902ceca15052006a41e2d3e69d328  AndroidSurfaceImguiEnhanced.onlytrampolines.hardened
  5c590dcf7b8c59c440f6ed24b520a62a  AndroidSurfaceImguiEnhanced.hardened
