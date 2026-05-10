qvmp_test.zip — diagnostic v4 (identity-mapped PHDR fix)
========================================================

上一轮发现:
  onebyte 能跑 → 启动器没做 hash 校验
  notramp 挂  → ELF 结构改动本身坏，不是跳板的事

定位到原因: 之前重定位 PHDR 后，PT_PHDR.p_offset != p_vaddr (相差 0x14000)。
原版是 identity mapping (offset == vaddr == 0x40)。某些 Android kernel/linker
路径用 `load_bias + e_phoff` 算 AT_PHDR (走 PT_PHDR 失败的回退分支)，
就读到错位置。

这版改成: 把文件 pad 到 vaddr 0x2ac000 处再追加新 LOAD 内容，
强制 file_offset == vaddr (identity mapping)。文件多 ~85KB 零填充。

  PHDR off=0x31c000 va=0x31c000  (id-map)
  LOAD off=0x2ac000 va=0x2ac000  (id-map)

按之前方法跑 4 个梯度:
  1. AndroidSurfaceImguiEnhanced              原版 (基线)
  2. AndroidSurfaceImguiEnhanced.onebyte.hardened     1 字节改动
  3. AndroidSurfaceImguiEnhanced.notramp.hardened     新 LOAD + PHDR (id-map)
  4. AndroidSurfaceImguiEnhanced.onlytrampolines.hardened   + 跳板
  5. AndroidSurfaceImguiEnhanced.hardened              完整版

如果 #3 (notramp) 这次能跑 → identity mapping 修对了，往下叠
如果 #3 还是挂 → PHDR 重定位还有别的问题，继续查

MD5:
  1e33950ddd0f3ca282d638ba92b892ba  AndroidSurfaceImguiEnhanced
  ff98505ec005b03664f03caf7e2882c6  AndroidSurfaceImguiEnhanced.onebyte.hardened
  92fca783ef3b1bfa17e59f4f45e57698  AndroidSurfaceImguiEnhanced.notramp.hardened
  51041fee2e9f20a1206369d9c78d43cb  AndroidSurfaceImguiEnhanced.onlytrampolines.hardened
  5731f7b9541e4a769fa4c2468479b04e  AndroidSurfaceImguiEnhanced.hardened
