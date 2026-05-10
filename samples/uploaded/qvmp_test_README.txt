qvmp_test.zip — diagnostic bundle for hardened ELF "PIE error" bisect
=====================================================================

7 files inside. Push each to /data/local/tmp/ (or wherever you ran the
original from), chmod +x, run the SAME way you ran the original.

Tell me which files run and which fail.

  AndroidSurfaceImguiEnhanced                              原版 (没改)
                                                           你已经验证它能跑

  AndroidSurfaceImguiEnhanced.onlytrampolines.hardened     只写跳板，零 armor
  AndroidSurfaceImguiEnhanced.strip_only.hardened          跳板 + .shstrtab 置零
  AndroidSurfaceImguiEnhanced.xor_only.hardened            跳板 + payload XOR
  AndroidSurfaceImguiEnhanced.rodata_only.hardened         跳板 + .rodata 加密(无解密)

  AndroidSurfaceImguiEnhanced.no_embed.hardened            跳板 + 全 armor，无嵌入 runtime
  AndroidSurfaceImguiEnhanced.hardened                     单文件完整版 (含 runtime)

第一行 onlytrampolines 是最关键的一档：什么 armor 都不开，只写跳板。
- 它跑得起来 → 跳板/PHDR/新 LOAD 本身没问题，是某个 armor 项搞坏了
- 它跑不起来 → 跳板/PHDR 本身就有 bug

剩下三个 strip/xor/rodata 是单独开一项 armor 看哪一项的锅。

MD5 校验（push 后在手机上 md5sum 应该对得上）：
1e33950ddd0f3ca282d638ba92b892ba  AndroidSurfaceImguiEnhanced
774ed409599e2bdbc1021421137f0645  AndroidSurfaceImguiEnhanced.hardened
876a5e9aa3f2e797b529970f88f1539a  AndroidSurfaceImguiEnhanced.no_embed.hardened
dfd9e5025a0a874da8a4dc171ff9bf63  AndroidSurfaceImguiEnhanced.onlytrampolines.hardened
8e56ead674b5d0f4c3a14bc83e3ec091  AndroidSurfaceImguiEnhanced.rodata_only.hardened
88b6b62787e625c2e54c67ca33dcfd7b  AndroidSurfaceImguiEnhanced.strip_only.hardened
a8c55ba46d1f0214de19761a11400ef2  AndroidSurfaceImguiEnhanced.xor_only.hardened
