qvmp_test.zip — diagnostic v5 (post-PHDR-fix bisect for SEGV)
=============================================================

v4 结果总结 (你已确认):
  notramp.hardened       ✅ 跑通 (PHDR/LOAD identity-map 修对了)
  onlytrampolines        Trap 133 (预期: 跳板触发 BRK + 没装 handler)
  hardened (full)        SEGV 139 (新问题: bootstrap+cdylib 路径有问题)

之前 PIE error 的几个 (no_embed/strip_only/xor_only/rodata_only) 是
v3 旧文件，现在全部用 v4 重新生成。

新增 embed_only.hardened: 只 embed runtime + 跳板，所有 armor 关掉。
用来分离: SEGV 是 armor 链触发的，还是 embed 本身坏的。

跑 4 个梯度:
  1. AndroidSurfaceImguiEnhanced              基线 (能跑)
  2. AndroidSurfaceImguiEnhanced.notramp.hardened  ✅ (你已确认)
  3. AndroidSurfaceImguiEnhanced.onlytrampolines.hardened  133 SIGTRAP (预期)
  4. AndroidSurfaceImguiEnhanced.strip_only.hardened
  5. AndroidSurfaceImguiEnhanced.xor_only.hardened
  6. AndroidSurfaceImguiEnhanced.rodata_only.hardened
  7. AndroidSurfaceImguiEnhanced.no_embed.hardened
  8. AndroidSurfaceImguiEnhanced.embed_only.hardened   ★ 新: embed + 0 armor
  9. AndroidSurfaceImguiEnhanced.hardened              ★ 完整版

跑 #8 时**重点看终端有没有 [qvmp] xxx 这种输出**。如果有，cdylib 装上了；
如果没有，dlopen 失败 (大概率 /data/local/tmp/.cachelib 写不进去)。

预期结果:
  4-7 应该都 SIGTRAP 133 (跟 onlytrampolines 一样，没 runtime)
  8: 取决于 dlopen 能不能成。
     成功 → ImGui 起来后第一次保护函数被调用看是否 SIGSEGV
     失败 → 跟 SIGTRAP 一样

挂的时候终端输出原样发回来。

MD5:
  1e33950ddd0f3ca282d638ba92b892ba  AndroidSurfaceImguiEnhanced
  4710886dd2931faf56ef626d73064a7e  AndroidSurfaceImguiEnhanced.embed_only.hardened
  bbde1842a8f96fdd81ccbf3a6e5bf852  AndroidSurfaceImguiEnhanced.no_embed.hardened
  92fca783ef3b1bfa17e59f4f45e57698  AndroidSurfaceImguiEnhanced.notramp.hardened
  ff98505ec005b03664f03caf7e2882c6  AndroidSurfaceImguiEnhanced.onebyte.hardened
  51041fee2e9f20a1206369d9c78d43cb  AndroidSurfaceImguiEnhanced.onlytrampolines.hardened
  b3ac2413e52a4b2a16175b09424a7504  AndroidSurfaceImguiEnhanced.rodata_only.hardened
  2bc00f366c3a2f3ac6f6d72490bbcafd  AndroidSurfaceImguiEnhanced.strip_only.hardened
  478d2c5c8469072b1ec48ef9aa0bf17b  AndroidSurfaceImguiEnhanced.xor_only.hardened
